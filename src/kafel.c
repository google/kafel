/*
   Kafel
   -----------------------------------------

   Copyright 2016 Google Inc. All Rights Reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.

*/

#include "kafel.h"

#include "codegen.h"
#include "common.h"
#include "context.h"
#include "includes.h"
#include "lexer.h"
#include "parser.h"
#include "syscall.h"

// flex <2.5.36 does not declare yyset_column
void kafel_yyset_column(int, yyscan_t);

static int parse(struct kafel_ctxt* ctxt) {
  yyscan_t scanner;

  if (kafel_yylex_init_extra(ctxt, &scanner)) {
    // couldn't initialize
    return -1;
  }

  kafel_yy_scan_string(ctxt->input.string, scanner);

  kafel_yyset_column(1, scanner);
  kafel_yyset_lineno(1, scanner);

  ctxt->syscalls = ctxt->use_companion_arch ?
                   companion_syscalls_lookup(ctxt->target_arch) :
                   syscalls_lookup(ctxt->target_arch);
  if (ctxt->syscalls == NULL) {
    kafel_yylex_destroy(scanner);

    // companion architectures may not be present,
    // so ;et's indicate it is not there silently for end-user
    if (ctxt->use_companion_arch) {
      return -2;
    } else {
      append_error(ctxt, "Cannot resolve syscall list for architecture %#x\n",
                   ctxt->target_arch);
      return -1;
    }
  }

  if (kafel_yyparse(ctxt, scanner) || ctxt->lexical_error) {
    // parse error
    // workaround for a flex bug
    for (int i = 0; i < MAX_INCLUDE_DEPTH; ++i) {
      kafel_yypop_buffer_state(scanner);
    }
    kafel_yylex_destroy(scanner);
    return -1;
  }

  kafel_yylex_destroy(scanner);
  return 0;
}

void set_target_arch(kafel_ctxt_t ctxt, uint32_t target_arch) {
  ctxt->target_arch = target_arch;
}

void set_use_companion_arch(kafel_ctxt_t ctxt, bool use_companion_arch) {
  ctxt->use_companion_arch = use_companion_arch;
}

KAFEL_API void kafel_set_input_file(kafel_ctxt_t ctxt, FILE* file) {
  ASSERT(ctxt != NULL);
  ASSERT(file != NULL);

  char *filebuf = NULL;

  // Free and null the string if the type was FILE
  if (ctxt->input.string && ctxt->input.type == INPUT_FILE) {
    char *freestr = (char*)ctxt->input.string;
    free(freestr);
    ctxt->input.string = NULL;
  }

  // Read YY_BUF_SIZE from file as string
  filebuf = calloc(1, YY_BUF_SIZE);
  if (!filebuf) {
    append_error(ctxt, "Cannot allocate file buffer of %d bytes",
                 YY_BUF_SIZE);
    return;
  }

  size_t bytes_read = fread(filebuf, 1, YY_BUF_SIZE, file);
  if(!bytes_read || ferror(file)) {
    append_error(ctxt, "Cannot read from file: %d",
                 ferror(file));
    free(filebuf);
    return;
  }

  ctxt->input.type = INPUT_FILE;
  ctxt->input.string = filebuf;
}

KAFEL_API void kafel_set_input_string(kafel_ctxt_t ctxt, const char* string) {
  ASSERT(ctxt != NULL);
  ASSERT(string != NULL);

  // Free and null the string if the type was FILE
  if (ctxt->input.string && ctxt->input.type == INPUT_FILE) {
    char *freestr = (char*)ctxt->input.string;
    free(freestr);
    ctxt->input.string = NULL;
  }

  ctxt->input.type = INPUT_STRING;
  ctxt->input.string = string;
}

KAFEL_API void kafel_set_target_arch(kafel_ctxt_t ctxt, uint32_t target_arch) {
  ASSERT(ctxt != NULL);

  uint32_t target_archs[MAX_TARGET_ARCHS] = {target_arch, 0, 0, 0};
  kafel_set_target_architectures(ctxt, target_archs, MAX_TARGET_ARCHS);
}

KAFEL_API void kafel_set_target_architectures(kafel_ctxt_t ctxt, uint32_t* target_archs, uint32_t size) {
  ASSERT(ctxt != NULL);
  ASSERT(target_archs != NULL);

  size = size >= MAX_TARGET_ARCHS ? MAX_TARGET_ARCHS : size;

  memset(ctxt->all_architectures, 0, MAX_TARGET_ARCHS * sizeof(uint32_t));
  memcpy(ctxt->all_architectures, target_archs, size * sizeof(uint32_t));

  ctxt->target_arch = ctxt->all_architectures[0];
}

KAFEL_API void kafel_add_include_search_path(kafel_ctxt_t ctxt,
                                             const char* path) {
  ASSERT(ctxt != NULL);
  ASSERT(path != NULL);
  includes_add_search_path(&ctxt->includes_ctxt, path);
}

KAFEL_API int kafel_compile(kafel_ctxt_t ctxt, struct sock_fprog* prog) {
  if (prog == NULL) {
    errno = EINVAL;
    return -EINVAL;
  }

  struct sock_fprog target_programs[MAX_TARGET_ARCHS] = { 0 };
  struct sock_fprog companion_programs[MAX_TARGET_ARCHS] = { 0 };
  unsigned char i = 0;
  int default_action = 0;

  for (i = 0; i < MAX_TARGET_ARCHS; i++) {
    if (!ctxt->all_architectures[i]) continue;

    kafel_ctxt_reset(ctxt);
    set_target_arch(ctxt, ctxt->all_architectures[i]);
    set_use_companion_arch(ctxt, false);

    int rv = parse(ctxt);
    if (rv) {
      for (i = 0; i < MAX_TARGET_ARCHS; i++) {
        free_sock_program(&target_programs[i]);
        free_sock_program(&companion_programs[i]);
      }

      return rv;
    }

    default_action = ctxt->default_action;

    rv = compile_policy(ctxt, &target_programs[i]);
    if (rv) {
      for (i = 0; i < MAX_TARGET_ARCHS; i++) {
        free_sock_program(&target_programs[i]);
        free_sock_program(&companion_programs[i]);
      }

      return rv;
    }

    if (!rv && target_programs[0].len == 1) {
      *prog = target_programs[0];
      return rv;
    }

    kafel_ctxt_reset(ctxt);
    set_target_arch(ctxt, ctxt->all_architectures[i]);
    set_use_companion_arch(ctxt, true);

    rv = parse(ctxt);
    if (rv) {
      if (rv == -2) continue;

      for (i = 0; i < MAX_TARGET_ARCHS; i++) {
        free_sock_program(&target_programs[i]);
        free_sock_program(&companion_programs[i]);
      }

      return rv;
    }

    rv = compile_policy(ctxt, &companion_programs[i]);
    if (rv) {
      for (i = 0; i < MAX_TARGET_ARCHS; i++) {
        free_sock_program(&target_programs[i]);
        free_sock_program(&companion_programs[i]);
      }

      return rv;
    }
  }

  return knit_policy(ctxt, target_programs, companion_programs,
                     default_action, prog);
}

KAFEL_API int kafel_compile_file(FILE* file, struct sock_fprog* prog) {
  if (file == NULL || prog == NULL) {
    errno = EINVAL;
    return -EINVAL;
  }

  kafel_ctxt_t ctxt = kafel_ctxt_create();
  kafel_set_input_file(ctxt, file);

  int rv = kafel_compile(ctxt, prog);
  kafel_ctxt_destroy(&ctxt);
  return rv;
}

KAFEL_API int kafel_compile_string(const char* source,
                                   struct sock_fprog* prog) {
  if (source == NULL || prog == NULL) {
    errno = EINVAL;
    return -EINVAL;
  }

  kafel_ctxt_t ctxt = kafel_ctxt_create();
  kafel_set_input_string(ctxt, source);

  int rv = kafel_compile(ctxt, prog);
  kafel_ctxt_destroy(&ctxt);
  return rv;
}

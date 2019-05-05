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

  YY_BUFFER_STATE buf_state;
  switch (ctxt->input.type) {
    case INPUT_FILE:
      buf_state =
          kafel_yy_create_buffer(ctxt->input.file, YY_BUF_SIZE, scanner);
      kafel_yy_switch_to_buffer(buf_state, scanner);
      break;
    case INPUT_STRING:
      buf_state = kafel_yy_scan_string(ctxt->input.string, scanner);
      break;
    default:
      kafel_yylex_destroy(scanner);
      return -1;
  }

  kafel_yyset_column(1, scanner);
  kafel_yyset_lineno(1, scanner);

  ctxt->target_arch_mask = syscall_get_arch_mask(ctxt->target_arch);
  if (!ctxt->target_arch_mask) {
    append_error(ctxt, "Cannot resolve syscall list for architecture %#x\n",
                 ctxt->target_arch);
    kafel_yylex_destroy(scanner);
    return -1;
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

KAFEL_API void kafel_set_input_file(kafel_ctxt_t ctxt, FILE* file) {
  ASSERT(ctxt != NULL);
  ASSERT(file != NULL);

  ctxt->input.type = INPUT_FILE;
  ctxt->input.file = file;
}

KAFEL_API void kafel_set_input_string(kafel_ctxt_t ctxt, const char* string) {
  ASSERT(ctxt != NULL);
  ASSERT(string != NULL);

  ctxt->input.type = INPUT_STRING;
  ctxt->input.string = string;
}

KAFEL_API void kafel_set_target_arch(kafel_ctxt_t ctxt, uint32_t target_arch) {
  ASSERT(ctxt != NULL);

  ctxt->target_arch = target_arch;
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

  kafel_ctxt_reset(ctxt);

  int rv = parse(ctxt);
  if (rv) {
    return rv;
  }

  return compile_policy(ctxt, prog);
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

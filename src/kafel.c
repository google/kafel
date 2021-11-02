/*
   Kafel
   -----------------------------------------

   Copyright 2016 Google LLC

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
#include "expression.h"
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

static int validate_references_in_expr(
    kafel_ctxt_t ctxt, const struct expr_tree* expr,
    const struct syscall_arg args[SYSCALL_MAX_ARGS]) {
  ASSERT(expr != NULL);

  if (expr->type >= EXPR_BINARY_MIN && expr->type <= EXPR_BINARY_MAX) {
    if (validate_references_in_expr(ctxt, expr->left, args) ||
        validate_references_in_expr(ctxt, expr->right, args)) {
      return -1;
    }
    return 0;
  }
  if (expr->type >= EXPR_UNARY_MIN && expr->type <= EXPR_UNARY_MAX) {
    return validate_references_in_expr(ctxt, expr->child, args);
  }
  if (expr->type != EXPR_IDENTIFIER) {
    return 0;
  }
  for (int i = 0; i < SYSCALL_MAX_ARGS; ++i) {
    if (args[i].name == NULL) {
      break;
    }
    if (strcmp(args[i].name, expr->identifier->id) == 0) {
      return 0;
    }
  }
  const struct kafel_identifier* identifier = expr->identifier;
  const struct kafel_source_location* loc = &identifier->loc;
  append_error(ctxt, "%d:%d: Undefined identifier `%s'\n", loc->first_line,
               loc->first_column, identifier->id);
  return -1;
}

static const char* kafel_arch_to_string(uint32_t arch) {
  switch (arch) {
    case KAFEL_TARGET_ARCH_X86_64:
      return "x86-64";
    case KAFEL_TARGET_ARCH_AARCH64:
      return "AArch64";
    case KAFEL_TARGET_ARCH_ARM:
      return "ARM";
    case KAFEL_TARGET_ARCH_X86:
      return "X86";
    case KAFEL_TARGET_ARCH_MIPS:
      return "mips";
    case KAFEL_TARGET_ARCH_MIPS64:
      return "mips64";
    case KAFEL_TARGET_ARCH_RISCV64:
      return "riscv64";
    default:
      return "Unknown";
  }
}

static int validate_references_for_arch(kafel_ctxt_t ctxt,
                                        uint32_t target_arch) {
  const struct syscall_list* syscall_list = syscalls_lookup(target_arch);
  if (syscall_list == NULL) {
    append_error(ctxt, "Cannot resolve syscall list for architecture %s\n",
                 kafel_arch_to_string(target_arch));
    return -1;
  }
  struct policy* policy;
  TAILQ_FOREACH(policy, &ctxt->policies, policies) {
    struct policy_entry* entry;
    TAILQ_FOREACH(entry, &policy->entries, entries) {
      if (entry->type != POLICY_ACTION) {
        continue;
      }
      struct syscall_filter* filter;
      TAILQ_FOREACH(filter, &entry->filters, filters) {
        if (filter->syscall->type == SYSCALL_SPEC_ID) {
          const struct kafel_identifier* identifier =
              filter->syscall->identifier;
          if (syscall_lookup(syscall_list, identifier->id) == NULL) {
            const struct kafel_source_location* loc = &identifier->loc;
            append_error(ctxt, "%d:%d: Undefined identifier `%s'",
                         loc->first_line, loc->first_column, identifier->id);
            return -1;
          }
        }
        if (filter->expr != NULL) {
          struct syscall_arg args[SYSCALL_MAX_ARGS];
          syscall_spec_get_args(filter->syscall, syscall_list, args);
          int rv = validate_references_in_expr(ctxt, filter->expr, args);
          if (rv) {
            return rv;
          }
        }
      }
    }
  }
  return 0;
}

static int validate_references(kafel_ctxt_t ctxt) {
  uint32_t target_archs = ctxt->target_archs;
  if (target_archs == 0) {
    target_archs = KAFEL_DEFAULT_TARGET_ARCH;
  }
  while (target_archs) {
    uint32_t target_arch = target_archs & ~(target_archs-1);
    target_archs &= ~target_arch;
    int rv = validate_references_for_arch(ctxt, target_arch);
    if (rv) {
      return rv;
    }
  }
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
  uint32_t kafel_arch = kafel_arch_lookup_by_audit_arch(target_arch);
  ASSERT(kafel_arch != 0);
  kafel_set_target_archs(ctxt, kafel_arch);
}

KAFEL_API void kafel_set_target_archs(kafel_ctxt_t ctxt,
                                      uint32_t target_archs) {
  ASSERT(ctxt != NULL);
  ASSERT(target_archs <= KAFEL_TARGET_ARCHS_ALL);
  ctxt->target_archs = target_archs;
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
  rv = validate_references(ctxt);
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

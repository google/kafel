/*
   Kafel - parser
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

%require "3.0"

%output "parser.c"
%defines "parser.h"

%{
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

#include "common.h"
#include "parser.h"
#include "lexer.h"

void yyerror(YYLTYPE * loc, struct kafel_ctxt* ctxt, yyscan_t scanner,
             const char *msg);

struct custom_syscall_args {
  int cur;
  struct custom_syscall_arg args[SYSCALL_MAX_ARGS];
};

struct custom_syscall_args* custom_syscall_args_create(void);
bool custom_syscall_args_has_already(struct custom_syscall_args* args, const char* name);
void custom_syscall_args_destroy(struct custom_syscall_args** args);

#define emit_error(loc, fmt, ...)                          \
    do {                                                   \
        append_error(ctxt, "%d:%d: "fmt, (loc).first_line, \
                    (loc).first_column, ##__VA_ARGS__);    \
    } while(0)

#define checked_expr_binary(result, loc, type, left, right)     \
    do {                                                        \
      if ((left)->depth >= MAX_EXPRESSION_DEPTH ||              \
        (right)->depth >= MAX_EXPRESSION_DEPTH) {               \
        emit_error((loc), "Max expression depth (%d) exceeded", \
                   MAX_EXPRESSION_DEPTH);                       \
        expr_destroy(&(left));                                  \
        expr_destroy(&(right));                                 \
        YYERROR;                                                \
      }                                                         \
      result = expr_create_binary((type), (left), (right));     \
    } while(0)

#define checked_expr_unary(result, loc, type, child)            \
    do {                                                        \
      if ((child)->depth >= MAX_EXPRESSION_DEPTH) {             \
        emit_error((loc), "Max expression depth (%d) exceeded", \
                   MAX_EXPRESSION_DEPTH);                       \
        expr_destroy(&(child));                                 \
        YYERROR;                                                \
      }                                                         \
      result = expr_create_unary((type), (child));              \
    } while(0)

#define YYLLOC_DEFAULT(Cur, Rhs, N )                    \
do {                                                    \
  if (N) {                                              \
    (Cur).filename = YYRHSLOC(Rhs, 1).filename;         \
    (Cur).first_line = YYRHSLOC(Rhs, 1).first_line;     \
    (Cur).first_column = YYRHSLOC(Rhs, 1).first_column; \
    (Cur).last_line = YYRHSLOC(Rhs, N).last_line;       \
    (Cur).last_column = YYRHSLOC(Rhs, N).last_column;   \
  }                                                     \
  else {                                                \
    (Cur).filename = YYRHSLOC(Rhs, 0).filename;         \
    (Cur).first_line = (Cur).last_line =                \
      YYRHSLOC(Rhs, 0).last_line;                       \
    (Cur).first_column = (Cur).last_column =            \
      YYRHSLOC(Rhs, 0).last_column;                     \
  }                                                     \
} while (0)
%}

%code requires {
#include <stdint.h>

#include "context.h"
#include "expression.h"
#include "policy.h"
#include "syscall.h"

#ifndef YY_TYPEDEF_YY_SCANNER_T
#define YY_TYPEDEF_YY_SCANNER_T
typedef void* yyscan_t;
#endif

#define KAFEL_YYLTYPE struct kafel_source_location
}

%define parse.error verbose
%define api.pure full
%define api.prefix {kafel_yy}
%locations
%lex-param {struct kafel_ctxt* ctxt}
%lex-param {yyscan_t scanner}
%parse-param {struct kafel_ctxt* ctxt}
%parse-param {yyscan_t scanner}

%union {
    char *id;
    uint32_t action;
    uint64_t number;
    struct custom_syscall_args *syscall_args;
    struct expr_tree *expr;
    struct syscall_filter *filter;
    struct syscall_spec *syscall_spec;
    struct filterslist filters;
    struct policy_entry *entry;
    struct entrieslist entries;
    struct policy *policy;
}

%token BIT_AND BIT_OR LOGIC_OR LOGIC_AND
%token IDENTIFIER NUMBER

%token POLICY USE DEFAULT SYSCALL DEFINE
%token ALLOW LOG KILL KILL_PROCESS DENY ERRNO TRAP TRACE USER_NOTIF

%token GT LT GE LE EQ NEQ

%type <id> IDENTIFIER
%type <number> NUMBER

%type <policy> policy
%type <entries> policy_statements
%type <entry> policy_statement use_statement action_block
%type <action> action
%type <filters> syscall_filters
%type <filter> syscall_filter
%type <syscall_args> syscall_args
%type <syscall_spec> syscall
%type <syscall_spec> syscall_id

%type <expr> bool_expr or_bool_expr and_bool_expr primary_bool_expr bit_or_expr bit_and_expr
%type <expr> operand

%destructor { policy_destroy(&$$); } <policy>
%destructor { policy_entry_destroy(&$$); } <entry>
%destructor { policy_entries_destroy(&$$); } <entries>
%destructor { syscall_filter_destroy(&$$); } <filter>
%destructor { syscall_filters_destroy(&$$); } <filters>
%destructor { custom_syscall_args_destroy(&$$); } <syscall_args>
%destructor { syscall_spec_destroy(&$$); } <syscall_spec>
%destructor { expr_destroy(&$$); } <expr>
%destructor { free($$); } <id>

%initial-action
{
    @$.filename = NULL;
};

%%

program
    : program_stmts
    ;

program_stmts
    : program_stmt
    | program_stmts program_stmt
    ;

program_stmt
    : const_def
    | policy
        {
          if (lookup_policy(ctxt, $1->name) != NULL) {
              emit_error(@1, "Redefinition of policy `%s'", $1->name);
              policy_destroy(&$1);
              YYERROR;
          }
          register_policy(ctxt, $1);
        }
    | policy_statements
        {
          if (ctxt->main_policy == NULL) {
            ctxt->main_policy = policy_create("@main", &$1);
            register_policy(ctxt, ctxt->main_policy);
          } else {
            TAILQ_CONCAT(&ctxt->main_policy->entries, &$1, entries);
          }
        }
    | DEFAULT action
        {
          if (ctxt->default_action != 0) {
            emit_error(@1, "Redefinition of default action");
            YYERROR;
          }
          ctxt->default_action = $2;
        }
    ;

policy
    : POLICY IDENTIFIER '{' '}' { $$ = policy_create($2, NULL); free($2); }
    | POLICY IDENTIFIER '{' policy_statements '}'
        {
          $$ = policy_create($2, &$4);
          free($2);
        }
    ;

policy_statements
    : policy_statement { TAILQ_INIT(&$$); TAILQ_INSERT_TAIL(&$$, $1, entries); }
    | policy_statements ',' policy_statement
        {
          TAILQ_INIT(&$$);
          TAILQ_CONCAT(&$$, &$1, entries);
          TAILQ_INSERT_TAIL(&$$, $3, entries);
        }
    ;

policy_statement
    : use_statement
    | action_block
    ;

use_statement
    : USE IDENTIFIER
        {
            struct policy* used = lookup_policy(ctxt, $2);
            if (used == NULL) {
                emit_error(@2, "Undefined policy `%s'", $2);
                free($2); $2 = NULL;
                YYERROR;
            }
            $$ = policy_use_create(used);
            free($2);
        }
    ;

action_block
    : action '{' '}' { $$ = policy_action_create($1, NULL); }
    | action '{' syscall_filters '}' { $$ = policy_action_create($1, &$3); }
    ;

action
    : ALLOW { $$ = ACTION_ALLOW; }
    | LOG  { $$ = ACTION_LOG; }
    | DENY { $$ = ACTION_KILL; }
    | KILL { $$ = ACTION_KILL; }
    | KILL_PROCESS { $$ = ACTION_KILL_PROCESS; }
    | USER_NOTIF { $$ = ACTION_USER_NOTIF; }
    | ERRNO '(' NUMBER ')'
        {
          if ($3 > 0xffff) {
            emit_error(@3, "Errno value %"PRIu64" out of range (0-65535)", $3);
            YYERROR;
          }
          $$ = ACTION_ERRNO | ($3 & 0xffff);
        }
    | TRACE '(' NUMBER ')'
        {
          if ($3 > 0xffff) {
            emit_error(@3, "Trace value %"PRIu64" out of range (0-65535)", $3);
            YYERROR;
          }
          $$ = ACTION_TRACE | ($3 & 0xffff);
        }
    | TRAP '(' NUMBER ')'
        {
          if ($3 > 0xffff) {
            emit_error(@3, "Trap value %"PRIu64" out of range (0-65535)", $3);
            YYERROR;
          }
          $$ = ACTION_TRAP | ($3 & 0xffff);
        }
    ;

syscall_filters
    : syscall_filter { TAILQ_INIT(&$$); TAILQ_INSERT_TAIL(&$$, $1, filters); }
    | syscall_filters ',' syscall_filter
        {
          TAILQ_INIT(&$$);
          TAILQ_CONCAT(&$$, &$1, filters);
          TAILQ_INSERT_TAIL(&$$, $3, filters);
        }
    ;

syscall_filter
    : syscall { $$ = syscall_filter_create($1, NULL); }
    | syscall '{' '}' { $$ = syscall_filter_create($1, NULL); }
    | syscall '{' bool_expr '}' { $$ = syscall_filter_create($1, $3); }
    ;

syscall_id
    : IDENTIFIER
        {
            uint64_t value = 0;
            if (lookup_const(ctxt, $1, &value) == 0) {
                $$ = syscall_spec_create_custom(value);
            } else {
                $$ = syscall_spec_create_identifier(kafel_identifier_create($1, &@1));
            }
            free($1);
        }
    | SYSCALL '[' NUMBER ']'
        {
            $$ = syscall_spec_create_custom($3);
        }
    ;

syscall
    : syscall_id
        {
          $$ = $1;
        }
    | syscall_id '(' ')'
        {
          $$ = $1;
          struct custom_syscall_arg custom_syscall_args[SYSCALL_MAX_ARGS];
          memset(custom_syscall_args, 0, sizeof(custom_syscall_args));
          syscall_spec_set_custom_args($$, custom_syscall_args);
        }
    | syscall_id '(' syscall_args ')'
        {
          $$ = $1;
          syscall_spec_set_custom_args($$, $3->args);
          memset($3->args, 0, sizeof($3->args));
          custom_syscall_args_destroy(&$3);
        }
    ;

syscall_args
    : IDENTIFIER
        {
          $$ = custom_syscall_args_create();
          $$->args[0].name = $1;
          $$->args[0].size = 8;
          $$->cur = 1;
        }
    | syscall_args ',' IDENTIFIER
        {
          $$ = $1;
          if (custom_syscall_args_has_already($$, $3)) {
            emit_error(@3, "Redefinition of argument `%s'", $3);
            custom_syscall_args_destroy(&$$);
            free($3); $3 = NULL;
            YYERROR;
          }
          if ($$->cur == SYSCALL_MAX_ARGS) {
            emit_error(@3, "Too many arguments defined for syscall");
            custom_syscall_args_destroy(&$$);
            free($3); $3 = NULL;
            YYERROR;
          }
          $$->args[$$->cur].size = 8;
          $$->args[$$->cur++].name = $3;
        }
    ;

bool_expr
    : bool_expr ',' or_bool_expr { checked_expr_binary($$, @1, EXPR_OR, $1, $3); }
    | or_bool_expr { $$ = $1; }
    ;

or_bool_expr
    : or_bool_expr LOGIC_OR and_bool_expr
        { checked_expr_binary($$, @1, EXPR_OR, $1, $3); }
    | and_bool_expr { $$ = $1; }
    ;

and_bool_expr
    : and_bool_expr LOGIC_AND primary_bool_expr
        { checked_expr_binary($$, @1, EXPR_AND, $1, $3); }
    | primary_bool_expr { $$ = $1; }
    ;

primary_bool_expr
    : '(' bool_expr ')' { $$ = $2; }
    | '!' primary_bool_expr { checked_expr_unary($$, @1, EXPR_NOT, $2); }
    | bit_or_expr GT bit_or_expr { checked_expr_binary($$, @1, EXPR_GT, $1, $3); }
    | bit_or_expr LT bit_or_expr { checked_expr_binary($$, @1, EXPR_LT, $1, $3); }
    | bit_or_expr GE bit_or_expr { checked_expr_binary($$, @1, EXPR_GE, $1, $3); }
    | bit_or_expr LE bit_or_expr { checked_expr_binary($$, @1, EXPR_LE, $1, $3); }
    | bit_or_expr EQ bit_or_expr { checked_expr_binary($$, @1, EXPR_EQ, $1, $3); }
    | bit_or_expr NEQ bit_or_expr { checked_expr_binary($$, @1, EXPR_NEQ, $1, $3); }
    ;

bit_or_expr
    : bit_or_expr BIT_OR bit_and_expr { checked_expr_binary($$, @1, EXPR_BIT_OR, $1, $3); }
    | bit_and_expr { $$ = $1; }
    ;

bit_and_expr
    : bit_and_expr BIT_AND operand { checked_expr_binary($$, @1, EXPR_BIT_AND, $1, $3); }
    | operand { $$ = $1; }
    ;

operand
    : NUMBER { $$ = expr_create_number($1); }
    | '(' bit_or_expr ')' { $$ = $2; }
    | IDENTIFIER
        {
          uint64_t value = 0;
          if (lookup_const(ctxt, $1, &value) == 0) {
            $$ = expr_create_number(value);
          } else {
            $$ = expr_create_identifier(kafel_identifier_create($1, &@1));
          }
          free($1);
        }
    ;

const_def
    : '#' DEFINE IDENTIFIER NUMBER
        {
          uint64_t value;
          if (lookup_const(ctxt, $3, &value) == 0) {
            if (value != $4) {
              emit_error(@1, "Redefinition of constant `%s' with different "
                         "value (was: %"PRIu64" is: %"PRIu64")", $3, value, $4);
              free($3); $3 = NULL;
              YYERROR;
            }
          } else {
            register_const(ctxt, $3, $4);
          }
          free($3);
        }
    ;

%%

void yyerror(YYLTYPE * loc, struct kafel_ctxt* ctxt, yyscan_t scanner,
             const char *msg) {
  (void)scanner; /* suppress unused-parameter warning */
  if (!ctxt->lexical_error) {
    if (loc->filename != NULL) {
      append_error(ctxt, "%s:%d:%d: %s", loc->filename, loc->first_line, loc->first_column, msg);
    } else {
      append_error(ctxt, "%d:%d: %s", loc->first_line, loc->first_column, msg);
    }
  }
}

struct custom_syscall_args *custom_syscall_args_create(void) {
  struct custom_syscall_args *rv = calloc(1, sizeof(*rv));
  rv->cur = 0;
  return rv;
}

bool custom_syscall_args_has_already(struct custom_syscall_args* args, const char* name) {
  ASSERT(args != NULL);
  ASSERT(name != NULL);
  for (int i = 0; i < args->cur; ++i) {
    if (strcmp(args->args[i].name, name) == 0) {
      return true;
    }
  }
  return false;
}

void custom_syscall_args_destroy(struct custom_syscall_args **args) {
  ASSERT(args != NULL);
  ASSERT((*args) != NULL);
  for (int i = 0; i < SYSCALL_MAX_ARGS; ++i) {
    free((*args)->args[i].name);
  }
  free(*args);
  *args = NULL;
}

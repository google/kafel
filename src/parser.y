/*
   Kafel - parser
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

%require "3.0"

%output "parser.c"
%defines "parser.h"

%{
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

#include "parser.h"
#include "lexer.h"

void yyerror(YYLTYPE * loc, struct kafel_ctxt* ctxt, yyscan_t scanner,
             const char *msg);

#define emit_error(loc, fmt, ...)                          \
    do {                                                   \
        append_error(ctxt, "%d:%d: "fmt, (loc).first_line, \
                    (loc).first_column, ##__VA_ARGS__);    \
    } while(0)                                             \

#define INVALID_ARG_SIZE -1

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

typedef struct KAFEL_YYLTYPE
{
    int first_line;
    int first_column;
    int last_line;
    int last_column;
    const char *filename;
} KAFEL_YYLTYPE;
#define KAFEL_YYLTYPE KAFEL_YYLTYPE
}

%code provides {
#define YYSTYPE KAFEL_YYSTYPE
typedef union YYSTYPE YYSTYPE;

#define YYLTYPE KAFEL_YYLTYPE
typedef struct YYLTYPE YYLTYPE;

#define YY_DECL \
      int kafel_yylex(YYSTYPE* yylval_param, YYLTYPE* yylloc_param, \
                      struct kafel_ctxt* ctxt, yyscan_t yyscanner)
YY_DECL;
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
    uint32_t syscall_nr;
    uint32_t action;
    uint64_t number;
    struct expr_tree *expr;
    struct syscall_descriptor* syscall_desc;
    struct syscall_filter *filter;
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
%type <syscall_desc> syscall_id
%type <syscall_nr> syscall

%type <expr> bool_expr or_bool_expr and_bool_expr primary_bool_expr bit_or_expr bit_and_expr
%type <expr> operand

%destructor { policy_destroy(&$$); } <policy>
%destructor { policy_entry_destroy(&$$); } <entry>
%destructor { policy_entries_destroy(&$$); } <entries>
%destructor { syscall_filter_destroy(&$$); } <filter>
%destructor { syscall_filters_destroy(&$$); } <filters>
%destructor { syscall_descriptor_destroy(&$$); } <syscall_desc>
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
                $$ = syscall_custom(value);
            } else {
                $$ = (struct syscall_descriptor*)
                        syscall_lookup(ctxt->syscalls, $1);
                    if ($$ == NULL) {
                    emit_error(@1, "Undefined syscall `%s'", $1);
                    free($1); $1 = NULL;
                    YYERROR;
                }
            }
            free($1);
        }
    | SYSCALL '[' NUMBER ']'
        {
            $$ = syscall_custom($3);
        }
    ;

syscall
    : syscall_id
        {
          $$ = $1->nr;
          register_ftrace_args(ctxt, $1);
          syscall_descriptor_destroy(&$1);
        }
    | syscall_id '(' ')'
        {
          $$ = $1->nr;
          clean_args(ctxt);
          syscall_descriptor_destroy(&$1);
        }
    | syscall_id '(' syscall_args ')'
        {
          $$ = $1->nr;
          for (int i = 0; i < SYSCALL_MAX_ARGS; ++i) {
            if (ctxt->syscall.args[i].size == INVALID_ARG_SIZE) {
              ctxt->syscall.args[i].size = 8;
              if ($1->args[i].name != NULL) {
                ctxt->syscall.args[i].size = $1->args[i].size;
              }
            }
          }
          syscall_descriptor_destroy(&$1);
        }
    ;

syscall_args
    : IDENTIFIER
        {
          register_first_arg(ctxt, $1, INVALID_ARG_SIZE);
          free($1);
        }
    | syscall_args ',' IDENTIFIER
        {
          if (lookup_var(ctxt, $3) >= 0) {
            emit_error(@3, "Redefinition of argument `%s'", $3);
            free($3); $3 = NULL;
            YYERROR;
          }
          if (register_arg(ctxt, $3, INVALID_ARG_SIZE)) {
            emit_error(@3, "Too many arguments defined for syscall");
            free($3); $3 = NULL;
            YYERROR;
          }
          free($3);
        }
    ;

bool_expr
    : bool_expr ',' or_bool_expr { $$ = expr_create_binary(EXPR_OR, $1, $3); }
    | or_bool_expr { $$ = $1; }
    ;

or_bool_expr
    : or_bool_expr LOGIC_OR and_bool_expr
        { $$ = expr_create_binary(EXPR_OR, $1, $3); }
    | and_bool_expr { $$ = $1; }
    ;

and_bool_expr
    : and_bool_expr LOGIC_AND primary_bool_expr
        { $$ = expr_create_binary(EXPR_AND, $1, $3); }
    | primary_bool_expr { $$ = $1; }
    ;

primary_bool_expr
    : '(' bool_expr ')' { $$ = $2; }
    | '!' primary_bool_expr { $$ = expr_create_unary(EXPR_NOT, $2); }
    | bit_or_expr GT bit_or_expr { $$ = expr_create_binary(EXPR_GT, $1, $3); }
    | bit_or_expr LT bit_or_expr { $$ = expr_create_binary(EXPR_LT, $1, $3); }
    | bit_or_expr GE bit_or_expr { $$ = expr_create_binary(EXPR_GE, $1, $3); }
    | bit_or_expr LE bit_or_expr { $$ = expr_create_binary(EXPR_LE, $1, $3); }
    | bit_or_expr EQ bit_or_expr { $$ = expr_create_binary(EXPR_EQ, $1, $3); }
    | bit_or_expr NEQ bit_or_expr { $$ = expr_create_binary(EXPR_NEQ, $1, $3); }
    ;

bit_or_expr
    : bit_or_expr BIT_OR bit_and_expr { $$ = expr_create_binary(EXPR_BIT_OR, $1, $3); }
    | bit_and_expr { $$ = $1; }
    ;

bit_and_expr
    : bit_and_expr BIT_AND operand { $$ = expr_create_binary(EXPR_BIT_AND, $1, $3); }
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
            int var = lookup_var(ctxt, $1);
            if (var < 0) {
                emit_error(@1, "Undefined argument `%s'", $1);
                free($1); $1 = NULL;
                YYERROR;
            }
            $$ = expr_create_var(var, ctxt->syscall.args[var].size);
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
  if (!ctxt->lexical_error) {
    YYUSE(scanner);
    if (loc->filename != NULL) {
      append_error(ctxt, "%s:%d:%d: %s", loc->filename, loc->first_line, loc->first_column, msg);
    } else {
      append_error(ctxt, "%d:%d: %s", loc->first_line, loc->first_column, msg);
    }
  }
}

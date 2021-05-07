/*
   Kafel - expression
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

#ifndef KAFEL_EXPRESSION_H
#define KAFEL_EXPRESSION_H

#include <stdbool.h>
#include <stdint.h>

#include "parser_types.h"
#include "syscall.h"

#define MAX_EXPRESSION_DEPTH 200

enum {
  EXPR_LEAF_MIN,
  EXPR_NUMBER = EXPR_LEAF_MIN,
  EXPR_VAR,
  EXPR_IDENTIFIER,
  EXPR_TRUE,
  EXPR_FALSE,
  EXPR_LEAF_MAX = EXPR_FALSE,
  EXPR_UNARY_MIN,
  EXPR_NOT = EXPR_UNARY_MIN,
  EXPR_UNARY_MAX = EXPR_NOT,
  EXPR_BINARY_MIN,
  EXPR_AND = EXPR_BINARY_MIN,
  EXPR_OR,
  EXPR_GT,
  EXPR_LT,
  EXPR_GE,
  EXPR_LE,
  EXPR_EQ,
  EXPR_NEQ,
  EXPR_BIT_OR,
  EXPR_BIT_AND,
  EXPR_BINARY_MAX = EXPR_BIT_AND,
  EXPR_MAX = EXPR_BINARY_MAX,
};

struct cached_value {
  bool is_const;
  uint32_t value;
};

struct expr_tree {
  int type;
  int depth;
  union {
    struct {
      int var;
      int size;
    };
    struct kafel_identifier *identifier;
    uint64_t number;
    struct expr_tree *child;
    struct {
      struct expr_tree *left;
      struct expr_tree *right;
    };
  };
  struct cached_value low;
  struct cached_value high;
};

struct expr_tree *expr_create_number(uint64_t value);
struct expr_tree *expr_create_identifier(struct kafel_identifier *identifier);
struct expr_tree *expr_create_unary(int op, struct expr_tree *child);
struct expr_tree *expr_create_binary(int op, struct expr_tree *left,
                                     struct expr_tree *right);
struct expr_tree *expr_copy(const struct expr_tree *expr);
void expr_simplify(struct expr_tree **expr);
void expr_destroy(struct expr_tree **expr);
void expr_resolve_identifiers(struct expr_tree *expr,
                              const struct syscall_arg args[SYSCALL_MAX_ARGS]);

#endif /* KAFEL_EXPRESSION_H */

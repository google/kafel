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

#include "expression.h"

#include <stdlib.h>
#include <string.h>

#include "common.h"

struct expr_tree *expr_create_number(uint64_t value) {
  struct expr_tree *rv = calloc(1, sizeof(*rv));
  rv->type = EXPR_NUMBER;
  rv->number = value;
  rv->depth = 0;
  return rv;
}

struct expr_tree *expr_create_identifier(struct kafel_identifier *identifier) {
  struct expr_tree *rv = calloc(1, sizeof(*rv));
  rv->type = EXPR_IDENTIFIER;
  rv->identifier = identifier;
  rv->depth = 0;
  return rv;
}

struct expr_tree *expr_create_unary(int op, struct expr_tree *child) {
  ASSERT(op >= EXPR_UNARY_MIN && op <= EXPR_UNARY_MAX);
  ASSERT(child != NULL);

  struct expr_tree *rv = calloc(1, sizeof(*rv));
  rv->type = op;
  rv->child = child;
  rv->depth = child->depth + 1;
  return rv;
}

struct expr_tree *expr_create_binary(int op, struct expr_tree *left,
                                     struct expr_tree *right) {
  ASSERT(op >= EXPR_BINARY_MIN && op <= EXPR_BINARY_MAX);
  ASSERT(left != NULL);
  ASSERT(right != NULL);

  struct expr_tree *rv = calloc(1, sizeof(*rv));
  rv->type = op;
  rv->left = left;
  rv->right = right;
  rv->depth = left->depth + 1;
  if (rv->depth < right->depth + 1) {
    rv->depth = right->depth + 1;
  }
  return rv;
}

static bool expr_eval(int type, uint64_t left, uint64_t right) {
  switch (type) {
    case EXPR_EQ:
      return left == right;
    case EXPR_NEQ:
      return left != right;
    case EXPR_GE:
      return left >= right;
    case EXPR_LE:
      return left <= right;
    case EXPR_GT:
      return left > right;
    case EXPR_LT:
      return left < right;
    default:
      ASSERT(0);  // should not happen
  }
}

void expr_simplify(struct expr_tree **pexpr) {
  ASSERT(pexpr != NULL);

  struct expr_tree *expr = *pexpr;
  ASSERT(expr != NULL);

  int type = expr->type;

  if (type >= EXPR_LEAF_MIN && type <= EXPR_LEAF_MAX) {
    return;
  }

  if (type >= EXPR_UNARY_MIN && type <= EXPR_UNARY_MAX) {
    ASSERT(type == EXPR_NOT);
    expr_simplify(&expr->child);
    if (expr->child->type == EXPR_TRUE) {
      expr_destroy(&expr->child);
      expr->type = EXPR_FALSE;
    } else if (expr->child->type == EXPR_FALSE) {
      expr_destroy(&expr->child);
      expr->type = EXPR_TRUE;
    }
    return;
  }

  ASSERT(type >= EXPR_BINARY_MIN && type <= EXPR_BINARY_MAX);

  expr_simplify(&expr->left);
  expr_simplify(&expr->right);

  struct expr_tree *left = expr->left;
  struct expr_tree *right = expr->right;

  if (left->type == EXPR_NUMBER && right->type == EXPR_NUMBER) {
    if (type == EXPR_BIT_AND) {
      expr->type = EXPR_NUMBER;
      expr->number = left->number & right->number;
    } else if (type == EXPR_BIT_OR) {
      expr->type = EXPR_NUMBER;
      expr->number = left->number | right->number;
    } else {
      expr->type =
          expr_eval(type, left->number, right->number) ? EXPR_TRUE : EXPR_FALSE;
    }
    expr_destroy(&left);
    expr_destroy(&right);
    return;
  }

  if (left->type < right->type) {
    const int swapped[EXPR_MAX + 1] = {
        [EXPR_AND] = EXPR_AND,       [EXPR_OR] = EXPR_OR,
        [EXPR_GE] = EXPR_LE,         [EXPR_GT] = EXPR_LT,
        [EXPR_LE] = EXPR_GE,         [EXPR_LT] = EXPR_GT,
        [EXPR_EQ] = EXPR_EQ,         [EXPR_NEQ] = EXPR_NEQ,
        [EXPR_BIT_OR] = EXPR_BIT_OR, [EXPR_BIT_AND] = EXPR_BIT_AND};
    type = swapped[type];
    SWAP(left, right);
  }

  int eq_vars_result = EXPR_TRUE;
  int dominant = EXPR_TRUE, recessive = EXPR_FALSE;
  uint64_t clobber = 0, identity = UINT64_MAX;

  switch (type) {
    case EXPR_AND:
      SWAP(dominant, recessive);
    // fall-through
    case EXPR_OR:
      if (left->type == dominant || right->type == dominant) {
        expr_destroy(&expr->left);
        expr_destroy(&expr->right);
        expr->type = dominant;
      } else if (right->type == recessive) {
        expr_destroy(&right);
        *pexpr = left;
        free(expr);
      }
      break;
    case EXPR_GT:
    case EXPR_LT:
    case EXPR_NEQ:
      eq_vars_result = EXPR_FALSE;
    // fall-through
    case EXPR_GE:
    case EXPR_LE:
    case EXPR_EQ:
      if (left->type == EXPR_VAR && right->type == EXPR_VAR &&
          left->var == right->var) {
        expr->type = eq_vars_result;
        expr_destroy(&expr->left);
        expr_destroy(&expr->right);
      }
      break;
    case EXPR_BIT_OR:
      SWAP(clobber, identity);
    // fall-through
    case EXPR_BIT_AND:
      if (right->type == EXPR_NUMBER) {
        if (right->number == clobber) {
          expr_destroy(&expr->left);
          expr_destroy(&expr->right);
          expr->type = EXPR_NUMBER;
          expr->number = clobber;
        } else if (right->number == identity) {
          expr_destroy(&right);
          *pexpr = left;
          free(expr);
        }
      }
      break;
  }
}

struct expr_tree *expr_copy(const struct expr_tree *expr) {
  ASSERT(expr != NULL);

  struct expr_tree *rv = calloc(1, sizeof(*rv));
  rv->type = expr->type;
  if (expr->type >= EXPR_BINARY_MIN && expr->type <= EXPR_BINARY_MAX) {
    rv->left = expr_copy(expr->left);
    rv->right = expr_copy(expr->right);
  } else if (expr->type >= EXPR_UNARY_MIN && expr->type <= EXPR_UNARY_MAX) {
    rv->child = expr_copy(expr->child);
  }
  switch (expr->type) {
    case EXPR_NUMBER:
      rv->number = expr->number;
      break;
    case EXPR_VAR:
      rv->var = expr->var;
      rv->size = expr->size;
      break;
    case EXPR_IDENTIFIER:
      rv->identifier = kafel_identifier_copy(expr->identifier);
      break;
  }
  return rv;
}

void expr_destroy(struct expr_tree **expr) {
  ASSERT(expr != NULL);
  ASSERT((*expr) != NULL);

  if ((*expr)->type >= EXPR_BINARY_MIN && (*expr)->type <= EXPR_BINARY_MAX) {
    expr_destroy(&(*expr)->left);
    expr_destroy(&(*expr)->right);
  } else if ((*expr)->type >= EXPR_UNARY_MIN &&
             (*expr)->type <= EXPR_UNARY_MAX) {
    expr_destroy(&(*expr)->child);
  }
  if ((*expr)->type == EXPR_IDENTIFIER) {
    kafel_identifier_destroy(&(*expr)->identifier);
  }
  free(*expr);
  *expr = NULL;
}

void expr_resolve_identifiers(struct expr_tree *expr,
                              const struct syscall_arg args[SYSCALL_MAX_ARGS]) {
  ASSERT(expr != NULL);

  if (expr->type >= EXPR_BINARY_MIN && expr->type <= EXPR_BINARY_MAX) {
    expr_resolve_identifiers(expr->left, args);
    expr_resolve_identifiers(expr->right, args);
  } else if (expr->type >= EXPR_UNARY_MIN && expr->type <= EXPR_UNARY_MAX) {
    expr_resolve_identifiers(expr->child, args);
  }
  if (expr->type != EXPR_IDENTIFIER) {
    return;
  }
  for (int i = 0; i < SYSCALL_MAX_ARGS; ++i) {
    ASSERT(args[i].name != NULL);
    if (strcmp(args[i].name, expr->identifier->id) == 0) {
      kafel_identifier_destroy(&expr->identifier);
      expr->type = EXPR_VAR;
      expr->var = i;
      expr->size = args[i].size;
      return;
    }
  }
  ASSERT(false);
}

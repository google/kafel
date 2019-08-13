/*
   Kafel - expression
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

#include "expression.h"

#include <stdlib.h>

#include "common.h"

struct expr_tree *expr_create_number(uint64_t value) {
  struct expr_tree *rv = calloc(1, sizeof(*rv));
  rv->type = EXPR_NUMBER;
  rv->number = value;
  return rv;
}

struct expr_tree *expr_create_var(int var, int size) {
  if (size == 2) {  // TODO fully support 16-bit arguments
    size = 4;
  }
  ASSERT(size == 4 || size == 8);  // 32- or 64-bit

  struct expr_tree *rv = calloc(1, sizeof(*rv));
  rv->type = EXPR_VAR;
  rv->var = var;
  rv->size = size;
  return rv;
}

struct expr_tree *expr_create_unary(int op, struct expr_tree *child) {
  ASSERT(op >= EXPR_UNARY_MIN && op <= EXPR_UNARY_MAX);
  ASSERT(child != NULL);

  struct expr_tree *rv = calloc(1, sizeof(*rv));
  rv->type = op;
  rv->child = child;
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
  return rv;
}

void expr_negate(struct expr_tree **expr) { expr_eliminate_negation(expr, 1); }

void expr_eliminate_negation(struct expr_tree **expr, bool neg) {
  ASSERT(expr != NULL);
  ASSERT((*expr) != NULL);

  int negations[EXPR_MAX + 1] = {
      [EXPR_AND] = EXPR_OR,    [EXPR_OR] = EXPR_AND, [EXPR_GE] = EXPR_LT,
      [EXPR_GT] = EXPR_LE,     [EXPR_LE] = EXPR_GT,  [EXPR_LT] = EXPR_GE,
      [EXPR_EQ] = EXPR_NEQ,    [EXPR_NEQ] = EXPR_EQ, [EXPR_TRUE] = EXPR_FALSE,
      [EXPR_FALSE] = EXPR_TRUE};
  switch ((*expr)->type) {
    case EXPR_NOT: {
      struct expr_tree *tmp = *expr;
      *expr = (*expr)->child;
      free(tmp);
      expr_eliminate_negation(expr, !neg);
      return;
    }
    case EXPR_AND:
    case EXPR_OR:
      expr_eliminate_negation(&(*expr)->left, neg);
      expr_eliminate_negation(&(*expr)->right, neg);
      break;
  }

  if (neg && negations[(*expr)->type] != 0) {
    (*expr)->type = negations[(*expr)->type];
  }
}

static void expr_sort_operands(struct expr_tree *expr) {
  ASSERT(expr != NULL);

  if (expr->type >= EXPR_BINARY_MIN && expr->type <= EXPR_BINARY_MAX) {
    ASSERT(expr->left != NULL);
    ASSERT(expr->right != NULL);

    if (expr->type != EXPR_AND && expr->type != EXPR_OR &&
        expr->left->type < expr->right->type) {
      int swapped[EXPR_MAX + 1] = {
          [EXPR_GE] = EXPR_LE,          [EXPR_GT] = EXPR_LT,
          [EXPR_LE] = EXPR_GE,          [EXPR_LT] = EXPR_GT,
          [EXPR_EQ] = EXPR_EQ,          [EXPR_NEQ] = EXPR_NEQ,
          [EXPR_BIT_OR] = EXPR_BIT_OR,  [EXPR_BIT_AND] = EXPR_BIT_AND};
      expr->type = swapped[expr->type];
      SWAP(expr->left, expr->right);
    }
    expr_sort_operands(expr->left);
    expr_sort_operands(expr->right);
  }
}

static int expr_boolean(bool boolean) {
  return boolean ? EXPR_TRUE : EXPR_FALSE;
}

#define EVAL_EXPR(type, op) \
  case type:                \
    return expr_boolean(left op right)

static int expr_eval(int type, uint32_t left, uint32_t right) {
  switch (type) {
    EVAL_EXPR(EXPR_EQ, ==);
    EVAL_EXPR(EXPR_NEQ, !=);
    EVAL_EXPR(EXPR_GE, >=);
    EVAL_EXPR(EXPR_LE, <=);
    EVAL_EXPR(EXPR_GT, >);
    EVAL_EXPR(EXPR_LT, <);
    default:
      ASSERT(0);  // should not happen
  }
}

static void expr_precompute_eliminate(struct expr_tree **expr) {
  ASSERT(expr != NULL);
  ASSERT((*expr) != NULL);

  if ((*expr)->type >= EXPR_LEAF_MIN && (*expr)->type <= EXPR_LEAF_MAX) {
    return;
  }

  if ((*expr)->type >= EXPR_UNARY_MIN && (*expr)->type <= EXPR_UNARY_MAX) {
    expr_precompute_eliminate(&(*expr)->child);
    return;
  }

  if ((*expr)->type >= EXPR_BINARY_MIN && (*expr)->type <= EXPR_BINARY_MAX) {
    expr_precompute_eliminate(&(*expr)->left);
    expr_precompute_eliminate(&(*expr)->right);
  }

  struct expr_tree *original_expr = *expr;

  if ((*expr)->left->type == EXPR_NUMBER &&
      (*expr)->right->type == EXPR_NUMBER) {
    if ((*expr)->type == EXPR_BIT_AND) {
      (*expr)->left->number &= (*expr)->right->number;
      expr_destroy(&(*expr)->right);
      *expr = (*expr)->left;
      free(original_expr);
    } else if ((*expr)->type == EXPR_BIT_OR) {
      (*expr)->left->number |= (*expr)->right->number;
      expr_destroy(&(*expr)->right);
      *expr = (*expr)->left;
      free(original_expr);
    } else {
      (*expr)->type = expr_eval((*expr)->type, (*expr)->left->number,
                                (*expr)->right->number);
      expr_destroy(&(*expr)->left);
      expr_destroy(&(*expr)->right);
    }
  }

  int eq_vars_result = EXPR_TRUE;
  int dominant = EXPR_TRUE, recessive = EXPR_FALSE;

  switch ((*expr)->type) {
    case EXPR_AND:
      dominant = EXPR_FALSE, recessive = EXPR_TRUE;
    // fall-through
    case EXPR_OR:
      if ((*expr)->left->type == dominant || (*expr)->right->type == dominant) {
        expr_destroy(&(*expr)->left);
        expr_destroy(&(*expr)->right);
        (*expr)->type = dominant;
      } else if ((*expr)->left->type == recessive) {
        expr_destroy(&(*expr)->left);
        *expr = (*expr)->right;
        free(original_expr);
      } else if ((*expr)->right->type == recessive) {
        expr_destroy(&(*expr)->right);
        *expr = (*expr)->left;
        free(original_expr);
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
      if ((*expr)->left->type == EXPR_VAR && (*expr)->right->type == EXPR_VAR &&
          (*expr)->left->var == (*expr)->right->var) {
        (*expr)->type = eq_vars_result;
        expr_destroy(&(*expr)->left);
        expr_destroy(&(*expr)->right);
      }
      break;
    case EXPR_BIT_OR:
      if ((*expr)->right->type == EXPR_NUMBER) {
        if ((*expr)->right->number == UINT64_MAX) {
          expr_destroy(&(*expr)->left);
          expr_destroy(&(*expr)->right);
          (*expr)->type = EXPR_NUMBER;
          (*expr)->number = UINT64_MAX;
        } else if ((*expr)->right->number == 0) {
          expr_destroy(&(*expr)->right);
          *expr = (*expr)->left;
          free(original_expr);
        }
      }
      break;
    case EXPR_BIT_AND:
      if ((*expr)->right->type == EXPR_NUMBER) {
        if ((*expr)->right->number == 0) {
          expr_destroy(&(*expr)->left);
          expr_destroy(&(*expr)->right);
          (*expr)->type = EXPR_NUMBER;
          (*expr)->number = 0;
        } else if ((*expr)->right->number == UINT64_MAX) {
          expr_destroy(&(*expr)->right);
          *expr = (*expr)->left;
          free(original_expr);
        }
      }
      break;
  }
}

void expr_simplify(struct expr_tree **expr) {
  expr_eliminate_negation(expr, false);
  expr_sort_operands(*expr);
  expr_precompute_eliminate(expr);
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
  free(*expr);
  *expr = NULL;
}

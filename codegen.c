/*
   Kafel - code generator
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

#include "codegen.h"

#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#include <linux/audit.h>
#include <linux/seccomp.h>
#include <sys/queue.h>

#include "common.h"
#include "range_rules.h"
#include "syscall.h"

#define INVALID_LOCATION INT_MIN
#define MAX_JUMP UINT8_MAX

#ifndef CODEGEN_INITAL_BUFFER_SIZE
#define CODEGEN_INITAL_BUFFER_SIZE 1024
#endif

#define CURRENT_LOC (ctxt->buffer.len - 1)
#define LOC_TO_JUMP(loc) (CURRENT_LOC - (loc))

#define ADD_INSTR(inst) (add_instruction(ctxt, ((struct sock_filter)inst)))

#define ADD_JUMP_K(type, k, tloc, floc)                        \
  (((type) == BPF_JGT)                                         \
       ? add_jump_gt(ctxt, (k), (tloc), (floc))                \
       : (((type) == BPF_JGE)                                  \
              ? add_jump_ge(ctxt, (k), (tloc), (floc))         \
              : (((type) == BPF_JSET)                          \
                     ? add_jump_set(ctxt, (k), (tloc), (floc)) \
                     : add_jump(ctxt, (type) | BPF_K, (k), (tloc), (floc)))))

#define ADD_JUMP_X(type, tloc, floc) \
  add_jump(ctxt, (type) | BPF_X, 0, (tloc), (floc))

static __u32 ACTION_TO_BPF(int action) {
  switch (action) {
    case ACTION_KILL:
      return SECCOMP_RET_KILL;
    case ACTION_ALLOW:
      return SECCOMP_RET_ALLOW;
  }
  int masked_action = action & 0xfff0000;
  int value = action & 0xffff;
  switch (masked_action) {
    case ACTION_TRAP:
      return SECCOMP_RET_TRAP | value;
    case ACTION_ERRNO:
      return SECCOMP_RET_ERRNO | value;
    case ACTION_TRACE:
      return SECCOMP_RET_TRACE | value;
  }
  ASSERT(0);  // should not happen
}

struct codegen_ctxt {
  struct {
    struct sock_filter *data;
    size_t len;
    size_t capacity;
  } buffer;
  struct {
    int basic_actions[ACTION_BASIC_MAX + 1];
    struct {
      int action;
      int location;
    } cache[MAX_JUMP];
    size_t cache_size;
  } locations;
};

static struct codegen_ctxt *context_create(void) {
  struct codegen_ctxt *ctxt = calloc(1, sizeof(*ctxt));
  ctxt->buffer.capacity = CODEGEN_INITAL_BUFFER_SIZE;
  ctxt->buffer.data = calloc(ctxt->buffer.capacity, sizeof(*ctxt->buffer.data));
  for (int i = 0; i <= ACTION_BASIC_MAX; ++i) {
    ctxt->locations.basic_actions[i] = INVALID_LOCATION;
  }
  return ctxt;
}

static void context_destroy(struct codegen_ctxt **ctxt) {
  ASSERT(ctxt != NULL);
  ASSERT((*ctxt) != NULL);

  free((*ctxt)->buffer.data);
  free(*ctxt);
  *ctxt = NULL;
}

static int add_instruction(struct codegen_ctxt *ctxt, struct sock_filter inst) {
  ASSERT(ctxt != NULL);

  if (ctxt->buffer.capacity <= ctxt->buffer.len) {
    size_t newcapacity = ctxt->buffer.capacity * 2;
    if (newcapacity == 0) {
      newcapacity = 1;
    }
    size_t oldbytes = ctxt->buffer.capacity * sizeof(*ctxt->buffer.data);
    size_t newbytes = newcapacity * sizeof(*ctxt->buffer.data);
    if (newcapacity < ctxt->buffer.capacity || newbytes < oldbytes) {
      ASSERT(0);  // overflow
    }
    ctxt->buffer.data = realloc(ctxt->buffer.data, newbytes);
    ctxt->buffer.capacity = newcapacity;
  }
  ctxt->buffer.data[ctxt->buffer.len++] = inst;
  return CURRENT_LOC;
}

static void purge_location_cache(struct codegen_ctxt *ctxt) {
  ASSERT(ctxt != NULL);

  size_t j = 0;
  for (size_t i = 0; i < ctxt->locations.cache_size; ++i) {
    if (LOC_TO_JUMP(ctxt->locations.cache[i].location) < MAX_JUMP) {
      if (j != i) {
        ctxt->locations.cache[j] = ctxt->locations.cache[i];
      }
      ++j;
    }
  }
  ctxt->locations.cache_size = j;
}

static __u8 resolve_action(struct codegen_ctxt *ctxt, int action) {
  ASSERT(ctxt != NULL);

  struct sock_filter action_inst =
      BPF_STMT(BPF_RET | BPF_K, ACTION_TO_BPF(action));

  if (action <= ACTION_BASIC_MAX) {
    if (ctxt->locations.basic_actions[action] == INVALID_LOCATION ||
        LOC_TO_JUMP(ctxt->locations.basic_actions[action]) > MAX_JUMP) {
      ctxt->locations.basic_actions[action] =
          add_instruction(ctxt, action_inst);
    }
    return LOC_TO_JUMP(ctxt->locations.basic_actions[action]);
  }

  // search cache
  for (size_t i = 0; i < ctxt->locations.cache_size; ++i) {
    if (ctxt->locations.cache[i].action == action) {
      if (LOC_TO_JUMP(ctxt->locations.cache[i].location) > MAX_JUMP) {
        ctxt->locations.cache[i].location = add_instruction(ctxt, action_inst);
      }
      return LOC_TO_JUMP(ctxt->locations.cache[i].location);
    }
  }

  purge_location_cache(ctxt);
  ASSERT(ctxt->locations.cache_size <
         (sizeof(ctxt->locations.cache) / sizeof(ctxt->locations.cache[0])));

  int location = add_instruction(ctxt, action_inst);
  ctxt->locations.cache[ctxt->locations.cache_size].action = action;
  ctxt->locations.cache[ctxt->locations.cache_size].location = location;
  ++ctxt->locations.cache_size;
  return LOC_TO_JUMP(location);
}

static __u8 resolve_location(struct codegen_ctxt *ctxt, int loc) {
  ASSERT(ctxt != NULL);

  if (loc < 0) {
    return resolve_action(ctxt, -loc);
  }

  int pos = LOC_TO_JUMP(loc);

  if (pos > MAX_JUMP) {
    loc = ADD_INSTR(BPF_STMT(BPF_JMP | BPF_JA, pos));
    pos = LOC_TO_JUMP(loc);
  }

  ASSERT(pos >= 0);
  ASSERT(pos <= MAX_JUMP);

  return pos;
}

static int add_jump(struct codegen_ctxt *ctxt, __u16 type, __u32 k, int tloc,
                    int floc) {
  ASSERT(ctxt != NULL);

  if (tloc == floc) {
    return tloc;
  }

  __u8 tpos = resolve_location(ctxt, tloc);
  __u8 fpos = resolve_location(ctxt, floc);
  // do tloc one more time as instruction added by floc may make it unreachable
  tpos = resolve_location(ctxt, tloc);
  return ADD_INSTR(BPF_JUMP(BPF_JMP | type, k, tpos, fpos));
}

static int add_jump_ge(struct codegen_ctxt *ctxt, __u32 than, int tloc,
                       int floc) {
  ASSERT(ctxt != NULL);

  if (than == 0) {
    return tloc;
  }

  return add_jump(ctxt, BPF_K | BPF_JGE, than, tloc, floc);
}

static int add_jump_gt(struct codegen_ctxt *ctxt, __u32 than, int tloc,
                       int floc) {
  ASSERT(ctxt != NULL);

  if (than == UINT32_MAX) {
    return floc;
  }

  return add_jump(ctxt, BPF_K | BPF_JGT, than, tloc, floc);
}

static int add_jump_set(struct codegen_ctxt *ctxt, __u32 what, int tloc,
                        int floc) {
  ASSERT(ctxt != NULL);

  if (what == 0) {
    return floc;
  }

  return add_jump(ctxt, BPF_K | BPF_JSET, what, floc, tloc);
}

#define HIGH_WORD 0
#define LOW_WORD 1

// TODO handle big-endian
#define ARG_LOW(arg) offsetof(struct seccomp_data, args[(arg)])
#define ARG_HIGH(arg) \
  offsetof(struct seccomp_data, args[(arg)]) + sizeof(uint32_t)
#define NUM_LOW(num) ((num)&UINT32_MAX)
#define NUM_HIGH(num) (((num) >> 32) & UINT32_MAX)

#define ARG_WORD(arg, word) ((word == HIGH_WORD) ? ARG_HIGH(arg) : ARG_LOW(arg))
#define NUM_WORD(num, word) ((word == HIGH_WORD) ? NUM_HIGH(num) : NUM_LOW(num))

#define BPF_LOAD_ARCH \
  BPF_STMT(BPF_LD + BPF_W + BPF_ABS, offsetof(struct seccomp_data, arch))
#define BPF_LOAD_SYSCALL \
  BPF_STMT(BPF_LD + BPF_W + BPF_ABS, offsetof(struct seccomp_data, nr))
#define BPF_LOAD_ARG_WORD(arg, high) \
  BPF_STMT(BPF_LD + BPF_W + BPF_ABS, ARG_WORD(arg, high))

static uint32_t value_of(struct expr_tree *expr, int word);

static bool is_const_value(struct expr_tree *expr, int word) {
  switch (expr->type) {
    case EXPR_NUMBER:
      return true;
    case EXPR_VAR:
      return false;
    case EXPR_BIT_AND:
      if (is_const_value(expr->right, word) &&
          value_of(expr->right, word) == 0) {
        return true;
      }
      if (is_const_value(expr->left, word) && value_of(expr->left, word) == 0) {
        return true;
      }
      return false;
    default:
      ASSERT(0);  // should not happen
  }
}

static uint32_t value_of(struct expr_tree *expr, int word) {
  switch (expr->type) {
    case EXPR_NUMBER:
      return NUM_WORD(expr->number, word);
    case EXPR_BIT_AND:
      if (is_const_value(expr->right, word) &&
          value_of(expr->right, word) == 0) {
        return 0;
      }
      if (is_const_value(expr->left, word) && value_of(expr->left, word) == 0) {
        return 0;
      }
    // fall-through
    default:
      ASSERT(0);  // should not happen
  }
}

static int generate_load(struct codegen_ctxt *ctxt, struct expr_tree *expr,
                         int word) {
  ASSERT(ctxt != NULL);
  ASSERT(expr != NULL);

  if (is_const_value(expr, word)) {
    ASSERT(0); /* valid but should not happen */
    return ADD_INSTR(BPF_STMT(BPF_LD | BPF_IMM, value_of(expr, word)));
  }

  switch (expr->type) {
    case EXPR_VAR:
      return ADD_INSTR(BPF_LOAD_ARG_WORD(expr->var, word));
    case EXPR_BIT_AND:
      if (is_const_value(expr->right, word)) {
        ADD_INSTR(
            BPF_STMT(BPF_ALU | BPF_AND | BPF_K, value_of(expr->right, word)));
        return generate_load(ctxt, expr->left, word);
      }
      ADD_INSTR(BPF_STMT(BPF_ALU | BPF_AND | BPF_X, 0));
      generate_load(ctxt, expr->left, word);
      ADD_INSTR(BPF_STMT(BPF_MISC | BPF_TAX, 0));
      return generate_load(ctxt, expr->right, word);
    default:
      ASSERT(0);  // should not happen
  }
}

static bool is_64bit(struct expr_tree *expr) {
  if (expr->type >= EXPR_BINARY_MIN && expr->type <= EXPR_BINARY_MAX) {
    return is_64bit(expr->left) || is_64bit(expr->right);
  }

  switch (expr->type) {
    case EXPR_NUMBER:
      return expr->number > UINT32_MAX;
    case EXPR_VAR:
      return expr->size == 8;
    default:
      ASSERT(0);  // should not happen
  }
}

enum {
  NEVER,
  NORMAL,
  ALWAYS,
};

static bool evaluate_jump(__u32 type, uint32_t left, uint32_t right) {
  switch (type) {
    case BPF_JEQ:
      return left == right;
    case BPF_JGE:
      return left >= right;
    case BPF_JGT:
      return left > right;
    case BPF_JSET:
      return left & right;
    default:
      ASSERT(0);  // should not happen
  }
}

static int generate_cmp32(struct codegen_ctxt *ctxt, __u32 type,
                          struct expr_tree *expr, int tloc, int floc, int word,
                          int load) {
  ASSERT(ctxt != NULL);
  ASSERT(expr != NULL);

  int next, begin = CURRENT_LOC;

  struct expr_tree *left = expr->left;
  struct expr_tree *right = expr->right;

  if (is_const_value(left, word)) {
    if (is_const_value(right, word)) {
      return evaluate_jump(type, value_of(left, word), value_of(right, word))
                 ? tloc
                 : floc;
    } else {
      SWAP(left, right);
      if (type == BPF_JGT) {
        type = BPF_JGE;
        SWAP(tloc, floc);
      } else if (type == BPF_JGE) {
        type = BPF_JGT;
        SWAP(tloc, floc);
      }
    }
  }

  // Only right may be a const value at this point

  if ((type == BPF_JEQ || type == BPF_JGT) && left->type == EXPR_BIT_AND &&
      is_const_value(right, word) && value_of(right, word) == 0) {
    right = left->right;
    left = left->left;
    if (is_const_value(left, word)) {
      SWAP(left, right);
    }
    type = BPF_JSET;
    if (type == BPF_JEQ) {
      SWAP(tloc, floc);
    }
  }

  if (is_const_value(right, word)) {
    next = ADD_JUMP_K(type, value_of(right, word), tloc, floc);
    if (load == ALWAYS || (load != NEVER && next > begin)) {
      begin = next = generate_load(ctxt, left, word);
    }
  } else {
    next = ADD_JUMP_X(type, tloc, floc);
    if (load == ALWAYS || (load != NEVER && next > begin)) {
      generate_load(ctxt, left, word);
      ADD_INSTR(BPF_STMT(BPF_MISC | BPF_TAX, 0));
      begin = next = generate_load(ctxt, right, word);
    }
  }

  return next;
}

static int generate_inequality(struct codegen_ctxt *ctxt, __u32 type,
                               struct expr_tree *expr, int tloc, int floc) {
  int next = generate_cmp32(ctxt, type, expr, tloc, floc, LOW_WORD, NORMAL);
  int begin = CURRENT_LOC;
  if (is_64bit(expr)) {
    next = generate_cmp32(ctxt, BPF_JGE, expr, next, floc, HIGH_WORD, NEVER);
    next = generate_cmp32(ctxt, BPF_JGT, expr, tloc, next, HIGH_WORD,
                          next > begin ? ALWAYS : NORMAL);
  }
  return next;
}

static int generate_equality(struct codegen_ctxt *ctxt, struct expr_tree *expr,
                             int tloc, int floc) {
  // TODO maybe compare low words first as they're more likely to differ
  int next = generate_cmp32(ctxt, BPF_JEQ, expr, tloc, floc, LOW_WORD, NORMAL);
  if (is_64bit(expr)) {
    next = generate_cmp32(ctxt, BPF_JEQ, expr, next, floc, HIGH_WORD, NORMAL);
  }
  return next;
}

static int generate_expr(struct codegen_ctxt *ctxt, struct expr_tree *expr,
                         int tloc, int floc) {
  ASSERT(ctxt != NULL);
  ASSERT(expr != NULL);

  switch (expr->type) {
    case EXPR_AND:
      tloc = generate_expr(ctxt, expr->right, tloc, floc);
      return generate_expr(ctxt, expr->left, tloc, floc);
    case EXPR_OR:
      floc = generate_expr(ctxt, expr->right, tloc, floc);
      return generate_expr(ctxt, expr->left, tloc, floc);
    case EXPR_LE:
      SWAP(tloc, floc);
    // fall-through
    case EXPR_GT:
      return generate_inequality(ctxt, BPF_JGT, expr, tloc, floc);
    case EXPR_LT:
      SWAP(tloc, floc);
    // fall-through
    case EXPR_GE:
      return generate_inequality(ctxt, BPF_JGE, expr, tloc, floc);
    case EXPR_NEQ:
      SWAP(tloc, floc);
    // fall-through
    case EXPR_EQ:
      return generate_equality(ctxt, expr, tloc, floc);
    default:
      ASSERT(0);  // should not happen
  }
}

static int generate_action(struct codegen_ctxt *ctxt,
                           struct syscall_range_rule *rule) {
  ASSERT(ctxt != NULL);
  ASSERT(rule != NULL);

  if (rule->action != ACTION_CONDITIONAL) {
    return -rule->action;
  }

  struct expression_to_action *mapping;
  int last_loc = INVALID_LOCATION;
  TAILQ_FOREACH_REVERSE(mapping, &rule->expr_list, expression_to_action_list,
                        list) {
    if (last_loc == INVALID_LOCATION) {
      ASSERT(mapping->expr == NULL || mapping->expr->type == EXPR_TRUE);
      last_loc = -mapping->action;
    } else {
      last_loc = generate_expr(ctxt, mapping->expr, -mapping->action, last_loc);
    }
  }
  ASSERT(last_loc != INVALID_LOCATION);
  return last_loc;
}

static int generate_rules(struct codegen_ctxt *ctxt,
                          struct syscall_range_rule *rules, size_t len) {
  ASSERT(ctxt != NULL);
  ASSERT(len > 0);

  if (len == 1) {
    return generate_action(ctxt, rules);
  }

  struct syscall_range_rule *mid = &rules[len / 2];
  int lower = generate_rules(ctxt, rules, len / 2);
  int upper = generate_rules(ctxt, mid, (len + 1) / 2);
  return add_jump(ctxt, BPF_JGE, mid->first, upper, lower);
}

static void reverse_instruction_buffer(struct codegen_ctxt *ctxt) {
  struct sock_filter *first = ctxt->buffer.data;
  struct sock_filter *last = first + (ctxt->buffer.len - 1);
  while (first < last) {
    SWAP(*first, *last);
    ++first, --last;
  }
}

int compile_policy(struct kafel_ctxt *kafel_ctxt, struct sock_fprog *prog) {
  ASSERT(kafel_ctxt != NULL);
  ASSERT(prog != NULL);

  if (kafel_ctxt->used_policy == NULL) {
    return -1;
  }

  struct codegen_ctxt *ctxt = context_create();
  struct syscall_range_rules *rules = range_rules_create();
  add_policy_rules(rules, kafel_ctxt->used_policy);
  normalize_rules(rules, kafel_ctxt->default_action);
  int begin = CURRENT_LOC;
  int next = generate_rules(ctxt, rules->data, rules->len);
  range_rules_destroy(&rules);
  if (next > begin) {
    begin = next = ADD_INSTR(BPF_LOAD_SYSCALL);
  } else {
    next = -kafel_ctxt->default_action;
  }
  next = add_jump(ctxt, BPF_JEQ, kafel_ctxt->target_arch, next, -ACTION_KILL);
  if (next > begin) {
    begin = next = ADD_INSTR(BPF_LOAD_ARCH);
  }
  if (next < 0) {
    resolve_location(ctxt, next);
  }
  reverse_instruction_buffer(ctxt);
  *prog = ((struct sock_fprog){.filter = ctxt->buffer.data,
                               .len = ctxt->buffer.len});
  ctxt->buffer.data = NULL;
  context_destroy(&ctxt);
  return 0;
}

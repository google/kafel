/*
   Kafel - code generator
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

#include "codegen.h"

#include <limits.h>
#include <linux/audit.h>
#include <linux/seccomp.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/queue.h>

#include "common.h"
#include "range_rules.h"
#include "syscall.h"

#define INVALID_LOCATION INT_MIN
#define MAX_JUMP UINT8_MAX

#ifndef CODEGEN_INITAL_BUFFER_SIZE
#define CODEGEN_INITAL_BUFFER_SIZE 1024
#endif

/*
    If headers are too old, take the define from
    include/uapi/linux/seccomp.h
*/
#ifndef SECCOMP_RET_LOG
#define SECCOMP_RET_LOG 0x7ffc0000U
#endif
#ifndef SECCOMP_RET_KILL_PROCESS
#define SECCOMP_RET_KILL_PROCESS 0x80000000U
#endif
#ifndef SECCOMP_RET_USER_NOTIF
#define SECCOMP_RET_USER_NOTIF 0x7fc00000U
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
    case ACTION_KILL_PROCESS:
      return SECCOMP_RET_KILL_PROCESS;
    case ACTION_ALLOW:
      return SECCOMP_RET_ALLOW;
    case ACTION_LOG:
      return SECCOMP_RET_LOG;
    case ACTION_USER_NOTIF:
      return SECCOMP_RET_USER_NOTIF;
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
  size_t max_stack_ptr;
};

static struct codegen_ctxt *context_create(void) {
  struct codegen_ctxt *ctxt = calloc(1, sizeof(*ctxt));
  ctxt->buffer.capacity = CODEGEN_INITAL_BUFFER_SIZE;
  ctxt->buffer.data = calloc(ctxt->buffer.capacity, sizeof(*ctxt->buffer.data));
  ctxt->max_stack_ptr = 0;
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
    ASSERT(ctxt->buffer.capacity <= SIZE_MAX / 2);  // overflow
    size_t newcapacity = ctxt->buffer.capacity * 2;
    if (newcapacity == 0) {
      newcapacity = 1;
    }
    ASSERT(newcapacity <= SIZE_MAX / sizeof(*ctxt->buffer.data));  // overflow
    size_t newbytes = newcapacity * sizeof(*ctxt->buffer.data);
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

static int resolve_action(struct codegen_ctxt *ctxt, int action) {
  ASSERT(ctxt != NULL);

  struct sock_filter action_inst =
      BPF_STMT(BPF_RET | BPF_K, ACTION_TO_BPF(action));

  if (action <= ACTION_BASIC_MAX) {
    if (ctxt->locations.basic_actions[action] == INVALID_LOCATION ||
        LOC_TO_JUMP(ctxt->locations.basic_actions[action]) > MAX_JUMP) {
      ctxt->locations.basic_actions[action] =
          add_instruction(ctxt, action_inst);
    }
    return ctxt->locations.basic_actions[action];
  }

  // search cache
  for (size_t i = 0; i < ctxt->locations.cache_size; ++i) {
    if (ctxt->locations.cache[i].action == action) {
      if (LOC_TO_JUMP(ctxt->locations.cache[i].location) > MAX_JUMP) {
        ctxt->locations.cache[i].location = add_instruction(ctxt, action_inst);
      }
      return ctxt->locations.cache[i].location;
    }
  }

  purge_location_cache(ctxt);
  ASSERT(ctxt->locations.cache_size <
         (sizeof(ctxt->locations.cache) / sizeof(ctxt->locations.cache[0])));

  int location = add_instruction(ctxt, action_inst);
  ctxt->locations.cache[ctxt->locations.cache_size].action = action;
  ctxt->locations.cache[ctxt->locations.cache_size].location = location;
  ++ctxt->locations.cache_size;
  return location;
}

static int resolve_location(struct codegen_ctxt *ctxt, int loc) {
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

  return loc;
}

static int add_jump(struct codegen_ctxt *ctxt, __u16 type, __u32 k, int tloc,
                    int floc) {
  ASSERT(ctxt != NULL);

  if (tloc == floc) {
    return tloc;
  }

  int tpos = resolve_location(ctxt, tloc);
  int fpos = resolve_location(ctxt, floc);
  // do tloc one more time as instruction added by floc may make it unreachable
  tpos = resolve_location(ctxt, tloc);
  return ADD_INSTR(
      BPF_JUMP(BPF_JMP | type, k, LOC_TO_JUMP(tpos), LOC_TO_JUMP(fpos)));
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

  return add_jump(ctxt, BPF_K | BPF_JSET, what, tloc, floc);
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

static bool is_const_value(struct expr_tree *expr, int word) {
  return word == HIGH_WORD ? expr->high.is_const : expr->low.is_const;
}

static uint32_t value_of(struct expr_tree *expr, int word) {
  return word == HIGH_WORD ? expr->high.value : expr->low.value;
}

static uint32_t evaluate_expression(int type, uint32_t left, uint32_t right) {
  switch (type) {
    case EXPR_BIT_OR:
      return left | right;
    case EXPR_BIT_AND:
      return left & right;
    default:
      ASSERT(0);  // should not happen
  }
}

static void cache_constants_by_word(struct expr_tree *expr, int word) {
  ASSERT(expr != NULL);

  struct cached_value *cached = (word == HIGH_WORD) ? &expr->high : &expr->low;
  cached->is_const = false;

  switch (expr->type) {
    case EXPR_NOT:
      cache_constants_by_word(expr->child, word);
      return;
    case EXPR_NUMBER:
      cached->is_const = true;
      cached->value = NUM_WORD(expr->number, word);
      return;
    case EXPR_VAR:
      return;
  }

  ASSERT(expr->type >= EXPR_BINARY_MIN && expr->type <= EXPR_BINARY_MAX);

  cache_constants_by_word(expr->right, word);
  cache_constants_by_word(expr->left, word);

  if (expr->type != EXPR_BIT_OR && expr->type != EXPR_BIT_AND) {
    return;
  }

  struct expr_tree *left = expr->left;
  struct expr_tree *right = expr->right;

  if (is_const_value(left, word)) {
    if (is_const_value(right, word)) {
      cached->is_const = true;
      cached->value = evaluate_expression(expr->type, value_of(left, word),
                                          value_of(right, word));
      return;
    }
    SWAP(left, right);
  }
  // Only right may be a const value at this point
  ASSERT(!is_const_value(left, word));

  if (!is_const_value(right, word)) {
    return;
  }

  uint32_t val = value_of(right, word);
  uint32_t clobber = 0;

  switch (expr->type) {
    case EXPR_BIT_OR:
      clobber = UINT32_MAX;
      /* fall-through */
    case EXPR_BIT_AND:
      if (val == clobber) {
        cached->is_const = true;
        cached->value = clobber;
      }
      break;
  }
}

static void cache_constants(struct expr_tree *expr) {
  ASSERT(expr != NULL);

  cache_constants_by_word(expr, HIGH_WORD);
  cache_constants_by_word(expr, LOW_WORD);
}

// Returns 1 if we need to push the result of executing the right sub-tree onto
// the stack (as opposed to the index register) before evaluating the left
// sub-tree.
static bool should_use_stack(struct expr_tree *left) {
  return left->type != EXPR_VAR;
}

static int generate_load(struct codegen_ctxt *ctxt, struct expr_tree *expr,
                         int word, size_t stack_ptr) {
  ASSERT(ctxt != NULL);
  ASSERT(expr != NULL);

  if (expr->type == EXPR_VAR) {
    return ADD_INSTR(BPF_LOAD_ARG_WORD(expr->var, word));
  }

  if (is_const_value(expr, word)) {
    ASSERT(0); /* valid but should not happen */
    return ADD_INSTR(BPF_STMT(BPF_LD | BPF_IMM, value_of(expr, word)));
  }

  ASSERT(expr->type >= EXPR_BINARY_MIN && expr->type <= EXPR_BINARY_MAX);

  struct expr_tree *left = expr->left;
  struct expr_tree *right = expr->right;

  if (is_const_value(left, word)) {
    SWAP(left, right);
  }

  // Only right may be a const value at this point
  ASSERT(!is_const_value(left, word));

  int op = BPF_OR;
  uint32_t identity_element = 0;

  switch (expr->type) {
    case EXPR_BIT_AND:
      op = BPF_AND;
      identity_element = UINT32_MAX;
      // fall-through
    case EXPR_BIT_OR:
      if (is_const_value(right, word)) {
        if (value_of(right, word) != identity_element) {
          ADD_INSTR(BPF_STMT(BPF_ALU | op | BPF_K, value_of(right, word)));
        }
        return generate_load(ctxt, left, word, stack_ptr);
      }
      bool use_stack = should_use_stack(left);
      ADD_INSTR(BPF_STMT(BPF_ALU | op | BPF_X, 0));
      if (use_stack) {
        ADD_INSTR(BPF_STMT(BPF_LDX | BPF_MEM, stack_ptr));
        generate_load(ctxt, left, word, stack_ptr + 1);
        if (stack_ptr > ctxt->max_stack_ptr) {
          ctxt->max_stack_ptr = stack_ptr;
        }
        ADD_INSTR(BPF_STMT(BPF_ST, stack_ptr));
      } else {
        generate_load(ctxt, left, word, stack_ptr);
        ADD_INSTR(BPF_STMT(BPF_MISC | BPF_TAX, 0));
      }
      return generate_load(ctxt, right, word, stack_ptr);
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
    if (type == BPF_JEQ) {
      SWAP(tloc, floc);
    }
    type = BPF_JSET;
  }

  ASSERT(!is_const_value(left, word));

  if (is_const_value(right, word)) {
    next = ADD_JUMP_K(type, value_of(right, word), tloc, floc);
    if (load == ALWAYS || (load != NEVER && next > begin)) {
      begin = next = generate_load(ctxt, left, word, 0);
    }
  } else {
    next = ADD_JUMP_X(type, tloc, floc);
    if (load == ALWAYS || (load != NEVER && next > begin)) {
      bool use_stack = should_use_stack(left);
      if (use_stack) {
        ADD_INSTR(BPF_STMT(BPF_LDX | BPF_MEM, 0));
        generate_load(ctxt, left, word, 1);
        ADD_INSTR(BPF_STMT(BPF_ST, 0));
      } else {
        generate_load(ctxt, left, word, 0);
        ADD_INSTR(BPF_STMT(BPF_MISC | BPF_TAX, 0));
      }
      begin = next = generate_load(ctxt, right, word, 0);
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
    case EXPR_NOT:
      return generate_expr(ctxt, expr->child, floc, tloc);
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
      ASSERT(mapping->expr != NULL);
      cache_constants(mapping->expr);
      last_loc = generate_expr(ctxt, mapping->expr, -mapping->action, last_loc);
    }
  }
  ASSERT(last_loc != INVALID_LOCATION);
  return last_loc;
}

static int generate_rules(struct codegen_ctxt *ctxt,
                          struct syscall_range_rules *rules) {
  ASSERT(ctxt != NULL);
  ASSERT(rules != NULL);
  ASSERT(rules->len != 0);

  struct {
    int level;
    int action;
    uint32_t nr;
  } buf[33];
  int num = 0;
  for (size_t i = rules->len; i > 0; --i) {
    struct syscall_range_rule *rule = &rules->data[i - 1];
    int action = generate_action(ctxt, rule);
    ASSERT(num == 0 || rule->last + 1 == buf[num - 1].nr);
    if (num > 0 && buf[num - 1].action == action) {
      buf[num - 1].nr = rule->first;
      continue;
    }
    while (num >= 2 && buf[num - 2].level == buf[num - 1].level) {
      --num;
      buf[num - 1].action = add_jump(ctxt, BPF_JGE, buf[num - 1].nr,
                                     buf[num - 1].action, buf[num].action);
      buf[num - 1].nr = buf[num].nr;
      ++buf[num - 1].level;
    }
    buf[num].level = 0;
    buf[num].nr = rule->first;
    buf[num].action = action;
    ++num;
  }
  ASSERT(num > 0);
  ASSERT(buf[num - 1].nr == 0);
  while (num >= 2) {
    --num;
    buf[num - 1].action = add_jump(ctxt, BPF_JGE, buf[num - 1].nr,
                                   buf[num - 1].action, buf[num].action);
    buf[num - 1].nr = buf[num].nr;
  }
  return buf[0].action;
}

static void reverse_instruction_buffer(struct codegen_ctxt *ctxt) {
  struct sock_filter *first = ctxt->buffer.data;
  struct sock_filter *last = first + (ctxt->buffer.len - 1);
  while (first < last) {
    SWAP(*first, *last);
    ++first, --last;
  }
}

static int compile_policy_impl(struct codegen_ctxt *ctxt,
                               struct kafel_ctxt *kafel_ctxt,
                               struct sock_fprog *prog) {
  ASSERT(ctxt != NULL);
  ASSERT(kafel_ctxt != NULL);
  ASSERT(prog != NULL);

  if (kafel_ctxt->main_policy == NULL) {
    kafel_ctxt->main_policy = policy_create("@main", NULL);
    register_policy(kafel_ctxt, kafel_ctxt->main_policy);
  }
  if (kafel_ctxt->default_action == 0) {
    kafel_ctxt->default_action = ACTION_KILL;
  }

  struct syscall_range_rules *rules = range_rules_create();
  const struct syscall_list *syscall_list =
      syscalls_lookup(kafel_ctxt->target_arch);
  ASSERT(syscall_list != NULL);
  mark_all_policies_unused(kafel_ctxt);
  add_policy_rules(rules, kafel_ctxt->main_policy, syscall_list);
  normalize_rules(rules, kafel_ctxt->default_action);
  int begin = CURRENT_LOC;
  int next = generate_rules(ctxt, rules);
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
  if (ctxt->max_stack_ptr >= BPF_MEMWORDS) {
    append_error(kafel_ctxt,
                 "Required stack size exceeds available BPF memory\n");
    return -1;
  }
  if (ctxt->buffer.len > USHRT_MAX) {
    append_error(
        kafel_ctxt,
        "Filter length exceeds maximum seccomp filter length: %zu > %d\n",
        ctxt->buffer.len, USHRT_MAX);
    return -1;
  }
  reverse_instruction_buffer(ctxt);
  *prog = ((struct sock_fprog){.filter = ctxt->buffer.data,
                               .len = ctxt->buffer.len});
  ctxt->buffer.data = NULL;
  return 0;
}

int compile_policy(struct kafel_ctxt *kafel_ctxt, struct sock_fprog *prog) {
  struct codegen_ctxt *ctxt = context_create();
  int rv = compile_policy_impl(ctxt, kafel_ctxt, prog);
  context_destroy(&ctxt);
  return rv;
}

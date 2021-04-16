/*
   Kafel - syscall range rules
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

#ifndef KAFEL_RANGE_RULES_H
#define KAFEL_RANGE_RULES_H

#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/queue.h>

#include "policy.h"
#include "syscall.h"

#ifndef INITAL_RANGE_RULES_SIZE
#define INITAL_RANGE_RULES_SIZE 16
#endif

#define ACTION_CONDITIONAL INT_MIN

struct expression_to_action {
  struct expr_tree *expr;
  int action;
  TAILQ_ENTRY(expression_to_action) list;
};

struct syscall_range_rule {
  uint32_t first;
  uint32_t last;
  int action;
  int priority;
  TAILQ_HEAD(expression_to_action_list, expression_to_action) expr_list;
};

struct syscall_range_rules {
  struct syscall_range_rule *data;
  size_t len;
  size_t capacity;
};

struct syscall_range_rules *range_rules_create(void);
void range_rules_destroy(struct syscall_range_rules **rules);
void add_policy_rules(struct syscall_range_rules *rules, struct policy *policy,
                      const struct syscall_list *syscall_list);
void normalize_rules(struct syscall_range_rules *rules, int default_action);

#endif /* KAFEL_RANGE_RULE_H */

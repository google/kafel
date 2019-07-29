/*
   Kafel - syscall range rules
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

#include "range_rules.h"

#include <stdint.h>
#include <stdlib.h>

#include "common.h"
#include "syscall.h"

static void range_rule_deinit(struct syscall_range_rule *rule) {
  ASSERT(rule != NULL);

  while (!TAILQ_EMPTY(&rule->expr_list)) {
    struct expression_to_action *mapping = TAILQ_FIRST(&rule->expr_list);
    TAILQ_REMOVE(&rule->expr_list, mapping, list);
    free(mapping);
  }
}

struct syscall_range_rules *range_rules_create(void) {
  struct syscall_range_rules *rv = calloc(1, sizeof(*rv));
  rv->capacity = INITAL_RANGE_RULES_SIZE;
  rv->data = calloc(rv->capacity, sizeof(*rv->data));
  return rv;
}

void range_rules_destroy(struct syscall_range_rules **rules) {
  ASSERT(rules != NULL);
  ASSERT((*rules) != NULL);

  for (size_t i = 0; i < (*rules)->len; ++i) {
    range_rule_deinit(&(*rules)->data[i]);
  }
  free((*rules)->data);
  free((*rules));
  *rules = NULL;
}

static void rule_add_expr(struct syscall_range_rule *rule,
                          struct expr_tree *expr, int action) {
  ASSERT(rule != NULL);

  struct expression_to_action *mapping = calloc(1, sizeof(*mapping));
  mapping->expr = expr;
  mapping->action = action;
  rule->action = ACTION_CONDITIONAL;
  TAILQ_INSERT_TAIL(&rule->expr_list, mapping, list);
}

static void fix_tailq_moving(struct syscall_range_rules *rules) {
  // Dirty hack to fix moving of TAILQ
  for (size_t i = 0; i < rules->len; ++i) {
    struct syscall_range_rule *cur = &rules->data[i];
    if (!TAILQ_EMPTY(&cur->expr_list)) {
      TAILQ_FIRST(&cur->expr_list)->list.tqe_prev = &cur->expr_list.tqh_first;
    } else {
      TAILQ_INIT(&cur->expr_list);
    }
  }
}

static void grow_range_rules(struct syscall_range_rules *rules,
                             size_t min_growth) {
  ASSERT(rules->len <= SIZE_MAX - min_growth);  // overflow
  size_t oldcapacity = rules->capacity;
  size_t reqcapacity = rules->len + min_growth;
  if (reqcapacity <= oldcapacity) {
    return;
  }
  ASSERT(rules->capacity <= SIZE_MAX / 2);  // overflow
  size_t newcapacity = rules->capacity * 2;
  if (newcapacity < reqcapacity) {
    newcapacity = reqcapacity;
  }
  ASSERT(newcapacity <= SIZE_MAX / sizeof(*rules->data));  // overflow
  size_t newbytes = newcapacity * sizeof(*rules->data);
  struct syscall_range_rule *newdata = realloc(rules->data, newbytes);
  ASSERT(newdata != NULL);  // OOM
  rules->data = newdata;
  rules->capacity = newcapacity;
  fix_tailq_moving(rules);
}

static void add_range_rule(struct syscall_range_rules *rules,
                           struct syscall_range_rule *rule) {
  ASSERT(rules != NULL);
  ASSERT(rule != NULL);

  grow_range_rules(rules, 1);
  struct syscall_range_rule *added = &rules->data[rules->len++];
  *added = *rule;
  added->priority = rules->len;
  TAILQ_INIT(&added->expr_list);
  TAILQ_CONCAT(&added->expr_list, &rule->expr_list, list);
}

void add_policy_rules(struct syscall_range_rules *rules,
                      struct policy *policy) {
  ASSERT(rules != NULL);
  ASSERT(policy != NULL);

  struct policy_entry *entry;
  struct syscall_filter *filter;

  TAILQ_FOREACH(entry, &policy->entries, entries) {
    switch (entry->type) {
      case POLICY_USE:
        add_policy_rules(rules, entry->used);
        break;
      case POLICY_ACTION:
        TAILQ_FOREACH(filter, &entry->filters, filters) {
          uint32_t syscall_nr = filter->syscall_nr;
          struct syscall_range_rule rule = {
              .first = syscall_nr,
              .last = syscall_nr,
          };
          TAILQ_INIT(&rule.expr_list);
          if (filter->expr != NULL && filter->expr->type != EXPR_TRUE) {
            if (filter->expr->type == EXPR_FALSE) {
              continue;
            }
            rule_add_expr(&rule, filter->expr, entry->action);
          } else {
            rule.action = entry->action;
          }
          add_range_rule(rules, &rule);
        }
        break;
      default:
        ASSERT(0);  // should not happen
    }
  }
}

static int by_syscall_and_priority(const void *av, const void *bv) {
  struct syscall_range_rule *a = (struct syscall_range_rule *)av;
  struct syscall_range_rule *b = (struct syscall_range_rule *)bv;
  if (a->first < b->first) return -1;
  if (a->first == b->first) {
    if (a->priority < b->priority) return -1;
    if (a->priority == b->priority) return 0;
  }
  return 1;
}

static void sort_range_rules(struct syscall_range_rules *rules) {
  qsort(rules->data, rules->len, sizeof(*rules->data), by_syscall_and_priority);
  fix_tailq_moving(rules);
}

static void normalize_expr_list(struct syscall_range_rule *rule,
                                int default_action) {
  struct expr_tree *last_expr = NULL;
  if (!TAILQ_EMPTY(&rule->expr_list)) {
    last_expr = TAILQ_LAST(&rule->expr_list, expression_to_action_list)->expr;
  }
  if (last_expr != NULL) {
    rule_add_expr(rule, NULL, default_action);
  }
}

static size_t normalize_rules_count_missing(struct syscall_range_rules *rules,
                                            int default_action) {
  ASSERT(rules != NULL);

  size_t len = rules->len;

  ASSERT(len > 0);

  size_t to_add = 0;
  size_t j = 1;
  for (size_t i = 1; i < len; ++i) {
    struct syscall_range_rule *cur = &rules->data[i];
    struct syscall_range_rule *prev = &rules->data[j - 1];
    ASSERT(cur->first == cur->last);
    if (cur->first == prev->last) {
      if (prev->action == ACTION_CONDITIONAL) {
        if (cur->action == ACTION_CONDITIONAL) {
          struct expr_tree *last_expr =
              TAILQ_LAST(&prev->expr_list, expression_to_action_list)->expr;
          if (last_expr != NULL && last_expr->type != EXPR_TRUE) {
            TAILQ_CONCAT(&prev->expr_list, &cur->expr_list, list);
          }
        } else {
          rule_add_expr(prev, NULL, cur->action);
        }
      }
      range_rule_deinit(cur);
      continue;
    } else if (cur->first == prev->last + 1) {
      if (prev->action != ACTION_CONDITIONAL && prev->action == cur->action) {
        prev->last = cur->last;
        range_rule_deinit(cur);
        continue;
      }
    } else {
      if (prev->action == default_action) {
        prev->last = cur->first - 1;
      } else if (cur->action == default_action) {
        cur->first = prev->last + 1;
      } else if (j < i) {
        struct syscall_range_rule *rule = &rules->data[j++];
        rule->first = prev->last + 1;
        rule->last = cur->first - 1;
        rule->action = default_action;
        TAILQ_INIT(&rule->expr_list);
      } else {
        ++to_add;
      }
    }
    normalize_expr_list(cur, default_action);
    if (j != i) {
      struct syscall_range_rule *dst = &rules->data[j];
      *dst = *cur;
      TAILQ_INIT(&dst->expr_list);
      TAILQ_CONCAT(&dst->expr_list, &cur->expr_list, list);
    }
    ++j;
  }
  rules->len = j;

  struct syscall_range_rule *first_rule = &rules->data[0];
  normalize_expr_list(first_rule, default_action);
  if (first_rule->first != 0) {
    if (first_rule->action == default_action) {
      first_rule->first = 0;
    } else {
      ++to_add;
    }
  }

  struct syscall_range_rule *last_rule = &rules->data[rules->len - 1];
  if (last_rule->last != MAX_SYSCALL_NR) {
    if (last_rule->action == default_action) {
      last_rule->last = MAX_SYSCALL_NR;
    } else {
      ++to_add;
    }
  }

  return to_add;
}

static void add_missing_rules(struct syscall_range_rules *rules, size_t to_add,
                              int default_action) {
  size_t oldlen = rules->len;
  grow_range_rules(rules, to_add);
  rules->len = oldlen + to_add;

  struct syscall_range_rule *last_rule = &rules->data[oldlen - 1];
  if (last_rule->last != MAX_SYSCALL_NR) {
    ASSERT(last_rule->action != default_action);
    rules->data[rules->len - 1] =
        ((struct syscall_range_rule){.first = last_rule->last + 1,
                                     .last = MAX_SYSCALL_NR,
                                     .action = default_action});
    TAILQ_INIT(&rules->data[rules->len - 1].expr_list);
    --to_add;
  }

  struct syscall_range_rule *prev = NULL;
  for (size_t i = oldlen; i > 0; --i) {
    struct syscall_range_rule *cur = &rules->data[(i - 1)];
    struct syscall_range_rule *dst = &rules->data[(i - 1) + to_add];
    if (prev != NULL && prev->first != cur->last + 1) {
      ASSERT(to_add > 0);
      dst->first = cur->last + 1;
      dst->last = prev->first - 1;
      dst->action = default_action;
      TAILQ_INIT(&dst->expr_list);
      --to_add;
      --dst;
    }
    if (dst != cur) {
      *dst = *cur;
      TAILQ_INIT(&dst->expr_list);
      TAILQ_CONCAT(&dst->expr_list, &cur->expr_list, list);
    }
    prev = cur;
  }

  if (to_add == 1) {
    ASSERT(rules->data[1].first > 0);
    rules->data[0] =
        ((struct syscall_range_rule){.first = 0,
                                     .last = rules->data[1].first - 1,
                                     .action = default_action});
    TAILQ_INIT(&rules->data[0].expr_list);
    --to_add;
  }

  ASSERT(to_add == 0);
}

void normalize_rules(struct syscall_range_rules *rules, int default_action) {
  ASSERT(rules != NULL);
  ASSERT(default_action != ACTION_CONDITIONAL);

  if (rules->len == 0) {
    struct syscall_range_rule rule = {
        .first = 0, .last = MAX_SYSCALL_NR, .action = default_action};
    add_range_rule(rules, &rule);
    return;
  }

  sort_range_rules(rules);
  size_t to_add = normalize_rules_count_missing(rules, default_action);
  add_missing_rules(rules, to_add, default_action);
}

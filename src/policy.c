/*
   Kafel - policy
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

#include "policy.h"

#include <stdlib.h>
#include <string.h>

#include "common.h"

struct policy* policy_create(const char* name, struct entrieslist* entries) {
  struct policy* rv = calloc(1, sizeof(*rv));
  rv->name = strdup(name);
  TAILQ_INIT(&rv->entries);
  if (entries != NULL) {
    TAILQ_CONCAT(&rv->entries, entries, entries);
  }
  return rv;
}

struct policy_entry* policy_action_create(uint32_t action,
                                          struct filterslist* filters) {
  struct policy_entry* rv = calloc(1, sizeof(*rv));
  rv->type = POLICY_ACTION;
  rv->action = action;
  TAILQ_INIT(&rv->filters);
  if (filters != NULL) {
    TAILQ_CONCAT(&rv->filters, filters, filters);
  }
  return rv;
}

struct policy_entry* policy_use_create(struct policy* used) {
  struct policy_entry* rv = calloc(1, sizeof(*rv));
  rv->type = POLICY_USE;
  rv->used = used;
  return rv;
}

static void policy_action_destroy(struct policy_entry** entry) {
  ASSERT(entry != NULL);
  ASSERT((*entry) != NULL);

  syscall_filters_destroy(&(*entry)->filters);
  free(*entry);
  *entry = NULL;
}

static void policy_use_destroy(struct policy_entry** entry) {
  ASSERT(entry != NULL);
  ASSERT((*entry) != NULL);

  free(*entry);
  *entry = NULL;
}

void policy_entry_destroy(struct policy_entry** entry) {
  ASSERT(entry != NULL);
  ASSERT((*entry) != NULL);

  switch ((*entry)->type) {
    case POLICY_ACTION:
      policy_action_destroy(entry);
      break;
    case POLICY_USE:
      policy_use_destroy(entry);
      break;
    default:
      ASSERT(0);  // should not happen
  }
}

void policy_entries_destroy(struct entrieslist* entries) {
  ASSERT(entries != NULL);

  // FIXME dirty hack
  if (!TAILQ_EMPTY(entries)) {
    TAILQ_FIRST(entries)->entries.tqe_prev = &entries->tqh_first;
  }

  while (!TAILQ_EMPTY(entries)) {
    struct policy_entry* entry = TAILQ_FIRST(entries);
    TAILQ_REMOVE(entries, entry, entries);
    policy_entry_destroy(&entry);
  }
}

void policy_destroy(struct policy** policy) {
  ASSERT(policy != NULL);
  ASSERT((*policy) != NULL);

  policy_entries_destroy(&(*policy)->entries);
  free((*policy)->name);
  free(*policy);
  *policy = NULL;
}

struct syscall_filter* syscall_filter_create(uint32_t nr,
                                             struct expr_tree* expr) {
  struct syscall_filter* rv = calloc(1, sizeof(*rv));
  rv->syscall_nr = nr;
  if (expr != NULL) {
    expr_simplify(&expr);
  }
  rv->expr = expr;
  return rv;
}

void syscall_filter_destroy(struct syscall_filter** filter) {
  ASSERT(filter != NULL);
  ASSERT((*filter) != NULL);

  if ((*filter)->expr != NULL) {
    expr_destroy(&(*filter)->expr);
  }
  free(*filter);
}

void syscall_filters_destroy(struct filterslist* filters) {
  ASSERT(filters != NULL);

  // FIXME dirty hack
  if (!TAILQ_EMPTY(filters)) {
    TAILQ_FIRST(filters)->filters.tqe_prev = &filters->tqh_first;
  }

  while (!TAILQ_EMPTY(filters)) {
    struct syscall_filter* filter = TAILQ_FIRST(filters);
    TAILQ_REMOVE(filters, filter, filters);
    syscall_filter_destroy(&filter);
  }
}

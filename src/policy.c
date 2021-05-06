/*
   Kafel - policy
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

struct syscall_spec* syscall_spec_create_identifier(
    struct kafel_identifier* identifier) {
  ASSERT(identifier != NULL);

  struct syscall_spec* rv = calloc(1, sizeof(*rv));
  rv->type = SYSCALL_SPEC_ID;
  rv->identifier = identifier;
  rv->custom_args_declared = false;
  return rv;
}

struct syscall_spec* syscall_spec_create_custom(int syscall_nr) {
  struct syscall_spec* rv = calloc(1, sizeof(*rv));
  rv->type = SYSCALL_SPEC_CUSTOM;
  rv->syscall_nr = syscall_nr;
  rv->custom_args_declared = false;
  return rv;
}

void syscall_spec_set_custom_args(struct syscall_spec* spec,
                                  struct custom_syscall_arg* custom_args) {
  ASSERT(spec != NULL);
  ASSERT(custom_args != NULL);
  spec->custom_args_declared = true;
  memcpy(spec->custom_args, custom_args, sizeof(spec->custom_args));
}

int syscall_spec_get_syscall_nr(const struct syscall_spec* spec,
                                const struct syscall_list* syscall_list) {
  switch (spec->type) {
    case SYSCALL_SPEC_ID: {
      const struct syscall_descriptor* desc =
          syscall_lookup(syscall_list, spec->identifier->id);
      ASSERT(desc != NULL);
      return desc->nr;
    }
    case SYSCALL_SPEC_CUSTOM:
      return spec->syscall_nr;
  }
  ASSERT(false);
}

void syscall_spec_get_args(const struct syscall_spec* spec,
                           const struct syscall_list* syscall_list,
                           struct syscall_arg out_args[SYSCALL_MAX_ARGS]) {
  if (spec->custom_args_declared) {
    for (int i = 0; i < SYSCALL_MAX_ARGS; ++i) {
      out_args[i].name = spec->custom_args[i].name;
      out_args[i].size = spec->custom_args[i].size;
    }
    return;
  }
  switch (spec->type) {
    case SYSCALL_SPEC_ID: {
      const struct syscall_descriptor* desc =
          syscall_lookup(syscall_list, spec->identifier->id);
      ASSERT(desc != NULL);
      for (int i = 0; i < SYSCALL_MAX_ARGS; ++i) {
        out_args[i].name = desc->args[i].name;
        out_args[i].size = desc->args[i].size;
      }
      break;
    }
    case SYSCALL_SPEC_CUSTOM:
      for (int i = 0; i < SYSCALL_MAX_ARGS; ++i) {
        out_args[i].name = NULL;
        out_args[i].size = 0;
      }
      break;
  }
}

void syscall_spec_destroy(struct syscall_spec** spec) {
  ASSERT(spec != NULL);
  ASSERT((*spec) != NULL);

  if ((*spec)->type == SYSCALL_SPEC_ID) {
    kafel_identifier_destroy(&(*spec)->identifier);
  }
  if ((*spec)->custom_args_declared) {
    for (int i = 0; i < SYSCALL_MAX_ARGS; ++i) {
      free((*spec)->custom_args[i].name);
    }
  }
  free(*spec);
  *spec = NULL;
}

struct syscall_filter* syscall_filter_create(struct syscall_spec* syscall,
                                             struct expr_tree* expr) {
  struct syscall_filter* rv = calloc(1, sizeof(*rv));
  rv->syscall = syscall;
  rv->expr = expr;
  return rv;
}

void syscall_filter_destroy(struct syscall_filter** filter) {
  ASSERT(filter != NULL);
  ASSERT((*filter) != NULL);

  syscall_spec_destroy(&(*filter)->syscall);
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

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

#ifndef KAFEL_POLICY_H
#define KAFEL_POLICY_H

#include <stdint.h>
#include <sys/queue.h>

#include "expression.h"

struct syscall_filter {
  uint32_t syscall_nr;
  struct expr_tree* expr;
  TAILQ_ENTRY(syscall_filter) filters;
};

TAILQ_HEAD(filterslist, syscall_filter);

enum { POLICY_USE, POLICY_ACTION };

enum {
  ACTION_KILL = 1,
  ACTION_ALLOW,
  ACTION_LOG,
  ACTION_KILL_PROCESS,
  ACTION_USER_NOTIF,
  ACTION_BASIC_MAX = ACTION_USER_NOTIF,
  ACTION_TRAP = 0x10000,
  ACTION_ERRNO = 0x20000,
  ACTION_TRACE = 0x40000,
};

struct policy_entry {
  int type;
  union {
    struct {
      uint32_t action;
      struct filterslist filters;
    };
    struct policy* used;
  };
  TAILQ_ENTRY(policy_entry) entries;
};

TAILQ_HEAD(entrieslist, policy_entry);

struct policy {
  char* name;
  struct entrieslist entries;
  TAILQ_ENTRY(policy) policies;
};

TAILQ_HEAD(policieslist, policy);

struct policy* policy_create(const char* name, struct entrieslist* entries);
void policy_destroy(struct policy** policy);
struct policy_entry* policy_action_create(uint32_t action,
                                          struct filterslist* filters);
struct policy_entry* policy_use_create(struct policy* used);
void policy_entry_destroy(struct policy_entry** entry);
void policy_entries_destroy(struct entrieslist* entries);

struct syscall_filter* syscall_filter_create(uint32_t nr,
                                             struct expr_tree* expr);
void syscall_filter_destroy(struct syscall_filter** filter);
void syscall_filters_destroy(struct filterslist* filters);

#endif /* KAFEL_POLICY_H */

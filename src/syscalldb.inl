/*
   Kafel - syscall database helper routines
   -----------------------------------------

   Copyright 2019 Google Inc. All Rights Reserved.

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

#include "syscall.h"

/* O(1) */
const struct syscalldb_definition* syscalldb_lookup(const char *name) {
  const struct syscalldb_entry *entry;
  if (!(entry = syscalldb_lookup_internal(name, strlen(name)))) return NULL;
  return (const struct syscalldb_definition*)(
    syscalldb_definitions+entry->definition_offset);
}

static inline uint32_t get_nr(
  const struct syscalldb_definition* def, uint32_t mask
) {
  uint32_t match = mask & def->arch_mask;
  return SYSCALLDB_DEFINITION_NR(def)[
    __builtin_popcount(def->arch_mask & (match^(match-1))) - 1];
}

/* O(n) */
const char* syscalldb_reverse_lookup(uint32_t mask, uint32_t nr) {
  const struct syscalldb_definition* def = (typeof(def))syscalldb_definitions;
  for (; def->arch_mask; def=SYSCALLDB_DEFINITION_NEXT(def)) {
    if (mask&def->arch_mask && get_nr(def, mask)==nr) {
      uint32_t offset = (uint32_t)(
        (const uint32_t*)def-syscalldb_definitions);
      const struct syscalldb_entry* entry = syscalldb_entries;
      while (entry->definition_offset!=offset) ++entry;
      return syscalldb_name_pool+entry->name;
    }
  }
  return NULL;
}

void syscalldb_unpack(
  const struct syscalldb_definition* def, uint32_t mask,
  struct syscall_descriptor *dest) {

  memset(dest, 0, sizeof *dest);
  dest->nr = get_nr(def, mask);
  if (def->n_arg_info<=INT32_MAX) {
    for (uint32_t i=def->n_arg_info; i--; ) {
      int argno = SYSCALLDB_GET_ARGNO(def->arg_info[i]);
      dest->args[argno].size = SYSCALLDB_GET_ARGTYPE(def->arg_info[i]);
      dest->args[argno].name = syscalldb_arg_name_pool
        +SYSCALLDB_GET_ARGNAME(def->arg_info[i]);
    }
  } else {
    for (uint32_t i=-def->n_arg_info; i--; ) {
      if (mask & def->ext_arg_info[i].arch_mask) {
        int argno = SYSCALLDB_GET_ARGNO(def->ext_arg_info[i].arg_info);
        dest->args[argno].size =
          SYSCALLDB_GET_ARGTYPE(def->ext_arg_info[i].arg_info);
        dest->args[argno].name = syscalldb_arg_name_pool
          +SYSCALLDB_GET_ARGNAME(def->ext_arg_info[i].arg_info);
      }
    }
  }
  for (int i=0; i!=SYSCALL_MAX_ARGS; ++i) {
    if (dest->args[i].name && !dest->args[i].size) {
      dest->args[i].size = syscalldb_pointer_size[
		__builtin_ctz(mask&def->arch_mask)];
    }
  }
}

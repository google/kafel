/*
   Kafel - syscalls
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

#ifndef KAFEL_SYSCALL_H
#define KAFEL_SYSCALL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define MAX_SYSCALL_NR UINT32_MAX
#define SYSCALL_MAX_ARGS 6

struct syscall_arg {
  const char* name;
  int size;
};

struct syscall_descriptor {
  const char* name;
  uint32_t nr;
  struct syscall_arg args[SYSCALL_MAX_ARGS];
};

struct syscall_list {
  uint32_t kafel_arch;
  uint32_t audit_arch;
  const struct syscall_descriptor* const syscalls;
  const size_t* const size;
};

uint32_t kafel_arch_lookup_by_audit_arch(uint32_t audit_arch);
const struct syscall_list* syscalls_lookup(uint32_t arch);
const struct syscall_descriptor* syscall_lookup(const struct syscall_list* list,
                                                const char* name);
void syscall_descriptor_destroy(struct syscall_descriptor** desc);

#endif /* KAFEL_SYSCALL_H */

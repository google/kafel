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

#include "syscall.h"

#include <linux/audit.h>
#include <stdlib.h>
#include <string.h>

#include "common.h"

// Fix for Linux <3.12
#ifndef EM_ARM
#define EM_ARM 40
#endif

#define SYSCALL_LIST_DECL(arch)                                 \
  extern const struct syscall_descriptor arch##_syscall_list[]; \
  extern const size_t arch##_syscall_list_size;

#define SYSCALL_LIST(audit_arch, arch) \
  { audit_arch, arch##_syscall_list, &arch##_syscall_list_size }

SYSCALL_LIST_DECL(arm)
SYSCALL_LIST_DECL(aarch64)
SYSCALL_LIST_DECL(amd64)
SYSCALL_LIST_DECL(mipso32)
SYSCALL_LIST_DECL(mips64)
SYSCALL_LIST_DECL(i386)

const struct syscall_list syscall_lists[] = {
#ifdef AUDIT_ARCH_ARM
    SYSCALL_LIST(AUDIT_ARCH_ARM, arm),
#endif
#ifdef AUDIT_ARCH_AARCH64
    SYSCALL_LIST(AUDIT_ARCH_AARCH64, aarch64),
#endif
#ifdef AUDIT_ARCH_X86_64
    SYSCALL_LIST(AUDIT_ARCH_X86_64, amd64),
#endif
#ifdef AUDIT_ARCH_MIPS
    SYSCALL_LIST(AUDIT_ARCH_MIPS, mipso32),
#endif
#ifdef AUDIT_ARCH_MIPS64
    SYSCALL_LIST(AUDIT_ARCH_MIPS64, mips64),
#endif
#ifdef AUDIT_ARCH_I386
    SYSCALL_LIST(AUDIT_ARCH_I386, i386),
#endif
};

const struct syscall_list* syscalls_lookup(uint32_t arch) {
  for (size_t i = 0; i < sizeof(syscall_lists) / sizeof(syscall_lists[0]);
       ++i) {
    if (syscall_lists[i].arch == arch) {
      return &syscall_lists[i];
    }
  }
  return NULL;
}

const struct syscall_descriptor* syscall_lookup(const struct syscall_list* list,
                                                const char* name) {
  ASSERT(list != NULL);
  ASSERT(name != NULL);
  /* TODO use binary search if syscalls can be guaranteed to be
   *  sorted alphabetically
   */
  for (size_t i = 0; i < *list->size; ++i) {
    if (strcmp(name, list->syscalls[i].name) == 0) {
      return &list->syscalls[i];
    }
  }
  return NULL;
}

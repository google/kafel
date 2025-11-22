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
#include <strings.h>

#include "common.h"
#include "kafel.h"

// Fix for Linux <3.12
#ifndef EM_ARM
#define EM_ARM 40
#endif

#define SYSCALL_LIST_DECL(arch)                                 \
  extern const struct syscall_descriptor arch##_syscall_list[]; \
  extern const size_t arch##_syscall_list_size;

#define SYSCALL_LIST(kafel_arch, audit_arch, arch) \
  { kafel_arch, audit_arch, arch##_syscall_list, &arch##_syscall_list_size }

SYSCALL_LIST_DECL(arm)
SYSCALL_LIST_DECL(aarch64)
SYSCALL_LIST_DECL(amd64)
SYSCALL_LIST_DECL(mipso32)
SYSCALL_LIST_DECL(mips64)
SYSCALL_LIST_DECL(i386)
SYSCALL_LIST_DECL(riscv64)
SYSCALL_LIST_DECL(m68k)

const struct syscall_list syscall_lists[] = {
#ifdef AUDIT_ARCH_ARM
    SYSCALL_LIST(KAFEL_TARGET_ARCH_ARM, AUDIT_ARCH_ARM, arm),
#endif
#ifdef AUDIT_ARCH_AARCH64
    SYSCALL_LIST(KAFEL_TARGET_ARCH_AARCH64, AUDIT_ARCH_AARCH64, aarch64),
#endif
#ifdef AUDIT_ARCH_X86_64
    SYSCALL_LIST(KAFEL_TARGET_ARCH_X86_64, AUDIT_ARCH_X86_64, amd64),
#endif
#ifdef AUDIT_ARCH_MIPS
    SYSCALL_LIST(KAFEL_TARGET_ARCH_MIPS, AUDIT_ARCH_MIPS, mipso32),
#endif
#ifdef AUDIT_ARCH_MIPS64
    SYSCALL_LIST(KAFEL_TARGET_ARCH_MIPS64, AUDIT_ARCH_MIPS64, mips64),
#endif
#ifdef AUDIT_ARCH_I386
    SYSCALL_LIST(KAFEL_TARGET_ARCH_X86, AUDIT_ARCH_I386, i386),
#endif
#ifdef AUDIT_ARCH_RISCV64
    SYSCALL_LIST(KAFEL_TARGET_ARCH_RISCV64, AUDIT_ARCH_RISCV64, riscv64),
#endif
#ifdef AUDIT_ARCH_M68K
    SYSCALL_LIST(KAFEL_TARGET_ARCH_M68K, AUDIT_ARCH_M68K, m68k),
#endif
};

const char* kafel_arch_to_string(uint32_t arch) {
  switch (arch) {
    case KAFEL_TARGET_ARCH_X86_64:
      return "x86_64";
    case KAFEL_TARGET_ARCH_AARCH64:
      return "aarch64";
    case KAFEL_TARGET_ARCH_ARM:
      return "arm";
    case KAFEL_TARGET_ARCH_X86:
      return "x86";
    case KAFEL_TARGET_ARCH_MIPS:
      return "mips";
    case KAFEL_TARGET_ARCH_MIPS64:
      return "mips64";
    case KAFEL_TARGET_ARCH_RISCV64:
      return "riscv64";
    case KAFEL_TARGET_ARCH_M68K:
      return "m68k";
    default:
      return "unknown";
  }
}

struct arch_name_entry {
  const char* name;
  uint32_t arch;
};

static const struct arch_name_entry arch_name_map[] = {
    {"arm", KAFEL_TARGET_ARCH_ARM},
    {"aarch64", KAFEL_TARGET_ARCH_AARCH64},
    {"arm64", KAFEL_TARGET_ARCH_AARCH64},
    {"x86_64", KAFEL_TARGET_ARCH_X86_64},
    {"amd64", KAFEL_TARGET_ARCH_X86_64},
    {"x86", KAFEL_TARGET_ARCH_X86},
    {"i386", KAFEL_TARGET_ARCH_X86},
    {"mips", KAFEL_TARGET_ARCH_MIPS},
    {"mipso32", KAFEL_TARGET_ARCH_MIPS},
    {"mips64", KAFEL_TARGET_ARCH_MIPS64},
    {"riscv64", KAFEL_TARGET_ARCH_RISCV64},
    {"rv64", KAFEL_TARGET_ARCH_RISCV64},
    {"m68k", KAFEL_TARGET_ARCH_M68K},
};

uint32_t kafel_arch_lookup_by_name(const char* name) {
  if (name == NULL) {
    return 0;
  }
  for (size_t i = 0; i < sizeof(arch_name_map) / sizeof(arch_name_map[0]);
       ++i) {
    if (strcasecmp(name, arch_name_map[i].name) == 0) {
      return arch_name_map[i].arch;
    }
  }
  return 0;
}

uint32_t kafel_arch_lookup_by_audit_arch(uint32_t audit_arch) {
  for (size_t i = 0; i < sizeof(syscall_lists) / sizeof(syscall_lists[0]);
       ++i) {
    if (syscall_lists[i].audit_arch == audit_arch) {
      return syscall_lists[i].kafel_arch;
    }
  }
  return 0;
}

const struct syscall_list* syscalls_lookup(uint32_t kafel_arch) {
  for (size_t i = 0; i < sizeof(syscall_lists) / sizeof(syscall_lists[0]);
       ++i) {
    if (syscall_lists[i].kafel_arch == kafel_arch) {
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

/*
   Kafel - syscalls
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

#include "syscall.h"

#include <linux/audit.h>
#include <stdlib.h>
#include <string.h>

#include "common.h"
#include "syscalldb.h"

// Fix for Linux <3.12
#ifndef EM_ARM
#define EM_ARM 40
#endif

struct syscall_descriptor* syscall_custom(uint32_t nr) {
  struct syscall_descriptor* rv = calloc(1, sizeof(*rv));
  rv->nr = nr;
  return rv;
}

uint32_t syscall_get_arch_mask(uint32_t arch) {
  switch (arch) {
    default:
      return 0;
#ifdef AUDIT_ARCH_ARM
    case AUDIT_ARCH_ARM:
      return SYSCALLDB_ARCH_ARM_FLAG;
#endif
#ifdef AUDIT_ARCH_AARCH64
    case AUDIT_ARCH_AARCH64:
      return SYSCALLDB_ARCH_AARCH64_FLAG;
#endif
#ifdef AUDIT_ARCH_X86_64
    case AUDIT_ARCH_X86_64:
      return SYSCALLDB_ARCH_X86_64_FLAG;
#endif
#ifdef AUDIT_ARCH_MIPS
    case AUDIT_ARCH_MIPS:
      return SYSCALLDB_ARCH_MIPS_FLAG;
#endif
#ifdef AUDIT_ARCH_MIPS64
    case AUDIT_ARCH_MIPS64:
      return SYSCALLDB_ARCH_MIPS64_FLAG;
#endif
#ifdef AUDIT_ARCH_I386
    case AUDIT_ARCH_I386:
      return SYSCALLDB_ARCH_I386_FLAG;
#endif
  }
}

const struct syscall_descriptor* syscall_lookup(uint32_t mask,
                                                const char* name) {
  const struct syscalldb_definition* def = syscalldb_lookup(name);
  if (def && mask & def->arch_mask) {
    struct syscall_descriptor* rv = calloc(1, sizeof(*rv));
    syscalldb_unpack(def, mask, rv);
    return rv;
  }
  return NULL;
}

void syscall_descriptor_destroy(struct syscall_descriptor** desc) {
  ASSERT(desc != NULL);
  ASSERT((*desc) != NULL);

  free(*desc);
  (*desc) = NULL;
}

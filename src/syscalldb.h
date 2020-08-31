/*
   Kafel - syscall database
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

#ifndef KAFEL_SYSCALLDB_H
#define KAFEL_SYSCALLDB_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

struct syscalldb_definition;
struct syscall_descriptor;

enum {
  SYSCALLDB_ARCH_ARM_FLAG = 0x01,
  SYSCALLDB_ARCH_AARCH64_FLAG = 0x02,
  SYSCALLDB_ARCH_X86_64_FLAG = 0x04,
  SYSCALLDB_ARCH_MIPS_FLAG = 0x08,
  SYSCALLDB_ARCH_MIPS64_FLAG = 0x10,
  SYSCALLDB_ARCH_I386_FLAG = 0x20,
};

const struct syscalldb_definition* syscalldb_lookup(const char* name);
const char* syscalldb_reverse_lookup(uint32_t arch_mask, uint32_t nr);

void syscalldb_unpack(const struct syscalldb_definition* definition,
                      uint32_t arch_mask, struct syscall_descriptor* dest);

/*
   internals

   Generated from individual syscall lists, has O(1) lookups and takes
   advantage of the redundancy in the data set to reduce footprint
   dramatically.

   O(1) lookups are courtesy of the perfect hash function generated with
   GNU gperf. PHF maps a name to an index in the table of <name, offset>
   tuples. If names match, syscall definition is found at the given
   offset.

   Syscall definitions are of the variable length and stored back to
   back. For details, consult syscalldb_definition struct.

*/

#define SYSCALLDB_MAX_ARGTYPE 8
#define SYSCALLDB_MAX_ARGNAME 0xffff

#define SYSCALLDB_ARGNO(no) (((uint32_t)(no)) << 24)
#define SYSCALLDB_ARGTYPE(type) (((uint32_t)(type)) << 16)
#define SYSCALLDB_ARGNAME(name) ((uint32_t)(name))

#define SYSCALLDB_GET_ARGNO(x) (((x)&UINT32_C(0xff000000)) >> 24)
#define SYSCALLDB_GET_ARGTYPE(x) (((x)&UINT32_C(0x00ff0000)) >> 16)
#define SYSCALLDB_GET_ARGNAME(x) (((x)&UINT32_C(0x0000ffff)))

struct syscalldb_entry {
  uint16_t name;
  uint16_t definition_offset;
};

/*
  Observations:

  (1) very few syscalls are arch-specific;

  (2) syscall numbers varies wildly across archs;

  (3) argument names and sizes (modulo pointer size differences) are the same
      across archs with a few notable exceptions (ex: clone).

  Last but not least, avoid pointers in static data structures with
  initializers! Due to PIC requirements every single one of theese
  require relocation. Increases the footprint and has runtime overhead.

*/
struct syscalldb_definition {
  uint32_t arch_mask;  /* archs providing this syscall */
  uint32_t n_arg_info; /* if >INT32_MAX), consult ext_arg_info;
                                                  it has -n_arg_info entries */
  union {
    uint32_t arg_info[1]; /* argno, argtype, argname */
    struct {
      uint32_t arch_mask; /* archs this entry applies to */
      uint32_t arg_info;  /* argno, argtype, argname */
    } ext_arg_info[1];
  };
  /* uint32_t nr[]; syscall numbers, one value per a bit set in arch_mask */
};

#define SYSCALLDB_DEFINITION_NR(d) \
  (&(d)->arch_mask + 2 +           \
   ((d)->n_arg_info > INT32_MAX ? 2 * -(d)->n_arg_info : (d)->n_arg_info))

#define SYSCALLDB_DEFINITION_NEXT(d) \
  (typeof(d))(SYSCALLDB_DEFINITION_NR(d) + __builtin_popcount((d)->arch_mask))

#endif /* KAFEL_SYSCALLDB_H */

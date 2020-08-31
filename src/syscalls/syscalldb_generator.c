/*
   Kafel - syscall database generator
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

#define _GNU_SOURCE /* memmem() */
#include "syscall.h"
#include "syscalldb.h"

#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <linux/audit.h>

#include "common.h"

// Fix for Linux <3.12
#ifndef EM_ARM
#define EM_ARM 40
#endif

#define SYSCALL_LIST_DECL(arch)                                 \
  extern const struct syscall_descriptor arch##_syscall_list[]; \
  extern const size_t arch##_syscall_list_size;

#define SYSCALL_LIST(flag, arch, pointer_size) \
  { flag, pointer_size, arch##_syscall_list, &arch##_syscall_list_size }

SYSCALL_LIST_DECL(arm)
SYSCALL_LIST_DECL(aarch64)
SYSCALL_LIST_DECL(amd64)
SYSCALL_LIST_DECL(mipso32)
SYSCALL_LIST_DECL(mips64)
SYSCALL_LIST_DECL(i386)

struct syscall_list {
  uint32_t arch_mask;
  int pointer_size;
  const struct syscall_descriptor* const syscalls;
  const size_t* const size;
};

const struct syscall_list syscall_lists[] = {
#ifdef AUDIT_ARCH_ARM
    SYSCALL_LIST(SYSCALLDB_ARCH_ARM_FLAG, arm, 4),
#endif
#ifdef AUDIT_ARCH_AARCH64
    SYSCALL_LIST(SYSCALLDB_ARCH_AARCH64_FLAG, aarch64, 8),
#endif
#ifdef AUDIT_ARCH_X86_64
    SYSCALL_LIST(SYSCALLDB_ARCH_X86_64_FLAG, amd64, 8),
#endif
#ifdef AUDIT_ARCH_MIPS
    SYSCALL_LIST(SYSCALLDB_ARCH_MIPS_FLAG, mipso32, 4),
#endif
#ifdef AUDIT_ARCH_MIPS64
    SYSCALL_LIST(SYSCALLDB_ARCH_MIPS64_FLAG, mips64, 8),
#endif
#ifdef AUDIT_ARCH_I386
    SYSCALL_LIST(SYSCALLDB_ARCH_I386_FLAG, i386, 4),
#endif
};

enum { NARCH = sizeof(syscall_lists) / sizeof(syscall_lists[0]) };

struct entry {
  const char* name;
  uint32_t definition_offset;
};

struct ctx {
  struct arch_ctx {
    uint32_t arch_mask;
    int pointer_size;
    const struct syscall_descriptor** syscall;
  } arch[NARCH];
  struct entry* syscall_entries;
  uint32_t syscall_entries_size, syscall_entries_capacity;
  uint32_t* syscall_definitions;
  uint32_t syscall_definitions_size;
  uint32_t syscall_definitions_capacity;
  char* arg_name_pool;
  uint32_t arg_name_pool_size;
  uint32_t arg_name_pool_capacity;
};

static int syscall_descriptor_name_cmp(const void* lhs, const void* rhs) {
  const char* syscall = (*(const struct syscall_descriptor**)lhs)->name;
  int cmp = strcmp(syscall, (*(const struct syscall_descriptor**)rhs)->name);
  if (!cmp) {
    fprintf(stderr,
            "Sanity check failed: multiple entries found for syscall '%s' "
            "in one list\n",
            syscall);
    exit(EXIT_FAILURE);
  }
  return cmp;
}

static int arch_ctx_arch_mask_cmp(const void* lhs, const void* rhs) {
  uint32_t larch_mask = ((const struct arch_ctx*)lhs)->arch_mask;
  uint32_t rarch_mask = ((const struct arch_ctx*)rhs)->arch_mask;
  if (larch_mask == rarch_mask) {
    fprintf(stderr, "Sanity check failed: non-unique arch_mask %" PRIx32 "\n",
            larch_mask);
    exit(EXIT_FAILURE);
  }
  return larch_mask < rarch_mask ? -1 : 1;
}

static void init(struct ctx* ctx) {
  for (size_t i = 0; i < NARCH; ++i) {
    const size_t size = *syscall_lists[i].size;
    const struct syscall_descriptor** p;
    p = malloc(sizeof(p[0]) * (size + 1));  // NULL-terminated
    for (size_t j = 0; j < size; ++j) p[j] = &syscall_lists[i].syscalls[j];
    qsort(p, size, sizeof(p[0]), syscall_descriptor_name_cmp);
    p[size] = NULL;
    ctx->arch[i].arch_mask = syscall_lists[i].arch_mask;
    ctx->arch[i].pointer_size = syscall_lists[i].pointer_size;
    ctx->arch[i].syscall = p;
    if (__builtin_popcount(ctx->arch[i].arch_mask) != 1) {
      fprintf(stderr,
              "Sanity check failed: invalid arch_mask %" PRIx32
              ", must have a single set bit\n",
              ctx->arch[i].arch_mask);
      exit(EXIT_FAILURE);
    }
  }
  qsort(ctx->arch, NARCH, sizeof(ctx->arch[0]), arch_ctx_arch_mask_cmp);
}

#define CHECK_CAPACITY(ctx, name, size)                                       \
  do {                                                                        \
    while ((ctx)->name##_size + size > (ctx)->name##_capacity) {              \
      if (!(ctx)->name##_capacity)                                            \
        (ctx)->name##_capacity = 1024;                                        \
      else                                                                    \
        (ctx)->name##_capacity *= 2;                                          \
      (ctx)->name = realloc((ctx)->name,                                      \
                            sizeof((ctx)->name[0]) * (ctx)->name##_capacity); \
    }                                                                         \
  } while (0)

static void syscall_entries_push(struct ctx* ctx, const char* name,
                                 uint32_t offset) {
  CHECK_CAPACITY(ctx, syscall_entries, 1);
  ctx->syscall_entries[ctx->syscall_entries_size].name = name;
  ctx->syscall_entries[ctx->syscall_entries_size].definition_offset = offset;
  ++ctx->syscall_entries_size;
}

static void syscall_definitions_push(struct ctx* ctx, uint32_t v) {
  CHECK_CAPACITY(ctx, syscall_definitions, 1);
  ctx->syscall_definitions[ctx->syscall_definitions_size++] = v;
}

static uint32_t arg_name_intern(struct ctx* ctx, const char* str) {
  uint32_t result, size = 1 + (uint32_t)strlen(str);
  char* existing =
      memmem(ctx->arg_name_pool, ctx->arg_name_pool_size, str, size);
  if (existing) return (uint32_t)(existing - ctx->arg_name_pool);
  CHECK_CAPACITY(ctx, arg_name_pool, size);
  memcpy(ctx->arg_name_pool + (result = ctx->arg_name_pool_size), str, size);
  ctx->arg_name_pool_size += size;
  return result;
}

// Find the lexicographically-minimal name in syscall descriptors
// pointed by ctx->arch[i].syscall; return the union of arch_mask-s
// of the architectures providing this syscall.
static uint32_t begin_syscall(const struct ctx* ctx,
                              const char** syscall_name) {
  static const char sentinel[] = {CHAR_MAX, 0};
  uint32_t mask = 0;
  const char* name_min = sentinel;
  for (size_t i = 0; i != NARCH; ++i) {
    int cmp;
    const char* name;
    if (!*ctx->arch[i].syscall) continue;
    cmp = strcmp(name_min, name = (*ctx->arch[i].syscall)->name);
    if (!cmp) {
      mask |= ctx->arch[i].arch_mask;
    } else if (cmp > 0) {
      mask = ctx->arch[i].arch_mask;
      name_min = name;
    }
  }
  *syscall_name = name_min;
  return mask;
}

// Extend syscall_definitions with syscall numbers from the subset of
// syscall descriptors pointed by ctx->arch[i].syscall as indicated by
// mask; advance ctx->arch[i].syscall pointers.
static void complete_syscall(struct ctx* ctx, uint32_t mask) {
  for (size_t i = 0; i < NARCH; ++i) {
    if (ctx->arch[i].arch_mask & mask) {
      syscall_definitions_push(ctx, (*ctx->arch[i].syscall)->nr);
      ++ctx->arch[i].syscall;
    }
  }
}

static uint32_t get_arg_name(const struct ctx* ctx, uint32_t mask, int argno,
                             const char** arg_name) {
  size_t i = 0;
  const char* name;
  uint32_t result;
  while (!(ctx->arch[i].arch_mask & mask) ||
         !(name = (*ctx->arch[i].syscall)->args[argno].name)) {
    if (++i == NARCH) return 0;
  }
  result = ctx->arch[i].arch_mask;
  *arg_name = name;
  while (++i != NARCH) {
    if (ctx->arch[i].arch_mask & mask &&
        (*ctx->arch[i].syscall)->args[argno].name &&
        !strcmp(name, (*ctx->arch[i].syscall)->args[argno].name)) {
      result |= ctx->arch[i].arch_mask;
    }
  }
  return result;
};

static bool is_ptr_sized_arg(const struct ctx* ctx, uint32_t mask, int argno) {
  for (size_t i = 0; i != NARCH; ++i) {
    if (ctx->arch[i].arch_mask & mask &&
        (*ctx->arch[i].syscall)->args[argno].size != ctx->arch[i].pointer_size)
      return false;
  }
  return true;
}

static uint32_t get_arg_type(const struct ctx* ctx, uint32_t mask, int argno,
                             int* arg_type) {
  size_t i = 0;
  int type;
  uint32_t result;
  while (!(ctx->arch[i].arch_mask & mask)) {
    if (++i == NARCH) return 0;
  }
  result = ctx->arch[i].arch_mask;
  *arg_type = type = (*ctx->arch[i].syscall)->args[argno].size;
  while (++i != NARCH) {
    if (ctx->arch[i].arch_mask & mask &&
        (*ctx->arch[i].syscall)->args[argno].size == type)
      result |= ctx->arch[i].arch_mask;
  }
  return result;
}

static void do_arg(struct ctx* ctx, uint32_t mask, int argno) {
  uint32_t namemask;
  const char* name;
  while ((namemask = get_arg_name(ctx, mask, argno, &name))) {
    uint32_t iname = arg_name_intern(ctx, name);
    uint32_t typemask;
    int type;
    mask &= ~namemask;
    if (is_ptr_sized_arg(ctx, namemask, argno)) {
      syscall_definitions_push(ctx, namemask);
      syscall_definitions_push(ctx, SYSCALLDB_ARGNO(argno) |
                                        SYSCALLDB_ARGTYPE(0) |
                                        SYSCALLDB_ARGNAME(iname));
      continue;
    }
    while ((typemask = get_arg_type(ctx, namemask, argno, &type))) {
      namemask &= ~typemask;
      if (type <= 0 || type > SYSCALLDB_MAX_ARGTYPE) {
        fprintf(stderr,
                "Syscall %s, argument #%d (%s): "
                "invalid argument size: %d\n",
                ctx->syscall_entries[ctx->syscall_entries_size - 1].name, argno,
                name, type);
        exit(EXIT_FAILURE);
      }
      syscall_definitions_push(ctx, typemask);
      syscall_definitions_push(ctx, SYSCALLDB_ARGNO(argno) |
                                        SYSCALLDB_ARGTYPE(type) |
                                        SYSCALLDB_ARGNAME(iname));
    }
  }
}

static uint32_t compress_args(struct ctx* ctx, uint32_t mask,
                              uint32_t firstargoff) {
  uint32_t narg = (ctx->syscall_definitions_size - firstargoff) / 2;
  for (uint32_t i = firstargoff; i != ctx->syscall_definitions_size; i += 2)
    if (ctx->syscall_definitions[i] != mask) return -narg;
  for (uint32_t i = 0; i != narg; ++i) {
    ctx->syscall_definitions[firstargoff + i] =
        ctx->syscall_definitions[firstargoff + i * 2 + 1];
  }
  ctx->syscall_definitions_size = firstargoff + narg;
  return narg;
}

static void write_pointer_size(const struct ctx* ctx) {
  fputs("static const int syscalldb_pointer_size[] = {\n ", stdout);
  for (int i = 0; i != NARCH; ++i) {
    printf(", [%d] = %d" + !i, __builtin_ctz(ctx->arch[i].arch_mask),
           syscall_lists[i].pointer_size);
  }
  fputs("\n};\n\n", stdout);
}

static void write_syscall_definitions(const struct ctx* ctx) {
  const struct syscalldb_definition* def =
      (typeof(def))ctx->syscall_definitions;
  const struct entry* entry = ctx->syscall_entries;
  fputs("static const uint32_t syscalldb_definitions[] = {\n\n", stdout);
  for (; def->arch_mask; def = SYSCALLDB_DEFINITION_NEXT(def), ++entry) {
    printf("  // %s\n  %#" PRIx32 ", ", entry->name, def->arch_mask);
    if (def->n_arg_info <= INT32_MAX) {
      printf("%" PRId32 ",\n", def->n_arg_info);
      for (uint32_t i = 0; i != def->n_arg_info; ++i) {
        printf("  ARGNO(%d) | ARGTYPE(%d) | ARGNAME(%d), // %s\n",
               (int)SYSCALLDB_GET_ARGNO(def->arg_info[i]),
               (int)SYSCALLDB_GET_ARGTYPE(def->arg_info[i]),
               (int)SYSCALLDB_GET_ARGNAME(def->arg_info[i]),
               ctx->arg_name_pool + SYSCALLDB_GET_ARGNAME(def->arg_info[i]));
      }
    } else {
      printf("-%" PRId32 ",\n", -def->n_arg_info);
      for (uint32_t i = 0; i != -def->n_arg_info; ++i) {
        printf("  %#" PRIx32 ", ARGNO(%d) | ARGTYPE(%d) | ARGNAME(%d), // %s\n",
               def->ext_arg_info[i].arch_mask,
               (int)SYSCALLDB_GET_ARGNO(def->ext_arg_info[i].arg_info),
               (int)SYSCALLDB_GET_ARGTYPE(def->ext_arg_info[i].arg_info),
               (int)SYSCALLDB_GET_ARGNAME(def->ext_arg_info[i].arg_info),
               ctx->arg_name_pool +
                   SYSCALLDB_GET_ARGNAME(def->ext_arg_info[i].arg_info));
      }
    }
    for (int i = 0; i != __builtin_popcount(def->arch_mask); ++i) {
      printf("  %" PRId32 "," + (i != 0), SYSCALLDB_DEFINITION_NR(def)[i]);
    }
    fputs("\n\n", stdout);
  }
  fputs("  0\n};\n\n", stdout);
}

static void write_arg_name_pool(const struct ctx* ctx) {
  enum { MAX_WIDTH = 72, INDENT = 1, QUOTATION_AND_DELIMITER_CHARS = 5 };
  fputs("static const char syscalldb_arg_name_pool[] =\n ", stdout);
  uint32_t i = 0;
  int pos = INDENT;
  while (i != ctx->arg_name_pool_size) {
    size_t len = strlen(ctx->arg_name_pool + i);
    pos += QUOTATION_AND_DELIMITER_CHARS + (int)len;
    if (pos >= MAX_WIDTH) {
      fputs("\n ", stdout);
      pos = INDENT + QUOTATION_AND_DELIMITER_CHARS + (int)len;
    }
    printf(" \"%s\\0\"", ctx->arg_name_pool + i);
    i += (uint32_t)len + 1;
  }
  fputs(";\n\n", stdout);
}

int main() {
  struct ctx ctx = {};
  uint32_t mask;
  const char* name;
  init(&ctx);
  while ((mask = begin_syscall(&ctx, &name))) {
    uint32_t firstargoff;
    syscall_entries_push(&ctx, name, ctx.syscall_definitions_size);
    syscall_definitions_push(&ctx, mask);
    syscall_definitions_push(&ctx, 0);
    firstargoff = ctx.syscall_definitions_size;
    for (int argno = 0; argno < SYSCALL_MAX_ARGS; ++argno) {
      do_arg(&ctx, mask, argno);
    }
    ctx.syscall_definitions[firstargoff - 1] =
        compress_args(&ctx, mask, firstargoff);
    complete_syscall(&ctx, mask);
  }
  syscall_definitions_push(&ctx, 0);
  if (ctx.arg_name_pool_size > SYSCALLDB_MAX_ARGNAME) {
    fprintf(stderr,
            "String pool size exceeds %d, "
            "consider increasing SYSCALLDB_MAX_ARGNAME\n",
            (int)SYSCALLDB_MAX_ARGNAME);
    exit(EXIT_FAILURE);
  }
  // Produce output in gperf format
  fputs(
      "%{\n"
      "#include \"syscalldb.h\"\n"
      "\n"
      "#define ARGNO(no)     SYSCALLDB_ARGNO(no)\n"
      "#define ARGTYPE(type) SYSCALLDB_ARGTYPE(type)\n"
      "#define ARGNAME(name) SYSCALLDB_ARGNAME(name)\n"
      "\n",
      stdout);
  write_pointer_size(&ctx);
  write_syscall_definitions(&ctx);
  write_arg_name_pool(&ctx);
  fputs(
      "%}\n"
      "%struct-type\n"
      "%readonly-tables\n"
      "%global-table\n"
      "%pic\n"
      "%define initializer-suffix ,-1\n"
      "%define word-array-name syscalldb_entries\n"
      "%define string-pool-name syscalldb_name_pool\n"
      "%define lookup-function-name syscalldb_lookup_internal\n"
      "struct syscalldb_entry;\n"
      "%%\n",
      stdout);
  for (uint32_t i = 0; i != ctx.syscall_entries_size; ++i) {
    printf("%s, %u\n", ctx.syscall_entries[i].name,
           ctx.syscall_entries[i].definition_offset);
  }
  fputs(
      "%%\n"
      "#include \"syscalldb.inl\"\n",
      stdout);
  return 0;
}

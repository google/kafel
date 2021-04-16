/*
   Kafel - BPF pretty printer
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

#include "print.h"

#include <inttypes.h>
#include <linux/seccomp.h>
#include <stddef.h>
#include <stdio.h>

/*
    If headers are too old, take the define from
    include/uapi/linux/seccomp.h
*/
#ifndef SECCOMP_RET_LOG
#define SECCOMP_RET_LOG 0x7ffc0000U
#endif
#ifndef SECCOMP_RET_KILL_PROCESS
#define SECCOMP_RET_KILL_PROCESS 0x80000000U
#endif
#ifndef SECCOMP_RET_USER_NOTIF
#define SECCOMP_RET_USER_NOTIF 0x7fc00000U
#endif

const char* action_to_string(int action) {
#define MAP(x) \
  case x:      \
    return #x;
  switch (action) {
    MAP(SECCOMP_RET_KILL_PROCESS)
    MAP(SECCOMP_RET_KILL)
    MAP(SECCOMP_RET_TRAP)
    MAP(SECCOMP_RET_ERRNO)
    MAP(SECCOMP_RET_USER_NOTIF)
    MAP(SECCOMP_RET_TRACE)
    MAP(SECCOMP_RET_LOG)
    MAP(SECCOMP_RET_ALLOW)
  }
#undef MAP
  return NULL;
}

static void print_offset(uint32_t offset, int mode) {
#define MAP(x) [x] = #x
  static const char* offsets[sizeof(struct seccomp_data) + 1] = {
      MAP(offsetof(struct seccomp_data, nr)),
      MAP(offsetof(struct seccomp_data, arch)),
      MAP(offsetof(struct seccomp_data, instruction_pointer)),
      MAP(offsetof(struct seccomp_data, args[0])),
      MAP(offsetof(struct seccomp_data, args[1])),
      MAP(offsetof(struct seccomp_data, args[2])),
      MAP(offsetof(struct seccomp_data, args[3])),
      MAP(offsetof(struct seccomp_data, args[4])),
      MAP(offsetof(struct seccomp_data, args[5])),
  };
#undef MAP
  if (mode == BPF_ABS && offset <= sizeof(struct seccomp_data)) {
    if (offsets[offset]) {
      printf("%s", offsets[offset]);
      return;
    }
    for (int i = offset; i >= 0; --i) {
      if (offsets[i]) {
        printf("%s + ", offsets[i]);
        if (offset - i == sizeof(__u32)) {
          printf("%s", "sizeof(__u32)");
        } else {
          printf("%" PRId32 "", offset - i);
        }
        return;
      }
    }
  }
  printf("%#" PRIx32 "u", offset);
}

void pretty_print_inst(const struct sock_filter* inst) {
#define MAP(x) [x] = #x
  static const char* classes[] = {
      MAP(BPF_LD),  MAP(BPF_LDX), MAP(BPF_ST),  MAP(BPF_STX),
      MAP(BPF_ALU), MAP(BPF_JMP), MAP(BPF_RET), MAP(BPF_MISC),
  };
  static const char* cmps[] = {
      MAP(BPF_JA), MAP(BPF_JEQ), MAP(BPF_JGT), MAP(BPF_JGE), MAP(BPF_JSET),
  };
  static const char* sizes[] = {
      MAP(BPF_B),
      MAP(BPF_W),
      MAP(BPF_H),
  };
  static const char* modes[] = {
      MAP(BPF_IMM), MAP(BPF_ABS), MAP(BPF_IND),
      MAP(BPF_MEM), MAP(BPF_LEN), MAP(BPF_MSH),
  };
  static const char* ops[] = {
      MAP(BPF_ADD), MAP(BPF_SUB), MAP(BPF_MUL), MAP(BPF_DIV),
      MAP(BPF_OR),  MAP(BPF_AND), MAP(BPF_LSH), MAP(BPF_RSH),
      MAP(BPF_NEG), MAP(BPF_MOD), MAP(BPF_XOR),
  };
  static const char* misc_ops[] = {
      MAP(BPF_TAX),
      MAP(BPF_TXA),
  };
  static const char* srcs[] = {
      MAP(BPF_K),
      MAP(BPF_X),
  };
  static const char* rvals[] = {
      MAP(BPF_K),
      MAP(BPF_A),
      MAP(BPF_X),
  };
#undef MAP
  const int code = inst->code;
  const int inst_class = BPF_CLASS(code);
  const int op = BPF_OP(code);
  const int src = BPF_SRC(code);
  const int mode = BPF_MODE(code);
  switch (inst_class) {
    case BPF_LD:
    case BPF_LDX:
      printf("BPF_STMT(%s | ", classes[inst_class]);
      if (mode == BPF_IMM) {
        printf("%s, %#" PRIx32 "u)", modes[BPF_MODE(code)], inst->k);
      } else if (mode == BPF_MEM) {
        printf("%s, %" PRId32 ")", modes[BPF_MODE(code)], inst->k);
      } else {
        printf("%s | %s, ", sizes[BPF_SIZE(code)], modes[BPF_MODE(code)]);
        print_offset(inst->k, mode);
        printf(")");
      }
      break;
    case BPF_MISC:
      printf("BPF_STMT(%s | %s, %#" PRIx32 "u)", classes[inst_class],
             misc_ops[BPF_MISCOP(code)], inst->k);
      break;
    case BPF_RET:
      printf("BPF_STMT(%s | %s, ", classes[inst_class], rvals[BPF_RVAL(code)]);
      if (BPF_RVAL(code) == BPF_K) {
        if ((inst->k & SECCOMP_RET_DATA) == 0) {
          printf("%s)", action_to_string(inst->k));
        } else {
          printf("%s | %#" PRIx32 "u)",
                 action_to_string(inst->k & SECCOMP_RET_ACTION),
                 inst->k & SECCOMP_RET_DATA);
        }
      } else {
        printf("%#" PRIx32 "u)", inst->k);
      }
      break;
    case BPF_ST:
    case BPF_STX:
      printf("BPF_STMT(%s, %" PRId32 ")", classes[inst_class], inst->k);
      break;
    case BPF_ALU:
      if (op == BPF_NEG) {
        printf("BPF_STMT(%s | %s, %#" PRIx32 "u)", classes[inst_class], ops[op],
               inst->k);
      } else {
        printf("BPF_STMT(%s | %s | %s, %#" PRIx32 "u)", classes[inst_class],
               ops[op], srcs[src], inst->k);
      }
      break;
    case BPF_JMP:
      if (op == BPF_JA) {
        printf("BPF_JUMP(%s | %s, %#" PRIx32 "u, %d, %d)", classes[inst_class],
               cmps[op], inst->k, inst->jt, inst->jf);
      } else {
        printf("BPF_JUMP(%s | %s | %s, %#" PRIx32 "u, %d, %d)",
               classes[inst_class], cmps[op], srcs[src], inst->k, inst->jt,
               inst->jf);
      }
      break;
  }
}

void pretty_print(struct sock_fprog prog) {
  for (int i = 0; i < prog.len; ++i) {
    pretty_print_inst(&prog.filter[i]);
    puts(",");
  }
}

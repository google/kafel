/*
   Kafel - BPF disassembler
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

#include "disasm.h"

#include <inttypes.h>
#include <linux/seccomp.h>
#include <stddef.h>
#include <stdio.h>

#define OFFSET(field) offsetof(struct seccomp_data, field)
#define SIZE_OF(field) sizeof(((struct seccomp_data*)0)->field)
#define INSIDE_FIELD(what, field)                     \
  ((OFFSET(field) == 0 || (what) >= OFFSET(field)) && \
   ((what) < (OFFSET(field) + SIZE_OF(field))))

void disasm_inst(const struct sock_filter* inst, const int pc) {
  const int op = BPF_OP(inst->code);
  static const char* ops[] = {
      [BPF_ADD] = "+", [BPF_SUB] = "-",  [BPF_MUL] = "*",
      [BPF_DIV] = "/", [BPF_XOR] = "^",  [BPF_AND] = "&",
      [BPF_OR] = "|",  [BPF_RSH] = ">>", [BPF_LSH] = "<<"};
  static const char* cmps[] = {
      [BPF_JGE] = ">=", [BPF_JGT] = ">", [BPF_JEQ] = "==", [BPF_JSET] = "&"};
  static const char* cmps_neg[] = {
      [BPF_JGE] = "<", [BPF_JGT] = "<=", [BPF_JEQ] = "!="};
  printf("%3d: ", pc);
  switch (inst->code) {
    case BPF_LD | BPF_W | BPF_ABS:
      if (inst->k & 3) {
        printf("A := %d // misaligned read", inst->k);
      } else if (INSIDE_FIELD(inst->k, nr)) {
        printf("A := syscall number");
      } else if (INSIDE_FIELD(inst->k, arch)) {
        printf("A := architecture");
      } else if (INSIDE_FIELD(inst->k, instruction_pointer)) {
        printf("A := instruction pointer");
        // TODO handle big-endian
        if (inst->k != OFFSET(instruction_pointer))
          printf(" high");
        else
          printf(" low");
      } else if (INSIDE_FIELD(inst->k, args)) {
        int argno = (inst->k - OFFSET(args[0])) / SIZE_OF(args[0]);
        printf("A := arg %" PRIu32, argno);
        // TODO handle big-endian
        if (inst->k != OFFSET(args[argno]))
          printf(" high");
        else
          printf(" low");
      } else {
        printf("A := data[%#" PRIx32 "] (invalid load)", inst->k);
      }
      break;
    case BPF_LD | BPF_W | BPF_LEN:
      printf("A := sizeof(seccomp_data)");
      break;
    case BPF_LDX | BPF_W | BPF_LEN:
      printf("X := sizeof(seccomp_data)");
      break;
    case BPF_LD | BPF_IMM:
      printf("A := %#" PRIx32, inst->k);
      break;
    case BPF_LDX | BPF_IMM:
      printf("X := %#" PRIx32, inst->k);
      break;
    case BPF_MISC | BPF_TAX:
      printf("X := A");
      break;
    case BPF_MISC | BPF_TXA:
      printf("A := X");
      break;
    case BPF_LD | BPF_MEM:
      printf("A := M[%" PRIu32 "]", inst->k);
      break;
    case BPF_LDX | BPF_MEM:
      printf("X := M[%" PRIu32 "]", inst->k);
      break;
    case BPF_ST:
      printf("M[%" PRIu32 "] := A", inst->k);
      break;
    case BPF_STX:
      printf("M[%" PRIu32 "] := X", inst->k);
      break;
    case BPF_RET | BPF_K: {
      __u32 data = inst->k & SECCOMP_RET_DATA;
#ifdef SECCOMP_RET_ACTION_FULL
      switch (inst->k & SECCOMP_RET_ACTION_FULL) {
#ifdef SECCOMP_RET_KILL_PROCESS
        case SECCOMP_RET_KILL_PROCESS:
          printf("KILL_PROCESS");
          break;
#endif
#else
      switch (inst->k & SECCOMP_RET_ACTION) {
#endif
#ifdef SECCOMP_RET_LOG
        case SECCOMP_RET_LOG:
          printf("LOG");
          break;
#endif
#ifdef SECCOMP_RET_USER_NOTIF
        case SECCOMP_RET_USER_NOTIF:
          printf("USER_NOTIFY");
          break;
#endif
        case SECCOMP_RET_KILL:
          printf("KILL");
          break;
        case SECCOMP_RET_ALLOW:
          printf("ALLOW");
          break;
        case SECCOMP_RET_TRAP:
          printf("TRAP %#" PRIx32, data);
          break;
        case SECCOMP_RET_ERRNO:
          printf("ERRNO %#" PRIx32, data);
          break;
        case SECCOMP_RET_TRACE:
          printf("TRACE %#" PRIx32, data);
          break;
        default:
          printf("return %#" PRIx32, inst->k);
      }
    } break;
    case BPF_RET | BPF_A:
      printf("return A");
      break;
    case BPF_ALU | BPF_ADD | BPF_K:
    case BPF_ALU | BPF_SUB | BPF_K:
    case BPF_ALU | BPF_MUL | BPF_K:
    case BPF_ALU | BPF_DIV | BPF_K:
    case BPF_ALU | BPF_AND | BPF_K:
    case BPF_ALU | BPF_OR | BPF_K:
    case BPF_ALU | BPF_XOR | BPF_K:
    case BPF_ALU | BPF_LSH | BPF_K:
    case BPF_ALU | BPF_RSH | BPF_K:
      printf("A := A %s %#" PRIx32, ops[op], inst->k);
      break;
    case BPF_ALU | BPF_ADD | BPF_X:
    case BPF_ALU | BPF_SUB | BPF_X:
    case BPF_ALU | BPF_MUL | BPF_X:
    case BPF_ALU | BPF_DIV | BPF_X:
    case BPF_ALU | BPF_AND | BPF_X:
    case BPF_ALU | BPF_OR | BPF_X:
    case BPF_ALU | BPF_XOR | BPF_X:
    case BPF_ALU | BPF_LSH | BPF_X:
    case BPF_ALU | BPF_RSH | BPF_X:
      printf("A := A %s X", ops[op]);
      break;
    case BPF_ALU | BPF_NEG:
      printf("A := -A");
      break;
    case BPF_JMP | BPF_JA:
      printf("jump to %" PRIu32, inst->k + pc + 1);
      break;
    case BPF_JMP | BPF_JEQ | BPF_K:
    case BPF_JMP | BPF_JGE | BPF_K:
    case BPF_JMP | BPF_JGT | BPF_K:
    case BPF_JMP | BPF_JSET | BPF_K:
      if (inst->jf == 0) {
        printf("if A %s %#" PRIx32 " goto %d", cmps[op], inst->k,
               inst->jt + pc + 1);
      } else if (inst->jt == 0 && op != BPF_JSET) {
        printf("if A %s %#" PRIx32 " goto %d", cmps_neg[op], inst->k,
               inst->jf + pc + 1);
      } else {
        printf("if A %s %#" PRIx32 " then %d else %d", cmps[op], inst->k,
               inst->jt + pc + 1, inst->jf + pc + 1);
      }

      break;
    case BPF_JMP | BPF_JEQ | BPF_X:
    case BPF_JMP | BPF_JGE | BPF_X:
    case BPF_JMP | BPF_JGT | BPF_X:
    case BPF_JMP | BPF_JSET | BPF_X:
      if (inst->jf == 0) {
        printf("if A %s X goto %d", cmps[op], inst->jt + pc + 1);
      } else if (inst->jt == 0 && op != BPF_JSET) {
        printf("if A %s X goto %d", cmps_neg[op], inst->jf + pc + 1);
      } else {
        printf("if A %s X then %d else %d", cmps[op], inst->jt + pc + 1,
               inst->jf + pc + 1);
      }
      break;
    default:
      printf("Invalid instruction %d", inst->code);
  }
  printf("\n");
}

void disasm(struct sock_fprog prog) {
  for (int i = 0; i < prog.len; ++i) {
    disasm_inst(&prog.filter[i], i);
  }
}

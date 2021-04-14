/*
Kafel - BPF interpreter
-----------------------------------------

Copyright 2021 Google LLC

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

#include "interpreter.h"

#include <inttypes.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static bool compute_alu(uint16_t op, uint32_t* a, uint32_t b) {
  switch (op) {
    case BPF_ADD:
      *a = *a + b;
      return true;
    case BPF_SUB:
      *a = *a - b;
      return true;
    case BPF_MUL:
      *a = *a * b;
      return true;
    case BPF_DIV:
      if (b == 0) {
        return false;
      }
      *a = *a / b;
      return true;
    case BPF_OR:
      *a = *a | b;
      return true;
    case BPF_AND:
      *a = *a & b;
      return true;
    case BPF_LSH:
      *a = *a << b;
      return true;
    case BPF_RSH:
      *a = *a >> b;
      return true;
    case BPF_NEG:
      *a = -*a;
      return true;
    default:
      abort();
  }
}

static bool evaluate_cmp(uint16_t cmp, uint32_t a, uint32_t b) {
  switch (cmp) {
    case BPF_JEQ:
      return a == b;
    case BPF_JGT:
      return a > b;
    case BPF_JGE:
      return a >= b;
    case BPF_JSET:
      return (a & b) != 0;
    default:
      abort();
  }
}

static bool interpret_instruction(interpreter_ctxt_t* ctxt,
                                  const struct sock_filter* inst,
                                  const struct seccomp_data* data) {
  uint32_t next_pc = ctxt->pc + 1;
  switch (inst->code) {
    case BPF_LD | BPF_W | BPF_ABS:
      if (inst->k & 3) {
        sprintf(ctxt->error_buf, "Misaligned read (%#" PRIx32 ")", inst->k);
        return false;
      }
      if (inst->k + sizeof(ctxt->accumulator) > sizeof(*data)) {
        sprintf(ctxt->error_buf, "Out of bounds read (%#" PRIx32 ")", inst->k);
        return false;
      }
      memcpy(&ctxt->accumulator, &((const char*)data)[inst->k],
             sizeof(ctxt->accumulator));
      break;
    case BPF_LD | BPF_W | BPF_LEN:
      ctxt->accumulator = sizeof(struct seccomp_data);
      break;
    case BPF_LDX | BPF_W | BPF_LEN:
      ctxt->x_reg = sizeof(struct seccomp_data);
      break;
    case BPF_LD | BPF_IMM:
      ctxt->accumulator = inst->k;
      break;
    case BPF_LDX | BPF_IMM:
      ctxt->x_reg = inst->k;
      break;
    case BPF_MISC | BPF_TAX:
      ctxt->x_reg = ctxt->accumulator;
      break;
    case BPF_MISC | BPF_TXA:
      ctxt->accumulator = ctxt->x_reg;
      break;
    case BPF_LD | BPF_MEM:
      if (inst->k >= sizeof(ctxt->mem) / sizeof(ctxt->mem[0])) {
        sprintf(ctxt->error_buf,
                "Out of bounds memory load (%" PRIu32 " >= 16)", inst->k);
        return false;
      }
      ctxt->accumulator = ctxt->mem[inst->k];
      break;
    case BPF_LDX | BPF_MEM:
      if (inst->k >= sizeof(ctxt->mem) / sizeof(ctxt->mem[0])) {
        sprintf(ctxt->error_buf,
                "Out of bounds memory load (%" PRIu32 " >= 16)", inst->k);
        return false;
      }
      ctxt->x_reg = ctxt->mem[inst->k];
      break;
    case BPF_ST:
      if (inst->k >= sizeof(ctxt->mem) / sizeof(ctxt->mem[0])) {
        sprintf(ctxt->error_buf,
                "Out of bounds memory store (%" PRIu32 " >= 16)", inst->k);
        return false;
      }
      ctxt->mem[inst->k] = ctxt->accumulator;
      break;
    case BPF_STX:
      if (inst->k >= sizeof(ctxt->mem) / sizeof(ctxt->mem[0])) {
        sprintf(ctxt->error_buf,
                "Out of bounds memory store (%" PRIu32 " >= 16)", inst->k);
        return false;
      }
      ctxt->mem[inst->k] = ctxt->x_reg;
      break;
    case BPF_RET | BPF_K:
      ctxt->has_result = true;
      ctxt->result = inst->k;
      return true;
    case BPF_RET | BPF_A:
      ctxt->has_result = true;
      ctxt->result = ctxt->accumulator;
      return true;
    case BPF_ALU | BPF_ADD | BPF_K:
    case BPF_ALU | BPF_SUB | BPF_K:
    case BPF_ALU | BPF_MUL | BPF_K:
    case BPF_ALU | BPF_DIV | BPF_K:
    case BPF_ALU | BPF_AND | BPF_K:
    case BPF_ALU | BPF_OR | BPF_K:
    case BPF_ALU | BPF_XOR | BPF_K:
    case BPF_ALU | BPF_LSH | BPF_K:
    case BPF_ALU | BPF_RSH | BPF_K:
    case BPF_ALU | BPF_ADD | BPF_X:
    case BPF_ALU | BPF_SUB | BPF_X:
    case BPF_ALU | BPF_MUL | BPF_X:
    case BPF_ALU | BPF_DIV | BPF_X:
    case BPF_ALU | BPF_AND | BPF_X:
    case BPF_ALU | BPF_OR | BPF_X:
    case BPF_ALU | BPF_XOR | BPF_X:
    case BPF_ALU | BPF_LSH | BPF_X:
    case BPF_ALU | BPF_RSH | BPF_X: {
      uint32_t val = BPF_SRC(inst->code) == BPF_K ? inst->k : ctxt->x_reg;
      if (!compute_alu(BPF_OP(inst->code), &ctxt->accumulator, val)) {
        sprintf(ctxt->error_buf, "Error while performing ALU op");
        return false;
      }
    } break;
    case BPF_ALU | BPF_NEG:
      ctxt->accumulator = -ctxt->accumulator;
      break;
    case BPF_JMP | BPF_JA:
      next_pc += inst->k;
      break;
    case BPF_JMP | BPF_JEQ | BPF_K:
    case BPF_JMP | BPF_JGE | BPF_K:
    case BPF_JMP | BPF_JGT | BPF_K:
    case BPF_JMP | BPF_JSET | BPF_K:
    case BPF_JMP | BPF_JEQ | BPF_X:
    case BPF_JMP | BPF_JGE | BPF_X:
    case BPF_JMP | BPF_JGT | BPF_X:
    case BPF_JMP | BPF_JSET | BPF_X: {
      uint32_t val = BPF_SRC(inst->code) == BPF_K ? inst->k : ctxt->x_reg;
      if (evaluate_cmp(BPF_OP(inst->code), ctxt->accumulator, val)) {
        next_pc += inst->jt;
      } else {
        next_pc += inst->jf;
      }
    } break;
    default:
      sprintf(ctxt->error_buf, "Invalid instruction %d", inst->code);
      return false;
  }
  if (next_pc <= ctxt->pc) {
    sprintf(ctxt->error_buf, "Out of bounds jump");
    return false;
  }
  ctxt->pc = next_pc;
  return true;
}

bool interpreter_run(interpreter_ctxt_t* ctxt, const struct sock_fprog* fprog,
                     const struct seccomp_data* data) {
  ctxt->pc = 0;
  ctxt->has_result = false;
  while (!ctxt->has_result) {
    if (ctxt->pc >= fprog->len) {
      sprintf(ctxt->error_buf, "Out of bounds jump (%d >= %d)", ctxt->pc,
              fprog->len);
      return false;
    }
    if (!interpret_instruction(ctxt, &fprog->filter[ctxt->pc], data)) {
      return false;
    }
  }
  return true;
}

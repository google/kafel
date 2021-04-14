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

#include <inttypes.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct {
  uint32_t accumulator;
  uint32_t x_reg;
  uint32_t mem[BPF_MEMWORDS];
  uint32_t pc;
  bool has_result;
  uint32_t result;
  char error_buf[256];
} interpreter_ctxt_t;

bool interpreter_run(interpreter_ctxt_t* ctxt, const struct sock_fprog* fprog,
                     const struct seccomp_data* data);

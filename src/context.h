/*
   Kafel - context
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

#ifndef KAFEL_CONTEXT_H
#define KAFEL_CONTEXT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "includes.h"
#include "parser_types.h"
#include "policy.h"
#include "syscall.h"

struct kafel_ctxt {
  struct includes_ctxt includes_ctxt;
  struct policieslist policies;
  struct policy* main_policy;
  int default_action;
  uint32_t target_arch;
  struct {
    enum {
      INPUT_NONE,
      INPUT_FILE,
      INPUT_STRING,
    } type;
    union {
      FILE* file;
      const char* string;
    };
  } input;
  bool lexical_error;
  struct {
    char* data;
    size_t len;
    size_t capacity;
  } errors;
  TAILQ_HEAD(, kafel_constant) constants;
};

void kafel_ctxt_clean(struct kafel_ctxt* ctxt);
void kafel_ctxt_reset(struct kafel_ctxt* ctxt);

void register_policy(struct kafel_ctxt* ctxt, struct policy* policy);
void register_const(struct kafel_ctxt* ctxt, const char* name, uint64_t value);
int lookup_const(struct kafel_ctxt* ctxt, const char* name, uint64_t* value);
struct policy* lookup_policy(struct kafel_ctxt* ctxt, const char* name);
void mark_all_policies_unused(struct kafel_ctxt* ctxt);

int append_error(struct kafel_ctxt* ctxt, const char* fmt, ...);

#endif /* KAFEL_CONTEXT_H */

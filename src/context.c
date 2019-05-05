/*
   Kafel - context
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

#include "context.h"

#include <linux/audit.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common.h"
#include "kafel.h"

KAFEL_API kafel_ctxt_t kafel_ctxt_create(void) {
  struct kafel_ctxt* ctxt = calloc(1, sizeof(*ctxt));
  includes_ctxt_init(&ctxt->includes_ctxt);
  TAILQ_INIT(&ctxt->policies);
  TAILQ_INIT(&ctxt->constants);
  ctxt->target_arch = KAFEL_DEFAULT_TARGET_ARCH;
  return ctxt;
}

static void clean_policies(kafel_ctxt_t ctxt) {
  while (!TAILQ_EMPTY(&ctxt->policies)) {
    struct policy* policy = TAILQ_FIRST(&ctxt->policies);
    TAILQ_REMOVE(&ctxt->policies, policy, policies);
    policy_destroy(&policy);
  }
}

static void clean_constants(kafel_ctxt_t ctxt) {
  while (!TAILQ_EMPTY(&ctxt->constants)) {
    struct kafel_constant* constant = TAILQ_FIRST(&ctxt->constants);
    TAILQ_REMOVE(&ctxt->constants, constant, constants);
    free(constant->name);
    free(constant);
  }
}

void kafel_ctxt_reset(kafel_ctxt_t ctxt) {
  ASSERT(ctxt != NULL);

  clean_args(ctxt);
  clean_policies(ctxt);
  clean_constants(ctxt);
  free(ctxt->errors.data);
  ctxt->errors.capacity = 0;
  ctxt->errors.len = 0;
  ctxt->errors.data = NULL;
  if (ctxt->main_policy) {
    policy_destroy(&ctxt->main_policy);
  }
  ctxt->default_action = 0;
  ctxt->lexical_error = false;
}

void kafel_ctxt_clean(kafel_ctxt_t ctxt) {
  ASSERT(ctxt != NULL);

  kafel_ctxt_reset(ctxt);
  includes_ctxt_clean(&ctxt->includes_ctxt);
}

KAFEL_API void kafel_ctxt_destroy(kafel_ctxt_t* ctxt) {
  ASSERT(ctxt != NULL);
  ASSERT(*ctxt != NULL);

  kafel_ctxt_clean(*ctxt);
  free(*ctxt);
  *ctxt = NULL;
}

KAFEL_API const char* kafel_error_msg(const kafel_ctxt_t ctxt) {
  ASSERT(ctxt != NULL);

  return ctxt->errors.data;
}

void register_policy(struct kafel_ctxt* ctxt, struct policy* policy) {
  TAILQ_INSERT_TAIL(&ctxt->policies, policy, policies);
}

void clean_args(struct kafel_ctxt* ctxt) {
  for (int i = 0; i < ctxt->syscall.args_num; ++i) {
    free((char*)ctxt->syscall.args[i].name);
    ctxt->syscall.args[i].name = NULL;
  }
  ctxt->syscall.args_num = 0;
}

void register_first_arg(struct kafel_ctxt* ctxt, const char* name, int size) {
  clean_args(ctxt);
  register_arg(ctxt, name, size);
}

int register_arg(struct kafel_ctxt* ctxt, const char* name, int size) {
  if (ctxt->syscall.args_num >= SYSCALL_MAX_ARGS) {
    return -1;
  }
  ctxt->syscall.args[ctxt->syscall.args_num++] =
      ((struct syscall_arg){.name = strdup(name), .size = size});
  return 0;
}

void register_ftrace_args(struct kafel_ctxt* ctxt,
                          const struct syscall_descriptor* desc) {
  clean_args(ctxt);
  for (int i = 0; i < SYSCALL_MAX_ARGS; ++i) {
    if (desc->args[i].name != NULL) {
      register_arg(ctxt, desc->args[i].name, desc->args[i].size);
    }
  }
}

int lookup_var(struct kafel_ctxt* ctxt, const char* name) {
  for (int i = 0; i < ctxt->syscall.args_num; ++i) {
    if (strcmp(ctxt->syscall.args[i].name, name) == 0) {
      return i;
    }
  }
  return -1;
}

struct policy* lookup_policy(struct kafel_ctxt* ctxt, const char* name) {
  struct policy* policy;
  TAILQ_FOREACH(policy, &ctxt->policies, policies) {
    if (strcmp(policy->name, name) == 0) {
      return policy;
    }
  }
  return NULL;
}

static int grow_errors_buffer(struct kafel_ctxt* ctxt, size_t min_growth) {
  size_t oldcapacity = ctxt->errors.capacity;
  size_t mincapacity = ctxt->errors.len + min_growth;
  if (min_growth > 0 && mincapacity <= ctxt->errors.len) {
    return -1;  // overflow
  }
  if (mincapacity <= oldcapacity) {
    return 0;
  }
  size_t newcapacity = oldcapacity * 2;
  if (newcapacity <= oldcapacity || newcapacity < mincapacity) {
    newcapacity = mincapacity;
  }
  char* newbuf = realloc(ctxt->errors.data, newcapacity);
  if (newbuf == NULL) {
    return -1;
  }
  ctxt->errors.data = newbuf;
  ctxt->errors.capacity = newcapacity;
  return 0;
}

int append_error(struct kafel_ctxt* ctxt, const char* fmt, ...) {
  ASSERT(ctxt != NULL);
  ASSERT(fmt != NULL);

  va_list ap;

  if (ctxt->errors.data == NULL) {
    ASSERT(ctxt->errors.len == 0);
    ASSERT(ctxt->errors.capacity == 0);

    size_t newcapacity = 128;
    ctxt->errors.data = malloc(newcapacity);
    if (ctxt->errors.data == NULL) {
      return -1;
    }
    ctxt->errors.capacity = newcapacity;
  }

  for (;;) {
    size_t space = ctxt->errors.capacity - ctxt->errors.len;

    va_start(ap, fmt);
    int n = vsnprintf(&ctxt->errors.data[ctxt->errors.len], space, fmt, ap);
    va_end(ap);

    if (n < 0) {
      ctxt->errors.data[ctxt->errors.len] = '\0';
      return -1;
    }
    if (((size_t)n) < space) {
      ctxt->errors.len += n;
      if (grow_errors_buffer(ctxt, 1) == 0) {
        ctxt->errors.data[ctxt->errors.len++] = '\n';
      }
      ctxt->errors.data[ctxt->errors.len] = '\0';
      return 0;
    }
    if (grow_errors_buffer(ctxt, n) != 0) {
      return -1;
    }
  }
  return -1;
}

void register_const(struct kafel_ctxt* ctxt, const char* name, uint64_t value) {
  struct kafel_constant* constant = calloc(1, sizeof(*constant));
  constant->name = strdup(name);
  constant->value = value;
  TAILQ_INSERT_TAIL(&ctxt->constants, constant, constants);
}

int lookup_const(struct kafel_ctxt* ctxt, const char* name, uint64_t* value) {
  struct kafel_constant* constant;
  TAILQ_FOREACH(constant, &ctxt->constants, constants) {
    if (strcmp(name, constant->name) == 0) {
      if (value != NULL) {
        *value = constant->value;
      }
      return 0;
    }
  }
  return -1;
}

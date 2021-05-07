/*
   Kafel - tests of broken (non compiling) policies
   -----------------------------------------

   Copyright 2017 Google LLC

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
#include <limits.h>
#include <stdio.h>
#include <string.h>

#include "runner/harness.h"
#include "runner/runner.h"

TEST_CASE(broken_syscall_no_out_of_range) {
  TEST_COMPILE_ERROR(
      "POLICY broken {\n"
      "  ALLOW { SYSCALL[0x12345678901234567] }\n"
      "} USE broken DEFAULT KILL");
}

TEST_CASE(broken_errno_out_of_range) {
  char policy[256];
  const char* policy_template =
      "POLICY broken {\n"
      "  %s(65536) { write }\n"
      "} USE broken DEFAULT KILL";
  const char* actions[] = {"ERRNO", "TRAP", "TRACE"};
  for (size_t i = 0; i < sizeof(actions) / sizeof(actions); ++i) {
    sprintf(policy, policy_template, actions[i]);
    TEST_COMPILE_ERROR(policy);
  }
}

TEST_CASE(broken_redefined_arg) {
  TEST_COMPILE_ERROR(
      "POLICY broken {\n"
      "  ALLOW {\n"
      "    write(myfd, myfd, mysize) { myfd == 1 || mysize == 1}\n"
      "  }\n"
      "} USE broken DEFAULT KILL");
}

TEST_CASE(broken_redefined_policy) {
  TEST_COMPILE_ERROR(
      "POLICY empty {}\n"
      "POLICY empty {}\n"
      "USE empty DEFAULT KILL");
}

TEST_CASE(broken_restricted_keywords_as_identifiers) {
  char policy[256];
  const char* keywords[] = {
      "SYSCALL", "ALLOW", "LOG", "ERRNO",  "KILL",    "DENY",
      "TRAP",    "TRACE", "USE", "POLICY", "DEFAULT", "define",
  };
  const char* templates[] = {
      "POLICY empty{} USE %s DEFAULT KILL",
      "POLICY %s {} POLICY empty{} USE empty DEFAULT KILL",
      "POLICY basic { ALLOW { %s } } USE basic DEFAULT KILL",
  };
  for (size_t i = 0; i < sizeof(keywords) / sizeof(keywords[0]); ++i) {
    for (size_t j = 0; j < sizeof(templates) / sizeof(templates[0]); ++j) {
      sprintf(policy, templates[j], keywords[i]);
      TEST_COMPILE_ERROR(policy);
    }
  }
}

TEST_CASE(broken_too_many_syscall_args) {
  TEST_COMPILE_ERROR(
      "POLICY broken {\n"
      "  ALLOW {\n"
      "    write(myfd, mybuf, mysize, more, and_more,\n"
      "      and_even_more, and_thats_too_much)\n"
      "  }\n"
      "} USE broken DEFAULT KILL");
}

TEST_CASE(broken_undefined_argument) {
  TEST_COMPILE_ERROR(
      "POLICY broken {\n"
      "  ALLOW {\n"
      "    write(myfd, mybuf, mysize) { undef == 1 || myfd == 2 }\n"
      "  }\n"
      "} USE broken DEFAULT KILL");
}

TEST_CASE(broken_undefined_policy) {
  TEST_COMPILE_ERROR("USE undef DEFAULT KILL");
  TEST_COMPILE_ERROR("POLICY empty {} USE undef DEFAULT KILL");
  TEST_COMPILE_ERROR("POLICY broken { USE undef } USE broken DEFAULT KILL");
}

TEST_CASE(broken_undefined_syscall) {
  TEST_COMPILE_ERROR(
      "POLICY broken {\n"
      "  ALLOW { this_is_a_syscall_that_does_not_exist }\n"
      "}\n"
      "USE broken DEFAULT KILL");
}

TEST_CASE(broken_undefined_syscall_main_policy) {
  TEST_COMPILE_ERROR("ALLOW { this_is_a_syscall_that_does_not_exist }\n");
}

TEST_CASE(broken_unterminated_comment) {
  TEST_COMPILE_ERROR("POLICY empty {} USE empty DEFAULT KILL /* oops ");
}

TEST_CASE(broken_stack_overflow) {
  TEST_COMPILE_ERROR(
      "POLICY stackoverflow {\n"
      "  ALLOW {\n"
      "    open {\n"
      "      flags & mode & 0x1337 & \n"
      "      flags & mode & 0x1337 & \n"
      "      flags & mode & 0x1337 & \n"
      "      flags & mode & 0x1337 & \n"
      "      flags & mode & 0x1337 & \n"
      "      flags & mode & 0x1337 & \n"
      "      flags & mode & 0x1337 & \n"
      "      flags & mode & 0x1337 & \n"
      "      flags & mode & 0x1337 & \n"
      "      flags & mode & 0x1337 == 0x1\n"
      "    }\n"
      "  }\n"
      "} USE stackoverflow DEFAULT KILL");
}

TEST_CASE(broken_const_redefintion) {
  TEST_COMPILE_ERROR(
      "#define myconst 1\n"
      "#define myconst 2\n"
      "POLICY empty {}\n"
      "USE empty DEFAULT KILL");
}

#define MAX_EXPR_DEPTH 200

TEST_CASE(broken_max_expr_depth) {
  char policy_buf[256 + MAX_EXPR_DEPTH * 2] = "ALLOW { read { fd == 1";
  char* p = &policy_buf[strlen(policy_buf)];
  for (int i = 1; i <= MAX_EXPR_DEPTH; ++i) {
    *p++ = '&';
    *p++ = '1';
  }
  *p++ = '}';
  *p++ = '}';
  *p++ = '\0';
  TEST_COMPILE_ERROR(policy_buf);
}

TEST_CASE(broken_max_instructions) {
  char policy_buf[256 + USHRT_MAX * 32] = "ALLOW { exit";
  char* p = &policy_buf[strlen(policy_buf)];
  for (uint32_t i = 0; i < USHRT_MAX; ++i) {
    // Allow every second syscall
    // Consecutive syscalls would get merged in 1 block
    p += sprintf(p, ", SYSCALL[%" PRId32 "]", i * 2);
  }
  *p++ = '}';
  *p++ = '\0';
  TEST_COMPILE_ERROR(policy_buf);
}

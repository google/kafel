/*
   Kafel - #include tests
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

#include <linux/unistd.h>
#include <unistd.h>

#include "runner/harness.h"
#include "runner/runner.h"

static int empty(void* ctx) {
  ((void)ctx);
  return 0;
}

TEST_CASE(simple_include) {
  TEST_POLICY("#include \"empty.policy\"; USE empty DEFAULT KILL");
  TEST_POLICY_BLOCKS(empty, NULL);
  TEST_POLICY("#include \"basic.policy\"; USE allow_exit DEFAULT KILL");
  TEST_POLICY_ALLOWS(empty, NULL);
  TEST_POLICY_BLOCKS_SYSCALL(SYSCALL_SPEC0(__NR_write));
  // include terminated with a newline
  TEST_POLICY("#include \"basic.policy\"\nUSE allow_exit DEFAULT KILL");
  TEST_POLICY_ALLOWS(empty, NULL);
  TEST_POLICY_BLOCKS_SYSCALL(SYSCALL_SPEC0(__NR_write));
}

TEST_CASE(multiple_includes) {
  TEST_POLICY(
      "#include \"empty.policy\" \"basic.policy\";"
      "USE allow_exit DEFAULT KILL");
  TEST_POLICY_ALLOWS(empty, NULL);
  TEST_POLICY_BLOCKS_SYSCALL(SYSCALL_SPEC0(__NR_write));
}

TEST_CASE(chained_includes) {
  TEST_POLICY(
      "#include \"chain.policy\"\n"
      "POLICY composite {\n"
      "  USE empty,\n"
      "  USE allow_exit,\n"
      "  USE allow_stdio\n"
      "}\n"
      "USE composite DEFAULT KILL");
  TEST_POLICY_ALLOWS(empty, NULL);
  TEST_POLICY_ALLOWS_SYSCALL(SYSCALL_SPEC3(__NR_read, STDIN_FILENO, 0, 0),
                             SYSCALL_EXECUTED_SPEC(0, 0));
  TEST_POLICY_BLOCKS_SYSCALL(SYSCALL_SPEC0(__NR_ptrace));
}

TEST_CASE(nosuch_include) {
  TEST_COMPILE_ERROR("#include \"nosuch_policy.policy\";");
}

TEST_CASE(wrong_includes) {
  // no whitespace after include keyword
  TEST_COMPILE_ERROR("#include\"empty.policy\"; USE empty DEFAULT KILL");
  // no whitespace between filenames
  TEST_COMPILE_ERROR(
      "#include\"empty.policy\"\"basic.policy\"\n"
      "USE empty DEFAULT KILL");
  // unterminated filename string
  TEST_COMPILE_ERROR("#include \"empty_policy");
  // unterminated include statement
  TEST_COMPILE_ERROR("#include \"empty.policy\"");
  // unquoted filename string
  TEST_COMPILE_ERROR("#include empty.policy; USE empty DEFAULT KILL");
}

TEST_CASE(infinite_recursion_includes) {
  TEST_COMPILE_ERROR(
      "#include \"self_recursive.policy\";"
      "POLICY empty {} USE empty DEFAULT KILL");
  TEST_COMPILE_ERROR(
      "#include \"short_loop.policy\";"
      "POLICY empty {} USE empty DEFAULT KILL");
  TEST_COMPILE_ERROR(
      "#include \"includes_short_loop.policy\";"
      "POLICY empty {} USE empty DEFAULT KILL");
}

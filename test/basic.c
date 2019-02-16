/*
   Kafel - basic policy tests
   -----------------------------------------

   Copyright 2018 Google Inc. All Rights Reserved.

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
#include <fcntl.h>
#include <unistd.h>

#include "runner/harness.h"
#include "runner/runner.h"

static int empty(void* ctx) {
  ((void)ctx);
  return 0;
}

TEST_CASE(default_kill) {
  TEST_POLICY("POLICY a {} USE a DEFAULT KILL");
  TEST_POLICY_BLOCKS(empty, NULL);
  TEST_POLICY(
      "POLICY a {\n"
      "  ALLOW { exit }\n"
      "} USE a DEFAULT KILL");
  TEST_POLICY_ALLOWS(empty, NULL);
  TEST_POLICY_BLOCKS_SYSCALL(SYSCALL_SPEC0(__NR_write));
}

TEST_CASE(actions) {
  TEST_POLICY(
      "POLICY a {\n"
      "  ALLOW { exit, read }\n"
      "} USE a DEFAULT KILL");
  TEST_POLICY_ALLOWS_SYSCALL(SYSCALL_SPEC3(__NR_read, STDIN_FILENO, 0, 0),
                             SYSCALL_RESULT_SPEC(0));
  TEST_POLICY_BLOCKS_SYSCALL(SYSCALL_SPEC3(__NR_write, STDIN_FILENO, 0, 0));
  TEST_POLICY(
      "POLICY a {\n"
      "  ALLOW { exit },\n"
      "  KILL { read }\n"
      "} USE a DEFAULT KILL");
  TEST_POLICY_BLOCKS_SYSCALL(SYSCALL_SPEC3(__NR_read, STDIN_FILENO, 0, 0));
  TEST_POLICY(
      "POLICY a {\n"
      "  ALLOW { exit },\n"
      "  ERRNO(1) { read }\n"
      "} USE a DEFAULT KILL");
  TEST_POLICY_ALLOWS_SYSCALL(SYSCALL_SPEC3(__NR_read, STDIN_FILENO, 0, 0),
                             SYSCALL_ERRNO_SPEC(1));
  // TODO trace, trap
}

TEST_CASE(custom_syscalls) {
  TEST_POLICY(
      "POLICY a {\n"
      "  ALLOW { exit },\n"
      "  ERRNO(1) { SYSCALL[-1] }\n"
      "} USE a DEFAULT KILL");
  TEST_POLICY_ALLOWS_SYSCALL(SYSCALL_SPEC0(-1), SYSCALL_ERRNO_SPEC(1));
  TEST_POLICY_BLOCKS_SYSCALL(SYSCALL_SPEC0(1));
  TEST_POLICY(
      "#define SYS_CUSTOM -1\n"
      "POLICY a {\n"
      "  ALLOW { exit },\n"
      "  ERRNO(1) { SYS_CUSTOM }\n"
      "} USE a DEFAULT KILL");
  TEST_POLICY_ALLOWS_SYSCALL(SYSCALL_SPEC0(-1), SYSCALL_ERRNO_SPEC(1));
  TEST_POLICY_BLOCKS_SYSCALL(SYSCALL_SPEC0(1));
}

TEST_CASE(rules_order) {
  TEST_POLICY(
      "POLICY a {\n"
      "  ALLOW { exit, read },\n"
      "  DENY { read, write }\n"
      "} USE a DEFAULT KILL");
  TEST_POLICY_ALLOWS_SYSCALL(SYSCALL_SPEC3(__NR_read, STDIN_FILENO, 0, 0),
                             SYSCALL_RESULT_SPEC(0));
  TEST_POLICY_BLOCKS_SYSCALL(SYSCALL_SPEC3(__NR_write, STDIN_FILENO, 0, 0));
  TEST_POLICY(
      "POLICY a {\n"
      "  ALLOW { exit, read { fd == 0 && count == 0 } },\n"
      "  ERRNO(1) { read { count == 0 } }\n"
      "} USE a DEFAULT KILL");
  TEST_POLICY_ALLOWS_SYSCALL(SYSCALL_SPEC3(__NR_read, 0, 0, 0),
                             SYSCALL_RESULT_SPEC(0));
  TEST_POLICY_ALLOWS_SYSCALL(SYSCALL_SPEC3(__NR_read, 5, 0, 0),
                             SYSCALL_ERRNO_SPEC(1));
  TEST_POLICY_BLOCKS_SYSCALL(SYSCALL_SPEC3(__NR_read, 5, 0, 1));
}

TEST_CASE(bitwise_operations) {
  TEST_POLICY(
      "POLICY a { \n"
      "  ALLOW { exit, read { count | 8 | fd == 8 } }\n"
      "} USE a DEFAULT KILL");
  TEST_POLICY_ALLOWS_SYSCALL(SYSCALL_SPEC3(__NR_read, 0, 0, 0),
                             SYSCALL_RESULT_SPEC(0));
  TEST_POLICY_BLOCKS_SYSCALL(SYSCALL_SPEC3(__NR_read, 5, 0, 0));

  // Test literals
  TEST_POLICY(
      "POLICY a { \n"
      "  ALLOW { exit },\n"
      "  ERRNO(1) { read { count == 1|2|4 } }\n"
      "} USE a DEFAULT KILL");
  TEST_POLICY_ALLOWS_SYSCALL(SYSCALL_SPEC3(__NR_read, 5, 0, 7),
                             SYSCALL_ERRNO_SPEC(1));
  TEST_POLICY_BLOCKS_SYSCALL(SYSCALL_SPEC3(__NR_read, 5, 0, 0));

  // Order of operations
  char dummy = 'a';
  TEST_POLICY(
      "POLICY a {\n"
      "  ALLOW { exit, read { buf | buf & count == buf } }\n"
      "} USE a DEFAULT KILL");
  TEST_POLICY_ALLOWS_SYSCALL(SYSCALL_SPEC3(__NR_read, STDIN_FILENO, (long) &dummy, 0),
                             SYSCALL_RESULT_SPEC(0));

  // Test stack
  TEST_POLICY(
      "POLICY a {\n"
      "  ALLOW {\n"
      "    exit,\n"
      "    read {\n"
      "      (count | 2) & (fd | 3) == 2\n"
      "    }\n"
      "  }\n"
      "} USE a DEFAULT KILL");
  TEST_POLICY_ALLOWS_SYSCALL(SYSCALL_SPEC3(__NR_read, 0, 0, 0),
                             SYSCALL_RESULT_SPEC(0));
  TEST_POLICY_BLOCKS_SYSCALL(SYSCALL_SPEC3(__NR_read, 0, 0, 1));
}

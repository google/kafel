/*
   Kafel - basic policy tests
   -----------------------------------------

   Copyright 2018 Google LLC

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

#include <errno.h>
#include <fcntl.h>
#include <linux/audit.h>
#include <linux/unistd.h>
#include <stdlib.h>
#include <unistd.h>

#include <kafel.h>

#include "runner/harness.h"
#include "runner/interpreter.h"
#include "runner/runner.h"

static int empty(void* ctx, char* err) {
  ((void)ctx);
  ((void)err);
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
                             SYSCALL_EXECUTED_SPEC(0, 0));
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
  TEST_POLICY_BLOCKS_SYSCALL(SYSCALL_SPEC0(4));
  TEST_POLICY(
      "#define SYS_CUSTOM -1\n"
      "POLICY a {\n"
      "  ALLOW { exit },\n"
      "  ERRNO(1) { SYS_CUSTOM }\n"
      "} USE a DEFAULT KILL");
  TEST_POLICY_ALLOWS_SYSCALL(SYSCALL_SPEC0(-1), SYSCALL_ERRNO_SPEC(1));
  TEST_POLICY_BLOCKS_SYSCALL(SYSCALL_SPEC0(4));
}

TEST_CASE(custom_args) {
  TEST_POLICY("ALLOW { read(f, buff, c) { f == 0 }, exit }");
  TEST_POLICY_ALLOWS_SYSCALL(SYSCALL_SPEC3(__NR_read, 0, 0, 0),
                             SYSCALL_EXECUTED_SPEC(0, 0));
  TEST_POLICY_BLOCKS_SYSCALL(SYSCALL_SPEC3(__NR_read, 4, 0, 0));
  TEST_POLICY(
      "ALLOW { exit }\n"
      "ERRNO(1) { SYSCALL[-1](a, b, c) { a == 1 } }\n"
      "ERRNO(2) { SYSCALL[-1] }");
  TEST_POLICY_ALLOWS_SYSCALL(SYSCALL_SPEC3(-1, 1, 2, 3), SYSCALL_ERRNO_SPEC(1));
  TEST_POLICY_ALLOWS_SYSCALL(SYSCALL_SPEC3(-1, 2, 3, 4), SYSCALL_ERRNO_SPEC(2));
}

TEST_CASE(arch_guard_basic) {
  TEST_POLICY(
      "DEFAULT KILL\n"
      "ALLOW { exit, read ON x86_64 }\n");
}

TEST_CASE(arch_guard_unknown_arch) {
  TEST_COMPILE_ERROR(
      "DEFAULT KILL\n"
      "ALLOW { exit, read ON madeup }\n");
}

TEST_CASE(arch_guard_duplicate_arch) {
  TEST_COMPILE_ERROR(
      "DEFAULT KILL\n"
      "ALLOW { exit, read ON { x86_64, x86_64 } }\n");
}

#if defined(AUDIT_ARCH_ARM) && defined(AUDIT_ARCH_X86_64)
TEST_CASE(arch_guard_multi_arch_compile) {
  const char* policy =
      "DEFAULT KILL\n"
      "ALLOW { exit, arm_fadvise64_64 ON arm, io_uring_setup ON x86_64 }\n";
  kafel_ctxt_t ctxt = kafel_ctxt_create();
  kafel_set_input_string(ctxt, policy);
  kafel_set_target_archs(ctxt,
                         KAFEL_TARGET_ARCH_ARM | KAFEL_TARGET_ARCH_X86_64);
  struct sock_fprog prog;
  int rv = kafel_compile(ctxt, &prog);
  if (rv != 0) {
    test_fail_with_message("Arch-guarded policy failed: %s",
                           kafel_error_msg(ctxt));
    test_failed(__LINE__, __FILE__);
    kafel_ctxt_destroy(&ctxt);
    return;
  }
  free(prog.filter);
  kafel_ctxt_destroy(&ctxt);
}
#endif

TEST_CASE(rules_order) {
  TEST_POLICY(
      "POLICY a {\n"
      "  ALLOW { exit, read },\n"
      "  DENY { read, write }\n"
      "} USE a DEFAULT KILL");
  TEST_POLICY_ALLOWS_SYSCALL(SYSCALL_SPEC3(__NR_read, STDIN_FILENO, 0, 0),
                             SYSCALL_EXECUTED_SPEC(0, 0));
  TEST_POLICY_BLOCKS_SYSCALL(SYSCALL_SPEC3(__NR_write, STDIN_FILENO, 0, 0));
  TEST_POLICY(
      "POLICY a {\n"
      "  ALLOW { exit, read { fd == 0 && count == 0 } },\n"
      "  ERRNO(1) { read { count == 0 } }\n"
      "} USE a DEFAULT KILL");
  TEST_POLICY_ALLOWS_SYSCALL(SYSCALL_SPEC3(__NR_read, 0, 0, 0),
                             SYSCALL_EXECUTED_SPEC(0, 0));
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
                             SYSCALL_EXECUTED_SPEC(0, 0));
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
  TEST_POLICY_ALLOWS_SYSCALL(
      SYSCALL_SPEC3(__NR_read, STDIN_FILENO, (long)&dummy, 0),
      SYSCALL_EXECUTED_SPEC(0, 0));

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
                             SYSCALL_EXECUTED_SPEC(0, 0));
  TEST_POLICY_BLOCKS_SYSCALL(SYSCALL_SPEC3(__NR_read, 0, 0, 1));
}

#ifndef __i386__
TEST_CASE(32bit_args) {
  // fcntl should be defined for all archs
  // and fd should be 32-bit argument
  TEST_POLICY("ALLOW { fcntl { fd == 0x1234 }, exit } DEFAULT KILL");
  TEST_POLICY_ALLOWS_SYSCALL(SYSCALL_SPEC3(__NR_fcntl, 0x000001234, F_GETFD, 0),
                             SYSCALL_EXECUTED_SPEC(-1, EBADF));
  TEST_POLICY_ALLOWS_SYSCALL(SYSCALL_SPEC3(__NR_fcntl, 0x100001234, F_GETFD, 0),
                             SYSCALL_EXECUTED_SPEC(-1, EBADF));
  TEST_POLICY_BLOCKS_SYSCALL(
      SYSCALL_SPEC3(__NR_fcntl, 0x000001235, F_GETFD, 0));
  TEST_POLICY_BLOCKS_SYSCALL(
      SYSCALL_SPEC3(__NR_fcntl, 0x100001235, F_GETFD, 0));
  // Even though fd is 32-bit a compare with 64-bit const should check whole arg
  TEST_POLICY("ALLOW { fcntl { fd == 0x100001234 }, exit } DEFAULT KILL");
  TEST_POLICY_BLOCKS_SYSCALL(
      SYSCALL_SPEC3(__NR_fcntl, 0x000001234, F_GETFD, 0));
  TEST_POLICY_ALLOWS_SYSCALL(SYSCALL_SPEC3(__NR_fcntl, 0x100001234, F_GETFD, 0),
                             SYSCALL_EXECUTED_SPEC(-1, EBADF));
  TEST_POLICY_BLOCKS_SYSCALL(
      SYSCALL_SPEC3(__NR_fcntl, 0x000001235, F_GETFD, 0));
  TEST_POLICY_BLOCKS_SYSCALL(
      SYSCALL_SPEC3(__NR_fcntl, 0x100001235, F_GETFD, 0));
}
// A negative constant is read as a 64-bit number (`-1' is 0xffffffffffffffff).
// The kernel only looks at the low half of the register for a 32-bit argument
// and callers may zero-extend it, so the rule has to match either way.
TEST_CASE(32bit_args_negative_const) {
  TEST_POLICY(
      "ERRNO(1) { fcntl { fd == -1 } }\n"
      "ALLOW { fcntl, exit } DEFAULT KILL");
  TEST_POLICY_ALLOWS_SYSCALL(
      SYSCALL_SPEC3(__NR_fcntl, 0xffffffffffffffff, F_GETFD, 0),
      SYSCALL_ERRNO_SPEC(1));
  TEST_POLICY_ALLOWS_SYSCALL(
      SYSCALL_SPEC3(__NR_fcntl, 0x00000000ffffffff, F_GETFD, 0),
      SYSCALL_ERRNO_SPEC(1));
  TEST_POLICY_ALLOWS_SYSCALL(
      SYSCALL_SPEC3(__NR_fcntl, 0x12345678ffffffff, F_GETFD, 0),
      SYSCALL_ERRNO_SPEC(1));
  TEST_POLICY_ALLOWS_SYSCALL(
      SYSCALL_SPEC3(__NR_fcntl, 0x00000000fffffffe, F_GETFD, 0),
      SYSCALL_EXECUTED_SPEC(-1, EBADF));
  TEST_POLICY(
      "ERRNO(1) { fcntl { fd != -100 } }\n"
      "ALLOW { fcntl, exit } DEFAULT KILL");
  TEST_POLICY_ALLOWS_SYSCALL(
      SYSCALL_SPEC3(__NR_fcntl, 0x00000000ffffff9c, F_GETFD, 0),
      SYSCALL_EXECUTED_SPEC(-1, EBADF));
  TEST_POLICY_ALLOWS_SYSCALL(
      SYSCALL_SPEC3(__NR_fcntl, 0xffffffffffffff9c, F_GETFD, 0),
      SYSCALL_EXECUTED_SPEC(-1, EBADF));
  TEST_POLICY_ALLOWS_SYSCALL(SYSCALL_SPEC3(__NR_fcntl, 0x1234, F_GETFD, 0),
                             SYSCALL_ERRNO_SPEC(1));
  // A constant that is neither a 32-bit value nor a negative 32-bit value
  // still makes the comparison look at the whole argument.
  TEST_POLICY(
      "ERRNO(1) { fcntl { fd == 0xffffffff7fffffff } }\n"
      "ALLOW { fcntl, exit } DEFAULT KILL");
  TEST_POLICY_ALLOWS_SYSCALL(
      SYSCALL_SPEC3(__NR_fcntl, 0xffffffff7fffffff, F_GETFD, 0),
      SYSCALL_ERRNO_SPEC(1));
  TEST_POLICY_ALLOWS_SYSCALL(
      SYSCALL_SPEC3(__NR_fcntl, 0x000000007fffffff, F_GETFD, 0),
      SYSCALL_EXECUTED_SPEC(-1, EBADF));
}
#endif

// A rule that can never match must not leave instructions behind. They used to
// end up at the very beginning of the filter, in front of the architecture and
// syscall number checks.
TEST_CASE(never_matching_rules) {
  // High words differ, known only after the low word compare was emitted.
  TEST_POLICY(
      "ALLOW { SYSCALL[-1](a) { (a & 1) == 0x100000001 } } DEFAULT KILL");
  TEST_POLICY_BLOCKS_SYSCALL(SYSCALL_SPEC3(__NR_fcntl, 1, F_GETFD, 0));
  TEST_POLICY_BLOCKS_SYSCALL(SYSCALL_SPEC1(-1, 1));
  // Left side of && is false, known only after the right side was emitted.
  TEST_POLICY(
      "ALLOW { SYSCALL[-1](a, b) { (a & 0) > 0 && b == 1 } } DEFAULT KILL");
  TEST_POLICY_BLOCKS_SYSCALL(SYSCALL_SPEC3(__NR_fcntl, 0, 1, 0));
  TEST_POLICY_BLOCKS_SYSCALL(SYSCALL_SPEC2(-1, 0, 1));
  // First rule always matches, known only after the second one was emitted.
  TEST_POLICY(
      "KILL { SYSCALL[-1](a) { (a & 1) != 0x100000001 } }\n"
      "ALLOW { SYSCALL[-1](a) { a == 1 } } DEFAULT KILL");
  TEST_POLICY_BLOCKS_SYSCALL(SYSCALL_SPEC3(__NR_fcntl, 1, F_GETFD, 0));
  TEST_POLICY_BLOCKS_SYSCALL(SYSCALL_SPEC1(-1, 1));
  // The rest of such a policy keeps working.
  TEST_POLICY(
      "ERRNO(1) { SYSCALL[-1](a) { (a & 1) == 0x100000001 } }\n"
      "ERRNO(2) { SYSCALL[-1](a) { a == 1 } }\n"
      "ALLOW { exit } DEFAULT KILL");
  TEST_POLICY_ALLOWS_SYSCALL(SYSCALL_SPEC1(-1, 1), SYSCALL_ERRNO_SPEC(2));
  TEST_POLICY_BLOCKS_SYSCALL(SYSCALL_SPEC1(-1, 3));
}

// Same as above for one of several architectures: the leftover used to sit
// right after the architecture load, in place of the dispatch.
TEST_CASE(never_matching_rules_multi_arch) {
  const char* policy =
      "ALLOW {\n"
      "  getpid ON x86,\n"
      "  write ON x86_64 { (fd & 0xff) == 0x100000001 }\n"
      "} DEFAULT KILL";
  kafel_ctxt_t ctxt = kafel_ctxt_create();
  kafel_set_input_string(ctxt, policy);
  kafel_set_target_archs(ctxt,
                         KAFEL_TARGET_ARCH_X86 | KAFEL_TARGET_ARCH_X86_64);
  struct sock_fprog prog;
  if (kafel_compile(ctxt, &prog) != 0) {
    test_fail_with_message("Compilation failure: %s", kafel_error_msg(ctxt));
    test_failed(__LINE__, __FILE__);
    kafel_ctxt_destroy(&ctxt);
    return;
  }
  kafel_ctxt_destroy(&ctxt);
  const struct {
    struct seccomp_data data;
    uint32_t expected;
  } cases[] = {
      // execve(1, ...) on x86_64
      {{59, AUDIT_ARCH_X86_64, 0, {1}}, SECCOMP_RET_KILL},
      // write(1, ...) on x86_64
      {{1, AUDIT_ARCH_X86_64, 0, {1}}, SECCOMP_RET_KILL},
      // getpid() on x86
      {{20, AUDIT_ARCH_I386, 0, {0}}, SECCOMP_RET_ALLOW},
      // exit(1) on x86
      {{1, AUDIT_ARCH_I386, 0, {1}}, SECCOMP_RET_KILL},
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
    interpreter_ctxt_t interpreter;
    if (!interpreter_run(&interpreter, &prog, &cases[i].data) ||
        interpreter.result != cases[i].expected) {
      test_fail_with_message("case %zu: got 0x%x, expected 0x%x", i,
                             interpreter.result, cases[i].expected);
      test_failed(__LINE__, __FILE__);
    }
  }
  free(prog.filter);
}

TEST_CASE(long_constants_eq) {
  TEST_POLICY("ALLOW { fcntl { 0x100001234 == 0x1234 }, exit } DEFAULT KILL");
  TEST_POLICY_BLOCKS_SYSCALL(SYSCALL_SPEC3(__NR_fcntl, 0, F_GETFD, 0));
}

TEST_CASE(duplicate_action_after_conditional) {
  TEST_POLICY(
      "ALLOW { read { fd == 1 }, exit }\n"
      "ALLOW { read }\n"
      "ALLOW { read }");
  TEST_POLICY_ALLOWS_SYSCALL(SYSCALL_SPEC3(__NR_read, 0, 0, 0),
                             SYSCALL_EXECUTED_SPEC(0, 0));
}

TEST_CASE(logic_negation) {
  TEST_POLICY(
      "ALLOW { exit },\n"
      "ERRNO(1) { read { !(fd == 5 && count == 0) } }\n"
      "DEFAULT KILL");
  TEST_POLICY_ALLOWS_SYSCALL(SYSCALL_SPEC3(__NR_read, 0, 0, 0),
                             SYSCALL_ERRNO_SPEC(1));
  TEST_POLICY_ALLOWS_SYSCALL(SYSCALL_SPEC3(__NR_read, 4, 0, 0),
                             SYSCALL_ERRNO_SPEC(1));
  TEST_POLICY_BLOCKS_SYSCALL(SYSCALL_SPEC3(__NR_read, 5, 0, 0));
}

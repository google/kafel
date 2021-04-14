/*
   Kafel - test harness
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

#ifndef KAFEL_TEST_RUNNER_HARNESS_H_
#define KAFEL_TEST_RUNNER_HARNESS_H_

#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stdbool.h>
#include <stdint.h>

#if defined(__x86_64__)
#define KAFEL_DEFAULT_SYSCALL_ARCH AUDIT_ARCH_X86_64
#elif defined(__aarch64__)
#define KAFEL_DEFAULT_SYSCALL_ARCH AUDIT_ARCH_AARCH64
#elif defined(__arm__)
#define KAFEL_DEFAULT_SYSCALL_ARCH AUDIT_ARCH_ARM
#elif defined(__mips64__)
#define KAFEL_DEFAULT_SYSCALL_ARCH AUDIT_ARCH_MIPS64
#elif defined(__mips__)
#define KAFEL_DEFAULT_SYSCALL_ARCH AUDIT_ARCH_MIPS
#elif defined(__i386__)
#define KAFEL_DEFAULT_SYSCALL_ARCH AUDIT_ARCH_I386
#else
#error "Unsupported architecture"
#endif

typedef int (*test_func_t)(void*);

typedef struct {
  uint32_t seccomp_ret;
  long rv;
  long expected_errno;
} syscall_result_spec_t;

typedef struct seccomp_data syscall_spec_t;

typedef struct {
  bool is_last;
  syscall_spec_t syscall;
  syscall_result_spec_t result;
} syscall_exec_spec_t;

enum {
  KAFEL_TEST_SYSCALLS_INTERPRET = 1,
  KAFEL_TEST_SYSCALLS_EXECUTE = 2,
};

#define SYSCALL_SPEC0(nr) SYSCALL_SPEC1((nr), 0)
#define SYSCALL_SPEC1(nr, arg0) SYSCALL_SPEC2((nr), (arg0), 0)
#define SYSCALL_SPEC2(nr, arg0, arg1) SYSCALL_SPEC3((nr), (arg0), (arg1), 0)
#define SYSCALL_SPEC3(nr, arg0, arg1, arg2) \
  SYSCALL_SPEC4((nr), (arg0), (arg1), (arg2), 0)
#define SYSCALL_SPEC4(nr, arg0, arg1, arg2, arg3) \
  SYSCALL_SPEC5((nr), (arg0), (arg1), (arg2), (arg3), 0)
#define SYSCALL_SPEC5(nr, arg0, arg1, arg2, arg3, arg4) \
  SYSCALL_SPEC6((nr), (arg0), (arg1), (arg2), (arg3), (arg4), 0)
#define SYSCALL_SPEC6(nr, arg0, arg1, arg2, arg3, arg4, arg5) \
  ((struct seccomp_data){(nr),                                \
                         KAFEL_DEFAULT_SYSCALL_ARCH,          \
                         0xf00f00f0deadbeefLL,                \
                         {(arg0), (arg1), (arg2), (arg3), (arg4), (arg5)}})
#define SYSCALL_KILLED_SPEC() ((syscall_result_spec_t){SECCOMP_RET_KILL, 0, 0})
#define SYSCALL_EXECUTED_SPEC(rv, err) \
  ((syscall_result_spec_t){SECCOMP_RET_ALLOW, (rv), (err)})
#define SYSCALL_ERRNO_SPEC(err) \
  ((syscall_result_spec_t){SECCOMP_RET_ERRNO | (err), -1, (err)})
#define SYSCALL_EXEC_SPEC(syscall, result) \
  ((syscall_exec_spec_t){false, (syscall), (result)})
#define SYSCALL_EXEC_SPEC_LAST \
  ((syscall_exec_spec_t){true, SYSCALL_SPEC0(0), SYSCALL_EXECUTED_SPEC(0, 0)})

int test_policy(bool should_fail, const char* source);
int test_policy_enforcment(test_func_t test_func, void* data, bool should_kill);
int test_set_syscalls_mode(int mode);
int test_policy_enforcment_syscalls(syscall_exec_spec_t syscall_specs[]);

static inline int test_policy_allows(test_func_t test_func, void* data) {
  return test_policy_enforcment(test_func, data, false);
}

static inline int test_policy_blocks(test_func_t test_func, void* data) {
  return test_policy_enforcment(test_func, data, true);
}

static inline int test_policy_enforcment_syscall(
    syscall_spec_t syscall_spec, syscall_result_spec_t result_spec) {
  syscall_exec_spec_t syscall_specs[2] = {
      SYSCALL_EXEC_SPEC(syscall_spec, result_spec), SYSCALL_EXEC_SPEC_LAST};
  return test_policy_enforcment_syscalls(syscall_specs);
}

static inline int test_policy_allows_syscall(
    syscall_spec_t syscall_spec, syscall_result_spec_t result_spec) {
  return test_policy_enforcment_syscall(syscall_spec, result_spec);
}

static inline int test_policy_blocks_syscall(syscall_spec_t syscall_spec) {
  return test_policy_enforcment_syscall(syscall_spec, SYSCALL_KILLED_SPEC());
}

extern void test_failed(int, const char*);

#define CHECK_TEST_RET(ret)            \
  do {                                 \
    int rv = (ret);                    \
    if (rv != 0) {                     \
      test_failed(__LINE__, __FILE__); \
    }                                  \
  } while (0)

#define TEST_POLICY(...) CHECK_TEST_RET((test_policy(false, __VA_ARGS__)))
#define TEST_COMPILE_ERROR(...) CHECK_TEST_RET((test_policy(true, __VA_ARGS__)))
#define TEST_POLICY_ENFORCMENT(...) \
  CHECK_TEST_RET((test_policy_enforcment(__VA_ARGS__)))
#define TEST_POLICY_ENFORCMENT_SYSCALL(...) \
  CHECK_TEST_RET((test_policy_enforcment_syscall(__VA_ARGS__)))
#define TEST_POLICY_ENFORCMENT_SYSCALLS(...) \
  CHECK_TEST_RET((test_policy_enforcment_syscalls(__VA_ARGS__)))
#define TEST_POLICY_ALLOWS(...) \
  CHECK_TEST_RET((test_policy_allows(__VA_ARGS__)))
#define TEST_POLICY_ALLOWS_SYSCALL(...) \
  CHECK_TEST_RET((test_policy_allows_syscall(__VA_ARGS__)))
#define TEST_POLICY_ALLOWS_SYSCALLS(...) \
  CHECK_TEST_RET((test_policy_allows_syscalls(__VA_ARGS__)))
#define TEST_POLICY_BLOCKS(...) \
  CHECK_TEST_RET((test_policy_blocks(__VA_ARGS__)))
#define TEST_POLICY_BLOCKS_SYSCALL(...) \
  CHECK_TEST_RET((test_policy_blocks_syscall(__VA_ARGS__)))
#define TEST_POLICY_BLOCKS_SYSCALLS(...) \
  CHECK_TEST_RET((test_policy_blocks_syscalls(__VA_ARGS__)))

#endif /* KAFEL_TEST_RUNNER_HARNESS_H_ */

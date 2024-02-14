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

#include "harness.h"

#include <errno.h>
#include <kafel.h>
#include <linux/seccomp.h>
#include <linux/unistd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/signalfd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "interpreter.h"
#include "runner.h"

#define TEST_PASSED() \
  do {                \
    return 0;         \
  } while (0)

#define TEST_FAIL(fmt, ...)                     \
  do {                                          \
    test_fail_with_message(fmt, ##__VA_ARGS__); \
    return -1;                                  \
  } while (0)

#define KAFEL_HARNESS_ERROR_BUF_SIZE 4096

static struct sock_fprog test_policy_prog = {0, NULL};
static bool test_policy_compilation_flag;
static int test_syscalls_mode =
    KAFEL_TEST_SYSCALLS_EXECUTE | KAFEL_TEST_SYSCALLS_INTERPRET;

int test_policy(bool should_fail, const char* source) {
  free(test_policy_prog.filter);
  test_policy_prog.filter = NULL;
  test_policy_prog.len = 0;
  kafel_ctxt_t ctxt = kafel_ctxt_create();
  kafel_set_input_string(ctxt, source);
  kafel_add_include_search_path(ctxt, "testdata");
  int rv = kafel_compile(ctxt, &test_policy_prog);
  if (rv != 0) {
    test_policy_compilation_flag = false;
    if (!should_fail) {
      test_fail_with_message("Compilation failure:\n\t%s",
                             kafel_error_msg(ctxt));
    }
    kafel_ctxt_destroy(&ctxt);
    return should_fail ? 0 : -1;
  }
  kafel_ctxt_destroy(&ctxt);
  test_policy_compilation_flag = true;
  if (!should_fail) {
    TEST_PASSED();
  } else {
    TEST_FAIL("Policy compiled succesfuly when compilation error expected");
  }
}

static void sys_exit(int rv) { syscall(__NR_exit, rv); }

static void install_seccomp_prog(struct sock_fprog* prog) {
  if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
    sys_exit(-1);
  }
  if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, prog, 0, 0)) {
    sys_exit(-1);
  }
}

static void kill_and_wait(pid_t pid) {
  if (kill(pid, SIGKILL) == 0) {
    waitpid(pid, NULL, 0);
  } else {
    waitpid(pid, NULL, WNOHANG);
  }
}

int test_policy_enforcment(test_func_t test_func, void* data,
                           bool should_kill) {
  // Skip tests when compilation failed
  if (!test_policy_compilation_flag) {
    TEST_PASSED();
  }

  sigset_t sigchld_set;
  sigset_t orig_set;
  sigemptyset(&sigchld_set);
  sigaddset(&sigchld_set, SIGCHLD);
  sigprocmask(SIG_BLOCK, &sigchld_set, &orig_set);
  // Allocate a shared buffer to pass back error info.
  char* err_buf =
      mmap(NULL, KAFEL_HARNESS_ERROR_BUF_SIZE, PROT_READ | PROT_WRITE,
           MAP_SHARED | MAP_ANONYMOUS, -1, 0);
  err_buf[0] = '\0';
  if (err_buf == MAP_FAILED) {
    TEST_FAIL("could not mmap error buf");
  }
  pid_t pid = fork();
  if (pid == -1) {
    sigprocmask(SIG_SETMASK, &orig_set, NULL);
    munmap(err_buf, KAFEL_HARNESS_ERROR_BUF_SIZE);
    TEST_FAIL("could not fork");
  } else if (pid == 0) {
    install_seccomp_prog(&test_policy_prog);
    sys_exit(test_func(data, err_buf));
  }
  int sigchld_fd = signalfd(-1, &sigchld_set, 0);
  if (sigchld_fd < 0) {
    kill_and_wait(pid);
    sigprocmask(SIG_SETMASK, &orig_set, NULL);
    munmap(err_buf, KAFEL_HARNESS_ERROR_BUF_SIZE);
    TEST_FAIL("signalfd failed");
  }
  fd_set rfds;
  FD_ZERO(&rfds);
  FD_SET(sigchld_fd, &rfds);
  struct timeval timeout;
  timeout.tv_sec = 1;
  timeout.tv_usec = 0;
  int rv = select(sigchld_fd + 1, &rfds, NULL, NULL, &timeout);
  while (rv < 0) {
    if (errno != EINTR) {
      close(sigchld_fd);
      kill_and_wait(pid);
      sigprocmask(SIG_SETMASK, &orig_set, NULL);
      munmap(err_buf, KAFEL_HARNESS_ERROR_BUF_SIZE);
      TEST_FAIL("select failed");
    }
    rv = select(sigchld_fd + 1, &rfds, NULL, NULL, &timeout);
  }
  close(sigchld_fd);
  if (rv == 0) {
    kill_and_wait(pid);
    sigprocmask(SIG_SETMASK, &orig_set, NULL);
    munmap(err_buf, KAFEL_HARNESS_ERROR_BUF_SIZE);
    TEST_FAIL("timed out");
  }
  sigprocmask(SIG_SETMASK, &orig_set, NULL);
  siginfo_t si;
  si.si_pid = 0;
  rv = waitid(P_PID, pid, &si, WEXITED | WNOHANG);
  if (rv != 0 || si.si_pid != pid) {
    kill_and_wait(pid);
    munmap(err_buf, KAFEL_HARNESS_ERROR_BUF_SIZE);
    TEST_FAIL("waitid failed %d %d %d %d", rv, errno, si.si_pid, pid);
  }
  char err_copy[KAFEL_HARNESS_ERROR_BUF_SIZE];
  memcpy(err_copy, err_buf, KAFEL_HARNESS_ERROR_BUF_SIZE);
  munmap(err_buf, KAFEL_HARNESS_ERROR_BUF_SIZE);
  bool signaled = si.si_code == CLD_KILLED || si.si_code == CLD_DUMPED;
  if (si.si_code == CLD_EXITED) {
    if (si.si_status != 0) {
      if (should_kill) {
        TEST_FAIL(
            "should be killed by seccomp; non-zero (%d) exit code instead: %s",
            si.si_status, err_copy);
      }
      TEST_FAIL("non-zero (%d) exit code: %s", si.si_status, err_copy);
    }
    if (should_kill) {
      TEST_FAIL("should be killed by seccomp; exited normally instead");
    }
  } else if (signaled) {
    if (si.si_status != SIGSYS) {
      if (should_kill) {
        TEST_FAIL("should be killed by seccomp; killed by signal %d instead",
                  si.si_status);
      }
      TEST_FAIL("killed by signal %d", si.si_status);
    }
    if (!should_kill) {
      TEST_FAIL("should not be killed by seccomp");
    }
  } else {
    if (should_kill) {
      TEST_FAIL("should be killed by seccomp; not exited normally instead");
    }
    TEST_FAIL("not exited normally");
  }
  TEST_PASSED();
}

int test_policy_enforcement_syscalls_interpret(
    syscall_exec_spec_t syscall_specs[]) {
  // Skip tests when compilation failed
  if (!test_policy_compilation_flag) {
    TEST_PASSED();
  }

  for (const syscall_exec_spec_t* syscall_spec = syscall_specs;
       !syscall_spec->is_last; ++syscall_spec) {
    uint32_t seccomp_ret = syscall_spec->result.seccomp_ret;
    const syscall_spec_t* data = &syscall_spec->syscall;
    uint64_t args[6];
    for (int i = 0; i < 6; ++i) {
      args[i] = data->args[i];
    }
    interpreter_ctxt_t ctxt;
    if (!interpreter_run(&ctxt, &test_policy_prog, data)) {
      TEST_FAIL("interpreter error for syscall(%d, %#" PRIx64 ", %#" PRIx64
                ", %#" PRIx64 ", %#" PRIx64 ", %#" PRIx64 ", %#" PRIx64
                ") @ %#" PRIx64 " with arch = %#" PRIx32 ": %s",
                data->nr, args[0], args[1], args[2], args[3], args[4], args[5],
                (uint64_t)data->instruction_pointer, data->arch,
                ctxt.error_buf);
    }
    if (ctxt.result != seccomp_ret) {
      TEST_FAIL("invalid result for syscall(%d, %#" PRIx64 ", %#" PRIx64
                ", %#" PRIx64 ", %#" PRIx64 ", %#" PRIx64 ", %#" PRIx64
                ") @ %#" PRIx64 " with arch = %#" PRIx32 ": got %#" PRIx32
                ", expected %#" PRIx32,
                data->nr, args[0], args[1], args[2], args[3], args[4], args[5],
                (uint64_t)data->instruction_pointer, data->arch, ctxt.result,
                seccomp_ret);
    }
  }
  TEST_PASSED();
}

static int syscall_caller_helper(void* data, char* err) {
  int syscall_no = 0;
  for (const syscall_exec_spec_t* syscall_spec =
           (const syscall_exec_spec_t*)data;
       !syscall_spec->is_last; ++syscall_spec) {
    ++syscall_no;
    long nr = syscall_spec->syscall.nr;
    long arg[6];
    for (int i = 0; i < 6; ++i) {
      arg[i] = syscall_spec->syscall.args[i];
    }
    long expected = syscall_spec->result.rv;
    long expected_errno = syscall_spec->result.expected_errno;
    errno = 0;
    long ret = syscall(nr, arg[0], arg[1], arg[2], arg[3], arg[4], arg[5]);
    if (ret != expected || errno != expected_errno) {
      int errno_copy = errno;
      snprintf(err, KAFEL_HARNESS_ERROR_BUF_SIZE,
               "%ld(%ld, %ld, %ld, %ld, %ld, %ld): %ld != %ld OR %d != %ld", nr,
               arg[0], arg[1], arg[2], arg[3], arg[4], arg[5], ret, expected,
               errno_copy, expected_errno);
      return syscall_no;
    }
  }
  return 0;
}

int test_policy_enforcment_syscalls(syscall_exec_spec_t syscall_specs[]) {
  int ret = 0;

  if (test_syscalls_mode & KAFEL_TEST_SYSCALLS_EXECUTE) {
    bool should_kill = false;
    for (const syscall_exec_spec_t* syscall_spec = syscall_specs;
         !syscall_spec->is_last; ++syscall_spec) {
      uint32_t seccomp_ret = syscall_spec->result.seccomp_ret;
      if (seccomp_ret == SECCOMP_RET_KILL ||
          seccomp_ret == SECCOMP_RET_KILL_PROCESS) {
        should_kill = true;
      }
    }
    ret |= test_policy_enforcment(syscall_caller_helper, syscall_specs,
                                  should_kill);
  }
  if (test_syscalls_mode & KAFEL_TEST_SYSCALLS_INTERPRET) {
    ret |= test_policy_enforcement_syscalls_interpret(syscall_specs);
  }
  return ret;
}

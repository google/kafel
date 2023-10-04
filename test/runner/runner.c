/*
   Kafel - test runner
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

#include "runner.h"

#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TEST_ERROR_MSG_BUF_SIZE 1024
#define TEST_ERROR_MSGS_SIZE 10 * TEST_ERROR_MSG_BUF_SIZE
static char test_error_msg_buf[TEST_ERROR_MSG_BUF_SIZE];
static char test_error_msgs[TEST_ERROR_MSGS_SIZE];

void test_fail_with_message(const char* format, ...) {
  va_list ap;
  va_start(ap, format);
  vsnprintf(test_error_msg_buf, TEST_ERROR_MSG_BUF_SIZE, format, ap);
  va_end(ap);
}

static bool test_case_failed_flag = false;

void test_failed(int line, const char* file) {
  size_t len = strlen(test_error_msgs);
  snprintf(test_error_msgs + len, TEST_ERROR_MSGS_SIZE - len, "\t%s:%d: %s\n",
           file, line, test_error_msg_buf);
  test_case_failed_flag = true;
}

#define MAX_TESTS 4096

test_case_def_t runner_tests[MAX_TESTS];
int runner_tests_count;

int main(void) {
  int tests_failed = 0, tests_passed = 0, tests_left = runner_tests_count;
  for (int i = 0; i < runner_tests_count; ++i) {
    test_case_def_t* test_case = &runner_tests[i];
    fprintf(stderr, "[+%4d|-%4d| %4d]\r", tests_passed, tests_failed,
            tests_left);
    test_case_failed_flag = false;
    test_error_msgs[0] = '\0';
    test_case->func();
    if (test_case_failed_flag) {
      ++tests_failed;
      fprintf(stderr, "FAILED %s:\n%s\n", test_case->name, test_error_msgs);
    } else {
      ++tests_passed;
    }
    --tests_left;
  }
  fprintf(stderr, "[+%4d|-%4d]      \n", tests_passed, tests_failed);
  return tests_failed == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

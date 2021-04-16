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

#ifndef KAFEL_TEST_RUNNER_RUNNER_H_
#define KAFEL_TEST_RUNNER_RUNNER_H_

__attribute__((format(printf, 1, 2))) void test_fail_with_message(
    const char* format, ...);
void test_failed(int line, const char* file);

typedef struct {
  const char* name;
  void (*func)(void);
} test_case_def_t;

extern test_case_def_t runner_tests[];
extern int runner_tests_count;

#define TEST_CASE(test_case_name)                                        \
  static void test_##test_case_name(void);                               \
  __attribute((constructor)) static void register_test_##test_case_name( \
      void) {                                                            \
    test_case_def_t* test_case = &runner_tests[runner_tests_count];      \
    test_case->name = #test_case_name;                                   \
    test_case->func = test_##test_case_name;                             \
    runner_tests_count++;                                                \
  }                                                                      \
  static void test_##test_case_name(void)

#endif /* KAFEL_TEST_RUNNER_RUNNER_H_ */

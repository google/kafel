/*
   Kafel - common
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

#ifndef KAFEL_COMMON_H
#define KAFEL_COMMON_H

#include <assert.h>

#define ASSERT(x) \
  do {            \
    assert(x);    \
  } while (0)

#define SWAP(a, b)         \
  do {                     \
    __typeof__(a) tmp = a; \
    a = b;                 \
    b = tmp;               \
  } while (0)

#define KAFEL_API __attribute__((visibility("default")))

#ifndef KAFEL_DEFAULT_TARGET_ARCH

#if defined(__x86_64__)
#define KAFEL_DEFAULT_TARGET_ARCH AUDIT_ARCH_X86_64
#elif defined(__aarch64__)
#define KAFEL_DEFAULT_TARGET_ARCH AUDIT_ARCH_AARCH64
#elif defined(__arm__)
#define KAFEL_DEFAULT_TARGET_ARCH AUDIT_ARCH_ARM
#elif defined(__mips64__)
#define KAFEL_DEFAULT_TARGET_ARCH AUDIT_ARCH_MIPS64
#elif defined(__mips__)
#define KAFEL_DEFAULT_TARGET_ARCH AUDIT_ARCH_MIPS
#elif defined(__i386__)
#define KAFEL_DEFAULT_TARGET_ARCH AUDIT_ARCH_I386
#else
#error "Unsupported architecture"
#endif

#endif /* KAFEL_DEFAULT_TARGET_ARCH */

#endif /* KAFEL_COMMON_H */

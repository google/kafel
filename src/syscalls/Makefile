#
#   Kafel - Makefile
#   -----------------------------------------
#
#   Copyright 2019 Google Inc. All Rights Reserved.
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
#

CFLAGS+=-I..
SRCS:=syscalldb_generator.c\
      amd64_syscalls.c \
      i386_syscalls.c \
      aarch64_syscalls.c \
      mipso32_syscalls.c \
      mips64_syscalls.c \
      arm_syscalls.c
TARGET=syscalldb_generator

include ${PROJECT_ROOT}build/Makefile.mk

syscalldb_generator: ${OBJECTS}

# DO NOT DELETE THIS LINE -- make depend depends on it.

syscalldb_generator.o: ../syscall.h ../syscalldb.h ../common.h
amd64_syscalls.o: ../syscall.h
i386_syscalls.o: ../syscall.h
aarch64_syscalls.o: ../syscall.h
mipso32_syscalls.o: ../syscall.h
mips64_syscalls.o: ../syscall.h
arm_syscalls.o: ../syscall.h


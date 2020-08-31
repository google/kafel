#
#   Kafel - Makefile
#   -----------------------------------------
#
#   Copyright 2016 Google Inc. All Rights Reserved.
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

SUBDIRS:=syscalls

OBJCOPY?=objcopy

CFLAGS+=-fPIC -fvisibility=hidden
GENERATED_SRCS:=lexer.c parser.c syscalldb.c
GENERATED:=lexer.h parser.h ${GENERATED_SRCS}
TEMPORARY:=libkafel_r.o libkafel.o syscalldb.gperf
SRCS:=kafel.c \
      context.c \
      codegen.c \
      expression.c \
      includes.c \
      policy.c \
      range_rules.c \
      syscall.c \
      ${GENERATED_SRCS}
DYNAMIC_TARGET:=${PROJECT_ROOT}libkafel.so
STATIC_TARGET:=${PROJECT_ROOT}libkafel.a
TARGET=${DYNAMIC_TARGET} ${STATIC_TARGET}
VERSION:=1

include ${PROJECT_ROOT}build/Makefile.mk

# Hard to fix those in generated code so just disable
${GENERATED_OBJECTS}: CFLAGS+=-Wno-error

${DYNAMIC_TARGET}: ${OBJECTS}
	$(CC) -Wl,-soname,$@.${VERSION} -shared $^ -o $@

${STATIC_TARGET}: ${OBJECTS}
	$(LD) -r ${OBJECTS} -o libkafel_r.o
	$(OBJCOPY) --localize-hidden libkafel_r.o libkafel.o
	$(RM) libkafel_r.o
	$(AR) rcs $@ libkafel.o
	$(RM) libkafel.o

lexer.h lexer.c: lexer.l
	flex $<

parser.h parser.c: parser.y
	bison $<

syscalldb.c: syscalls/syscalldb_generator
	./syscalls/syscalldb_generator > ./syscalldb.gperf
	gperf -m10 --output-file=./syscalldb.c ./syscalldb.gperf

syscalls/syscalldb_generator: syscalls
	true

# DO NOT DELETE THIS LINE -- make depend depends on it.

kafel.o: codegen.h context.h includes.h policy.h expression.h syscall.h
kafel.o: common.h lexer.h parser.h
context.o: context.h includes.h policy.h expression.h syscall.h common.h
codegen.o: codegen.h context.h includes.h policy.h expression.h syscall.h
codegen.o: common.h range_rules.h
expression.o: expression.h common.h
includes.o: includes.h common.h
policy.o: policy.h expression.h common.h
range_rules.o: range_rules.h policy.h expression.h common.h syscall.h
syscall.o: syscall.h syscalldb.h common.h
syscalldb.o: syscall.h syscalldb.h syscalldb.inl
lexer.o: parser.h context.h includes.h policy.h expression.h syscall.h
lexer.o: common.h
parser.o: parser.h context.h includes.h policy.h expression.h syscall.h
parser.o: lexer.h

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

OBJCOPY?=objcopy

CFLAGS+=-std=gnu11 -I./include -Wall -Wextra -Werror
CFLAGS+=-fPIC -fvisibility=hidden
GENERATED_SRCS:=lexer.c parser.c
GENERATED:=lexer.h parser.h ${GENERATED_SRCS}
TEMPORARY:=libkafel_r.o libkafel.o
SYSCALL_LISTS:=amd64_syscalls.c \
               arm_syscalls.c
SRCS:=kafel.c \
      context.c \
      codegen.c \
      expression.c \
      policy.c \
      range_rules.c \
      syscall.c \
      ${GENERATED_SRCS} \
      $(SYSCALL_LISTS:%.c=syscalls/%.c)
GENERATED_OBJECTS:=$(GENERATED_SRCS:.c=.o)
OBJECTS:=$(SRCS:.c=.o)
TARGET:=libkafel.so
STATIC_TARGET:=libkafel.a
VERSION:=1

ifdef DEBUG
  CFLAGS += -g -ggdb -gdwarf-4
else
  CFLAGS += -O2
endif

ifdef ASAN
  CFLAGS += -fsanitize=address
endif

.PHONY: all clean depend format tools

all: ${TARGET} ${STATIC_TARGET}

tools:
	$(MAKE) -C tools

# Hard to fix those in generated code so just disable
${GENERATED_OBJECTS}: CFLAGS+=-Wno-error

clean:
	$(RM) Makefile.bak ${GENERATED} ${TEMPORARY} ${OBJECTS} ${TARGET} ${STATIC_TARGET}
	$(MAKE) -C tools clean

${TARGET}: ${OBJECTS}
	$(CC) -Wl,-soname,${TARGET}.${VERSION} -shared $^ -o $@

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

depend:
	makedepend -Y. $(SRCS)
	$(MAKE) -C tools depend

format:
	clang-format -i -style=Google *.c *.h syscalls/*.c
	$(MAKE) -C tools format

# DO NOT DELETE THIS LINE -- make depend depends on it.

kafel.o: parser.h context.h policy.h expression.h syscall.h codegen.h
kafel.o: common.h lexer.h
context.o: context.h policy.h expression.h syscall.h common.h
codegen.o: codegen.h context.h policy.h expression.h syscall.h common.h
codegen.o: range_rules.h
expression.o: expression.h common.h
policy.o: policy.h expression.h common.h
range_rules.o: range_rules.h policy.h expression.h common.h syscall.h
syscall.o: syscall.h common.h
lexer.o: parser.h context.h policy.h expression.h syscall.h
parser.o: parser.h context.h policy.h expression.h syscall.h lexer.h
syscalls/amd64_syscalls.o: syscall.h
syscalls/arm_syscalls.o: syscall.h

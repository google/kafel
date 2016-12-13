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

PROJECT_ROOT:=../../
CFLAGS+=-std=gnu11 -I${PROJECT_ROOT}include -Wall
SRCS:=main.c disasm.c
OBJECTS:=$(SRCS:.c=.o)
TARGET:=dump_policy_bpf
LIBS:=${PROJECT_ROOT}libkafel.a

ifdef DEBUG
        CFLAGS += -g -ggdb -gdwarf-4
else
        CFLAGS += -O2
endif

.PHONY: all clean depend format

all: ${TARGET}

clean:
	$(RM) Makefile.bak ${OBJECTS} ${TARGET}

${TARGET}: ${OBJECTS}
	$(CC) $^ ${LIBS} -o $@

depend:
	makedepend -Y. $(SRCS)

format:
	clang-format -i -style=Google *.c *.h

# DO NOT DELETE THIS LINE -- make depend depends on it.

main.o: disasm.h
disasm.o: disasm.h

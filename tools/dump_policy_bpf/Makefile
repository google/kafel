#
#   Kafel - Makefile
#   -----------------------------------------
#
#   Copyright 2016 Google LLC
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

SRCS:=main.c disasm.c print.c
TARGET:=dump_policy_bpf
LIBS:=${PROJECT_ROOT}libkafel.a

include ${PROJECT_ROOT}build/Makefile.mk

CFLAGS+=-Wno-error=type-limits

${TARGET}: ${OBJECTS}
	$(CC) ${CFLAGS} $^ ${LIBS} -o $@

# DO NOT DELETE THIS LINE -- make depend depends on it.

main.o: disasm.h print.h
disasm.o: disasm.h
print.o: print.h

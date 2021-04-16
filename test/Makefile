#
#   Kafel - Makefile
#   -----------------------------------------
#
#   Copyright 2017 Google LLC
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

SRCS:=basic.c broken.c includes.c
TARGET:=tests
LIBS:=runner/librunner.a ${PROJECT_ROOT}libkafel.a
SUBDIRS:=runner

include ${PROJECT_ROOT}build/Makefile.mk

runner/librunner.a: runner
${TARGET}: ${OBJECTS} ${LIBS}
	$(CC) ${CFLAGS} ${OBJECTS} ${LIBS} -o $@

# DO NOT DELETE THIS LINE -- make depend depends on it.

basic.o: runner/harness.h runner/runner.h
broken.o: runner/harness.h runner/runner.h
includes.o: runner/harness.h runner/runner.h

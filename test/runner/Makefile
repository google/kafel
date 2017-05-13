#
#   Kafel - Makefile
#   -----------------------------------------
#
#   Copyright 2017 Google Inc. All Rights Reserved.
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

SRCS:=harness.c\
      runner.c
TARGET:=librunner.a

include ${PROJECT_ROOT}build/Makefile.mk

${TARGET}: ${OBJECTS} ${LIBS}
	$(AR) rcs $@ $^

# DO NOT DELETE THIS LINE -- make depend depends on it.

harness.o: harness.h runner.h
runner.o: runner.h

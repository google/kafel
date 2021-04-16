#
#   Kafel - Makefile skeleton
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

PROJECT_ROOT?=
CFLAGS+=-std=gnu11 -I${PROJECT_ROOT}include -Wall -Wextra -Werror

GENERATED_OBJECTS:=$(GENERATED_SRCS:.c=.o)
OBJECTS:=$(SRCS:.c=.o)

ifdef DEBUG
  CFLAGS += -g -ggdb -gdwarf-4
else
  CFLAGS += -O2
endif

ifdef ASAN
  CFLAGS += -fsanitize=address
endif

.PHONY: all clean depend format $(SUBDIRS)

all: ${TARGET}

$(SUBDIRS):
	$(MAKE) -C $@ PROJECT_ROOT=../${PROJECT_ROOT}

clean:
	$(RM) Makefile.bak ${GENERATED} ${TEMPORARY} ${OBJECTS} ${TARGET} ${STATIC_TARGET}
	for dir in ${SUBDIRS}; do \
		$(MAKE) -C $$dir PROJECT_ROOT=../${PROJECT_ROOT} clean; \
	done


depend:
	makedepend -Y. $(SRCS)
	for dir in ${SUBDIRS}; do \
		$(MAKE) -C $$dir PROJECT_ROOT=../${PROJECT_ROOT} depend; \
	done

format:
ifdef SRCS
	clang-format -i -style=Google ${SRCS}
endif
	clang-format -i -style=Google *.h || true
	for dir in ${SUBDIRS}; do \
		$(MAKE) -C $$dir PROJECT_ROOT=../${PROJECT_ROOT} format; \
	done

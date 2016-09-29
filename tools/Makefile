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

SUBDIRS:=dump_policy_bpf

.PHONY: all depend format ${SUBDIRS}

all: ${SUBDIRS}
${SUBDIRS}:
	$(MAKE) -C $@

depend:
	$(MAKE) -C ${SUBDIRS} depend

format:
	$(MAKE) -C ${SUBDIRS} format

clean:
	${MAKE} -C ${SUBDIRS} clean

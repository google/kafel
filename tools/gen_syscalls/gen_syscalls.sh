#!/bin/bash

#
#   Kafel - syscalls extractor
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

if [ $# -ne 1 ] || [ ! -e "$1" -o -d "$1" ]; then
	echo "USAGE: $0 [linux_with_debugging_symbols]"
	exit 1
fi

linux="$1"
arch="$(readelf -h "$linux" | sed -ne '/Machine:/{s/^[[:space:]]*Machine:[[:space:]]*//;P}')"
if [ "$arch" = "Advanced Micro Devices X86-64" ]; then
	arch="AMD64"
fi
outname="${arch,,}_syscalls.c"

echo -n "Generating syscalls for $arch... "

year=$(date +%Y)
cat > "$outname" <<HEADER
/*
   Kafel - syscalls ($arch)
   -----------------------------------------

   Copyright $(year) Google LLC

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

#include <stddef.h>

#include "../syscall.h"

#define ARG_0 0
#define ARG_1 1
#define ARG_2 2
#define ARG_3 3
#define ARG_4 4
#define ARG_5 5

#define NORMAL false

const struct syscall_descriptor ${arch,,}_syscall_list[] = {
HEADER

case "$arch" in
ARM)
	gdb --batch -ex 'set gnutarget elf32-littlearm' -ex "file $linux" -x extract.py
	;;
*)
	gdb --batch -ex "file $linux" -x extract.py
	;;
esac

if [ -f "missing/${arch,,}.c" ]; then
	cat "missing/${arch,,}.c" >> output_syscalls.c
fi

cat output_syscalls.c | sort -k1,1 --unique --stable -t',' >> "$outname"
rm output_syscalls.c

cat >> "$outname" <<FOOTER
};

const size_t ${arch,,}_syscall_list_size = sizeof(${arch,,}_syscall_list)/sizeof(${arch,,}_syscall_list[0]);
FOOTER

echo "DONE"

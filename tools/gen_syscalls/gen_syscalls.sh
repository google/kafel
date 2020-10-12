#!/bin/bash

#
#   Kafel - syscalls extractor
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

# Start of functions

generate_syscall_file()
{
	# $1 - linux file ($linux)
	# $2 - architecture ($arch)
	# $3 - (optional) syscall table symbol name (sys_call_table)
	# $4 - (optional) syscall bit (0 or _X32_SYSCALL_BIT)

	linux="$1"
	arch="$2"
	SYSCALLTABLENAME="$3"
	SYSCALLBIT="$4"

	[ -z "$SYSCALLTABLENAME" ] && SYSCALLTABLENAME="sys_call_table"
	[ -z "$SYSCALLBIT" ] && SYSCALLBIT=0

	echo -n "Generating syscalls for $arch ... "
	outname="${arch,,}_syscalls.c"

	cat > "$outname" <<HEADER
/*
   Kafel - syscalls ($arch)
   -----------------------------------------

   Copyright 2016 Google Inc. All Rights Reserved.

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

	echo -n "" > output_syscalls.c


	case "$arch" in
	ARM)
		SYSCALLTABLENAME="$SYSCALLTABLENAME" \
		SYSCALLBIT=$SYSCALLBIT \
			"$GDB" --batch \
			-ex 'set gnutarget elf32-littlearm' \
			-ex "file $linux" \
			-x extract.py
		;;
	*)
		SYSCALLTABLENAME="$SYSCALLTABLENAME" \
		SYSCALLBIT=$SYSCALLBIT \
			"$GDB" --batch \
			-ex "file $linux" \
			-x extract.py
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
}

# End of functions

# Start of script

if [ $# -ne 1 ] || [ ! -e "$1" -o -d "$1" ]; then
	echo "USAGE: $0 [linux_with_debugging_symbols]"
	exit 1
fi

export LANG=C

# For gdb-multiarch or toolchain-provided gdb

[ -z "$GDB" ] && GDB="gdb"

linux="$1"
arch="$(readelf -h "$linux" | sed -ne '/Machine:/{s/^[[:space:]]*Machine:[[:space:]]*//;P}')"
class="$(readelf -h "$linux" | sed -ne '/Class:/{s/^[[:space:]]*Class:[[:space:]]*//;P}')"

if [ "$arch" = "Advanced Micro Devices X86-64" ]; then
	arch="AMD64"
elif [ "$arch" = "Intel 80386" ]; then
	arch="i386"
elif [ "$arch" = "MIPS R3000" ]; then
        [ "$class" = "ELF32" ] && arch="mipso32" || arch="mips64"
fi

if [ "$arch" = "AMD64" ]; then
	generate_syscall_file "$linux" amd64
	generate_syscall_file "$linux" i386 ia32_sys_call_table 0
	generate_syscall_file "$linux" x32 x32_sys_call_table 1073741824
else
	generate_syscall_file "$linux" "$arch"
fi

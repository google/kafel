"""
   Kafel - syscall extractor
   -----------------------------------------

   Copyright 2016 Google LLC

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
"""

import re

out_file = open('output_syscalls.c', 'w')

def output(str):
	out_file.write(str)

def get_int_val(command):
	out = gdb.execute(command, False, True)
	m = re.search('\$[0-9]* = (.*)', out)
	return int(m.group(1))

def get_string_val(command):
	out = gdb.execute(command, False, True)
	m = re.search('\$[0-9]* = 0x[0-9a-f]* "(.*)"', out)
	return m.group(1)

def output_syscall(nr, name):
	try:
		real_name = get_string_val("print __syscall_meta__"+name+"->name")
		nb_args = get_int_val("print __syscall_meta__"+name+"->nb_args")
	except gdb.error:
		return
	m = re.search("^[Ss]y[Ss]_(.*)$", real_name)
	if m:
		real_name = m.group(1)
	else:
		real_name = name
	output('\t{"'+real_name+'", '+str(nr)+', {')
	for j in xrange(0, nb_args):
		arg_name = get_string_val("print __syscall_meta__"+name+"->args["+str(j)+"]")
		arg_type = get_string_val("print __syscall_meta__"+name+"->types["+str(j)+"]")
		arg_size = get_int_val("print sizeof("+arg_type+")")
		output('[ARG_'+str(j)+'] = {"'+arg_name+'", '+str(arg_size)+'}, ')
	output('}},\n')

num_syscalls=get_int_val("print sizeof(sys_call_table)/sizeof(sys_call_table[0])")
table_cmd = "print sys_call_table"
syscall_regex = "<([Ss]y[Ss]|stub)_([^>]*)>"

if num_syscalls <= 0:
	num_syscalls = 1000
	table_cmd = "info symbol ((void**)sys_call_table)"
	syscall_regex = "([Ss]y[Ss]|stub)_([^ ]*)"

for i in xrange(0, num_syscalls):
	try:
		out = gdb.execute(table_cmd+"["+str(i)+"]", False, True)
	except gdb.error:
		continue
	m = re.search(syscall_regex, out)
	if m:
		name = m.group(2)
		output_syscall(i, name)

out_file.close()

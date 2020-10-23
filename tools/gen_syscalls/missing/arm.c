	{"alarm", 27, {[ARG_0] = {"seconds", 4},}}, // obsolete, no longer available for EABI
	{"arm_fadvise64_64", 270, {[ARG_0] = {"fd", 4}, [ARG_1] = {"offset", 8}, [ARG_2] = {"len", 8},}},
	{"breakpoint", 983041, {}},
	{"cacheflush", 983042, {[ARG_0] = {"vaddr_from", 4}, [ARG_1] = {"vaddr_to", 4}, [ARG_2] = {"flags", 4},}},
	{"copy_file_range", 391, {[ARG_0] = {"fd_in", 4}, [ARG_1] = {"off_in", 4}, [ARG_2] = {"fd_out", 4}, [ARG_3] = {"off_out", 4}, [ARG_4] = {"len", 4}, [ARG_5] = {"flags", 4},}},
	{"fstatfs64", 267, {[ARG_0] = {"fd", 4}, [ARG_1] = {"sz", 4}, [ARG_2] = {"buf", 4},}},
	{"get_mempolicy", 320, {[ARG_0] = {"policy", 4}, [ARG_1] = {"nmask", 4}, [ARG_2] = {"maxnode", 4}, [ARG_3] = {"addr", 4}, [ARG_4] = {"flags", 4},}},
	{"ipc", 117, {[ARG_0] = {"call", 4}, [ARG_1] = {"first", 4}, [ARG_2] = {"second", 4}, [ARG_3] = {"third", 4}, [ARG_4] = {"ptr", 4}, [ARG_5] = {"fifth", 4},}}, // obsolete, no longer available for EABI
	{"mbind", 319, {[ARG_0] = {"start", 4}, [ARG_1] = {"len", 4}, [ARG_2] = {"mode", 4}, [ARG_3] = {"nmask", 4}, [ARG_4] = {"maxnode", 4}, [ARG_5] = {"flags", 4},}},
	{"mmap", 90, {[ARG_0] = {"addr", 4}, [ARG_1] = {"len", 4}, [ARG_2] = {"prot", 4}, [ARG_3] = {"flags", 4}, [ARG_4] = {"fd", 4}, [ARG_5] = {"offset", 4},}}, // obsolete, no longer available for EABI
	{"mmap2", 192, {[ARG_0] = {"addr", 4}, [ARG_1] = {"len", 4}, [ARG_2] = {"prot", 4}, [ARG_3] = {"flags", 4}, [ARG_4] = {"fd", 4}, [ARG_5] = {"pgoffset", 4},}},
	{"move_pages", 344, {[ARG_0] = {"pid", 4}, [ARG_1] = {"nr_pages", 4}, [ARG_2] = {"pages", 4}, [ARG_3] = {"nodes", 4}, [ARG_4] = {"status", 4}, [ARG_5] = {"flag", 4},}},
	{"nfsservctl", 169, {[ARG_0] = {"cmd", 4}, [ARG_1] = {"argp", 4}, [ARG_2] = {"resp", 4},}},
	{"old_getrlimit", 76, {[ARG_0] = {"resource", 4}, [ARG_1] = {"rlim", 4},}},
	{"old_oldumount", 22, {[ARG_0] = {"name", 4},}},
	{"old_select", 82, {[ARG_0] = {"arg", 4},}},
	{"pciconfig_iobase", 271, {[ARG_0] = {"which", 4}, [ARG_1] = {"bus", 4}, [ARG_2] = {"devfn", 4},}},
	{"preadv2", 392, {[ARG_0] = {"fd", 4}, [ARG_1] = {"vec", 4}, [ARG_2] = {"vlen", 4}, [ARG_3] = {"pos_l", 4}, [ARG_4] = {"pos_h", 4}, [ARG_5] = {"flags", 4},}},
	{"pwritev2", 393, {[ARG_0] = {"fd", 4}, [ARG_1] = {"vec", 4}, [ARG_2] = {"vlen", 4}, [ARG_3] = {"pos_l", 4}, [ARG_4] = {"pos_h", 4}, [ARG_5] = {"flags", 4},}},
	{"readdir", 89, {[ARG_0] = {"fd", 4}, [ARG_1] = {"dirent", 4}, [ARG_2] = {"count", 4},}}, // obsolete, no longer available for EABI
	{"rt_sigreturn", 173, {}},
	{"set_mempolicy", 321, {[ARG_0] = {"mode", 4}, [ARG_1] = {"nmask", 4}, [ARG_2] = {"maxnode", 4},}},
	{"set_tls", 983045, {[ARG_0] = {"val", 4},}},
	{"sigreturn", 119, {}},
	{"socketcall", 102, {[ARG_0] = {"call", 4}, [ARG_1] = {"args", 4},}}, // obsolete, no longer available for EABI
	{"statfs64", 266, {[ARG_0] = {"path", 4}, [ARG_1] = {"sz", 4}, [ARG_2] = {"buf", 4},}},
	{"stime", 25, {[ARG_0] = {"tptr", 4},}}, // obsolete, no longer available for EABI
	{"syscall", 113, {}}, // obsolete, no longer available for EABI
	{"time", 13, {[ARG_0] = {"tloc", 4},}}, // obsolete, no longer available for EABI
	{"usr26", 983043, {}},
	{"usr32", 983044, {}},
	{"utime", 30, {[ARG_0] = {"filename", 4}, [ARG_1] = {"times", 4},}},
	{"vserver", 313, {}}, // unimplemented system call

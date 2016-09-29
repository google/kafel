	{"alarm", 27, NORMAL, {[ARG_0] = {"seconds", 4},}}, // obsolete, no longer available for EABI
	{"arm_fadvise64_64", 270, NORMAL, {[ARG_0] = {"fd", 4}, [ARG_1] = {"offset", 8}, [ARG_2] = {"len", 8},}},
	{"breakpoint", 983041, NORMAL, {}},
	{"cacheflush", 983042, NORMAL, {[ARG_0] = {"vaddr_from", 4}, [ARG_1] = {"vaddr_to", 4}, [ARG_2] = {"flags", 4},}},
	{"copy_file_range", 391, NORMAL, {[ARG_0] = {"fd_in", 4}, [ARG_1] = {"off_in", 4}, [ARG_2] = {"fd_out", 4}, [ARG_3] = {"off_out", 4}, [ARG_4] = {"len", 4}, [ARG_5] = {"flags", 4},}},
	{"fstatfs64", 267, NORMAL, {[ARG_0] = {"fd", 4}, [ARG_1] = {"sz", 4}, [ARG_2] = {"buf", 4},}},
	{"get_mempolicy", 320, NORMAL, {[ARG_0] = {"policy", 4}, [ARG_1] = {"nmask", 4}, [ARG_2] = {"maxnode", 4}, [ARG_3] = {"addr", 4}, [ARG_4] = {"flags", 4},}},
	{"ipc", 117, NORMAL, {[ARG_0] = {"call", 4}, [ARG_1] = {"first", 4}, [ARG_2] = {"second", 4}, [ARG_3] = {"third", 4}, [ARG_4] = {"ptr", 4}, [ARG_5] = {"fifth", 4},}}, // obsolete, no longer available for EABI
	{"mbind", 319, NORMAL, {[ARG_0] = {"start", 4}, [ARG_1] = {"len", 4}, [ARG_2] = {"mode", 4}, [ARG_3] = {"nmask", 4}, [ARG_4] = {"maxnode", 4}, [ARG_5] = {"flags", 4},}},
	{"mmap", 90, NORMAL, {[ARG_0] = {"addr", 4}, [ARG_1] = {"len", 4}, [ARG_2] = {"prot", 4}, [ARG_3] = {"flags", 4}, [ARG_4] = {"fd", 4}, [ARG_5] = {"offset", 4},}}, // obsolete, no longer available for EABI
	{"mmap2", 192, NORMAL, {[ARG_0] = {"addr", 4}, [ARG_1] = {"len", 4}, [ARG_2] = {"prot", 4}, [ARG_3] = {"flags", 4}, [ARG_4] = {"fd", 4}, [ARG_5] = {"pgoffset", 4},}},
	{"move_pages", 344, NORMAL, {[ARG_0] = {"pid", 4}, [ARG_1] = {"nr_pages", 4}, [ARG_2] = {"pages", 4}, [ARG_3] = {"nodes", 4}, [ARG_4] = {"status", 4}, [ARG_5] = {"flag", 4},}},
	{"nfsservctl", 169, NORMAL, {[ARG_0] = {"cmd", 4}, [ARG_1] = {"argp", 4}, [ARG_2] = {"resp", 4},}},
	{"old_getrlimit", 76, NORMAL, {[ARG_0] = {"resource", 4}, [ARG_1] = {"rlim", 4},}},
	{"old_oldumount", 22, NORMAL, {[ARG_0] = {"name", 4},}},
	{"old_select", 82, NORMAL, {[ARG_0] = {"arg", 4},}},
	{"pciconfig_iobase", 271, NORMAL, {[ARG_0] = {"which", 4}, [ARG_1] = {"bus", 4}, [ARG_2] = {"devfn", 4},}},
	{"preadv2", 392, NORMAL, {[ARG_0] = {"fd", 4}, [ARG_1] = {"vec", 4}, [ARG_2] = {"vlen", 4}, [ARG_3] = {"pos_l", 4}, [ARG_4] = {"pos_h", 4}, [ARG_5] = {"flags", 4},}},
	{"pwritev2", 393, NORMAL, {[ARG_0] = {"fd", 4}, [ARG_1] = {"vec", 4}, [ARG_2] = {"vlen", 4}, [ARG_3] = {"pos_l", 4}, [ARG_4] = {"pos_h", 4}, [ARG_5] = {"flags", 4},}},
	{"readdir", 89, NORMAL, {[ARG_0] = {"fd", 4}, [ARG_1] = {"dirent", 4}, [ARG_2] = {"count", 4},}}, // obsolete, no longer available for EABI
	{"rt_sigreturn", 173, NORMAL, {}},
	{"set_mempolicy", 321, NORMAL, {[ARG_0] = {"mode", 4}, [ARG_1] = {"nmask", 4}, [ARG_2] = {"maxnode", 4},}},
	{"set_tls", 983045, NORMAL, {[ARG_0] = {"val", 4},}},
	{"sigreturn", 119, NORMAL, {}},
	{"socketcall", 102, NORMAL, {[ARG_0] = {"call", 4}, [ARG_1] = {"args", 4},}}, // obsolete, no longer available for EABI
	{"statfs64", 266, NORMAL, {[ARG_0] = {"path", 4}, [ARG_1] = {"sz", 4}, [ARG_2] = {"buf", 4},}},
	{"stime", 25, NORMAL, {[ARG_0] = {"tptr", 4},}}, // obsolete, no longer available for EABI
	{"syscall", 113, NORMAL, {}}, // obsolete, no longer available for EABI
	{"time", 13, NORMAL, {[ARG_0] = {"tloc", 4},}}, // obsolete, no longer available for EABI
	{"usr26", 983043, NORMAL, {}},
	{"usr32", 983044, NORMAL, {}},
	{"utime", 30, NORMAL, {[ARG_0] = {"filename", 4}, [ARG_1] = {"times", 4},}},
	{"vserver", 313, NORMAL, {}}, // unimplemented system call

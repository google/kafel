	{"adjtimex", 4124, NORMAL, {[ARG_0] = {"txc_p", 4},}},
	{"breakpoint", 983041, NORMAL, {}},
	{"futimesat", 4292, NORMAL, {[ARG_0] = {"dfd", 4}, [ARG_1] = {"filename", 4}, [ARG_2] = {"utimes", 4},}},
	{"getegid16", 50, NORMAL, {}},
	{"geteuid16", 49, NORMAL, {}},
	{"getgid16", 47, NORMAL, {}},
	{"getuid16", 24, NORMAL, {}},
	{"get_mempolicy", 4269, NORMAL, {[ARG_0] = {"policy", 4}, [ARG_1] = {"nmask", 4}, [ARG_2] = {"maxnode", 4}, [ARG_3] = {"addr", 4}, [ARG_4] = {"flags", 4},}},
	{"io_getevents", 4243, NORMAL, {[ARG_0] = {"ctx_id", 4}, [ARG_1] = {"min_nr", 4}, [ARG_2] = {"nr", 4}, [ARG_3] = {"events", 4}, [ARG_4] = {"timeout", 4},}},
	{"mbind", 4268, NORMAL, {[ARG_0] = {"start", 4}, [ARG_1] = {"len", 4}, [ARG_2] = {"mode", 4}, [ARG_3] = {"nmask", 4}, [ARG_4] = {"maxnode", 4}, [ARG_5] = {"flags", 4},}},
	{"mmap", 4090, NORMAL, {[ARG_0] = {"addr", 4}, [ARG_1] = {"len", 4}, [ARG_2] = {"prot", 4}, [ARG_3] = {"flags", 4}, [ARG_4] = {"fd", 4}, [ARG_5] = {"offset", 4},}},  // obsolete, no longer available for EABI
	{"mmap2", 4210, NORMAL, {[ARG_0] = {"addr", 4}, [ARG_1] = {"len", 4}, [ARG_2] = {"prot", 4}, [ARG_3] = {"flags", 4}, [ARG_4] = {"fd", 4}, [ARG_5] = {"pgoffset", 4},}},
	{"move_pages", 4308, NORMAL, {[ARG_0] = {"pid", 4}, [ARG_1] = {"nr_pages", 4}, [ARG_2] = {"pages", 4}, [ARG_3] = {"nodes", 4}, [ARG_4] = {"status", 4}, [ARG_5] = {"flag", 4},}},
	{"nanosleep", 4166, NORMAL, {[ARG_0] = {"rqtp", 4}, [ARG_1] = {"rmtp", 4},}},
	{"nfsservctl", 4189, NORMAL, {[ARG_0] = {"cmd", 4}, [ARG_1] = {"argp", 4}, [ARG_2] = {"resp", 4},}},
	{"pipe", 4042, NORMAL, {[ARG_0] = {"fildes", 4},}},
	{"readdir", 4089, NORMAL, {[ARG_0] = {"fd", 4}, [ARG_1] = {"dirent", 4}, [ARG_2] = {"count", 4},}},  // obsolete, no longer available for EABI
	{"rt_sigreturn", 173, NORMAL, {}},
	{"set_mempolicy", 4270, NORMAL, {[ARG_0] = {"mode", 4}, [ARG_1] = {"nmask", 4}, [ARG_2] = {"maxnode", 4},}},
	{"sigreturn", 119, NORMAL, {}},
	{"stime", 4025, NORMAL, {[ARG_0] = {"tptr", 4},}},  // obsolete, no longer available for EABI
	{"syscall", 113, NORMAL, {}},  // obsolete, no longer available for EABI
	{"time", 4013, NORMAL, {[ARG_0] = {"tloc", 4},}},  // obsolete, no longer available for EABI
	{"uselib", 4086, NORMAL, {[ARG_0] = {"library", 4},}},
	{"usr26", 983043, NORMAL, {}},
	{"usr32", 983044, NORMAL, {}},
	{"utime", 4030, NORMAL, {[ARG_0] = {"filename", 4}, [ARG_1] = {"times", 4},}},
	{"utimes", 4267, NORMAL, {[ARG_0] = {"filename", 4}, [ARG_1] = {"utimes", 4},}},
	{"vfork", 190, NORMAL, {}},
	{"vserver", 313, NORMAL, {}},  // unimplemented system call

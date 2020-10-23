	{"arch_prctl", 158, {[ARG_0] = {"code", 4}, [ARG_1] = {"addr", 8},}},
	{"rt_sigreturn", 15, {}},
	{"uselib", 134, {[ARG_0] = {"library", 8},}},
	{"modify_ldt", 154, {[ARG_0] = {"func", 4}, [ARG_1] = {"ptr", 8}, [ARG_2] = {"bytecount", 8},}},
	{"ioperm", 173, {[ARG_0] = {"from", 8}, [ARG_1] = {"num", 8}, [ARG_2] = {"turn_on", 4},}},
	{"create_module", 174, {[ARG_0] = {"name", 8}, [ARG_1] = {"size", 8},}}, // only in kernels before Linux 2.6
	{"get_kernel_syms", 177, {[ARG_0] = {"table", 8},}}, // only in kernels before Linux 2.6
	{"query_module", 178, {[ARG_0] = {"name", 8}, [ARG_1] = {"which", 4}, [ARG_2] = {"buf", 8}, [ARG_3] = {"bufsize", 8}, [ARG_4] = {"ret", 8},}}, // only in kernels before Linux 2.6
	{"nfsservctl", 180, {[ARG_0] = {"cmd", 4}, [ARG_1] = {"argp", 8}, [ARG_2] = {"resp", 8},}}, // only in kernels before Linux 3.1
	{"getpmsg", 181, {}}, // Unimplemented system call
	{"putpmsg", 182, {}}, // Unimplemented system call
	{"afs_syscall", 183, {}}, // Unimplemented system call
	{"tuxcall", 184, {}}, // Unimplemented system call
	{"security", 185, {}}, // Unimplemented system call
	{"set_thread_area", 205, {[ARG_0] = {"u_info", 8},}},
	{"get_thread_area", 211, {[ARG_0] = {"u_info", 8},}},
	{"epoll_ctl_old", 214, {}}, // old/Unimplemented system call
	{"epoll_wait_old", 215, {}}, // old/Unimplemented system call
	{"vserver", 236, {}}, // Unimplemented system call
	{"copy_file_range", 326, {[ARG_0] = {"fd_in", 4}, [ARG_1] = {"off_in", 8}, [ARG_2] = {"fd_out", 4}, [ARG_3] = {"off_out", 8}, [ARG_4] = {"len", 8}, [ARG_5] = {"flags", 4},}},
	{"preadv2", 327, {[ARG_0] = {"fd", 8}, [ARG_1] = {"vec", 8}, [ARG_2] = {"vlen", 8}, [ARG_3] = {"pos_l", 8}, [ARG_4] = {"pos_h", 8}, [ARG_5] = {"flags", 4},}},
	{"pwritev2", 328, {[ARG_0] = {"fd", 8}, [ARG_1] = {"vec", 8}, [ARG_2] = {"vlen", 8}, [ARG_3] = {"pos_l", 8}, [ARG_4] = {"pos_h", 8}, [ARG_5] = {"flags", 4},}},

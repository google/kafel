	{"fadvise64", 5215, NORMAL, {[ARG_0] = {"fd", 4}, [ARG_1] = {"offset", 8}, [ARG_2] = {"len", 8}, [ARG_3] = {"advice", 4},}},
	{"get_mempolicy", 5228, NORMAL, {[ARG_0] = {"policy", 8}, [ARG_1] = {"nmask", 8}, [ARG_2] = {"maxnode", 8}, [ARG_3] = {"addr", 8}, [ARG_4] = {"flags", 8},}},
	{"mbind", 5227, NORMAL, {[ARG_0] = {"start", 8}, [ARG_1] = {"len", 8}, [ARG_2] = {"mode", 8}, [ARG_3] = {"nmask", 8}, [ARG_4] = {"maxnode", 8}, [ARG_5] = {"flags", 4},}},
	{"migrate_pages", 5246, NORMAL, {[ARG_0] = {"pid", 4}, [ARG_1] = {"maxnode", 8}, [ARG_2] = {"old_nodes", 8}, [ARG_3] = {"new_nodes", 8},}},
	{"mmap", 5009, NORMAL, {[ARG_0] = {"addr", 8}, [ARG_1] = {"len", 8}, [ARG_2] = {"prot", 8}, [ARG_3] = {"flags", 8}, [ARG_4] = {"fd", 8}, [ARG_5] = {"off", 8},}},
	{"move_pages", 5267, NORMAL, {[ARG_0] = {"pid", 4}, [ARG_1] = {"nr_pages", 8}, [ARG_2] = {"pages", 8}, [ARG_3] = {"nodes", 8}, [ARG_4] = {"status", 8}, [ARG_5] = {"flags", 4},}},
	{"msgctl", 5069, NORMAL, {[ARG_0] = {"msqid", 4}, [ARG_1] = {"cmd", 4}, [ARG_2] = {"buf", 8},}},
	{"nfsservctl", 5173, NORMAL, {[ARG_0] = {"cmd", 4}, [ARG_1] = {"argp", 8}, [ARG_2] = {"resp", 8},}},
	{"rt_sigreturn", 139, NORMAL, {}},
	{"semctl", 5064, NORMAL, {[ARG_0] = {"semid", 4}, [ARG_1] = {"semnum", 4}, [ARG_2] = {"cmd", 4}, [ARG_3] = {"arg", 8},}},
	{"sendfile", 71, NORMAL, {[ARG_0] = {"out_fd", 4}, [ARG_1] = {"in_fd", 4}, [ARG_2] = {"offset", 8}, [ARG_3] = {"count", 8},}},
	{"set_mempolicy", 5229, NORMAL, {[ARG_0] = {"mode", 4}, [ARG_1] = {"nmask", 8}, [ARG_2] = {"maxnode", 8},}},
	{"shmctl", 5030, NORMAL, {[ARG_0] = {"shmid", 4}, [ARG_1] = {"cmd", 4}, [ARG_2] = {"buf", 8},}},
	{"sync_file_range2", 84, NORMAL, {[ARG_0] = {"fd", 4}, [ARG_1] = {"offset", 8}, [ARG_2] = {"nbytes", 8},[ARG_3] = {"flags", 4},}},

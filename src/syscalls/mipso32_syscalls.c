/*
   Kafel - syscalls (mipso32)
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

*/

#include <stddef.h>

#include "../syscall.h"

#define ARG_0 0
#define ARG_1 1
#define ARG_2 2
#define ARG_3 3
#define ARG_4 4
#define ARG_5 5

const struct syscall_descriptor mipso32_syscall_list[] = {
    {"accept",
     4168,
     {
         [ARG_0] = {"fd", 4},
         [ARG_1] = {"upeer_sockaddr", 4},
         [ARG_2] = {"upeer_addrlen", 4},
     }},
    {"accept4",
     4334,
     {
         [ARG_0] = {"fd", 4},
         [ARG_1] = {"upeer_sockaddr", 4},
         [ARG_2] = {"upeer_addrlen", 4},
         [ARG_3] = {"flags", 4},
     }},
    {"access",
     4033,
     {
         [ARG_0] = {"filename", 4},
         [ARG_1] = {"mode", 4},
     }},
    {"acct",
     4051,
     {
         [ARG_0] = {"name", 4},
     }},
    {"add_key",
     4280,
     {
         [ARG_0] = {"_type", 4},
         [ARG_1] = {"_description", 4},
         [ARG_2] = {"_payload", 4},
         [ARG_3] = {"plen", 4},
         [ARG_4] = {"ringid", 4},
     }},
    {"adjtimex",
     4124,
     {
         [ARG_0] = {"txc_p", 4},
     }},
    {"alarm",
     4027,
     {
         [ARG_0] = {"seconds", 4},
     }},  // obsolete, no longer available for EABI
          /*
              {"arm_fadvise64_64",
               TEMPLATE_NUM,
               {
                       [ARG_0] = {"fd", 4}, [ARG_1] = {"offset", 8}, [ARG_2] = {"len",
             8},
               }},
          */
    {"bdflush",
     4134,
     {
         [ARG_0] = {"func", 4},
         [ARG_1] = {"data", 4},
     }},
    {"bind",
     4169,
     {
         [ARG_0] = {"fd", 4},
         [ARG_1] = {"umyaddr", 4},
         [ARG_2] = {"addrlen", 4},
     }},
    {"bpf",
     4355,
     {
         [ARG_0] = {"cmd", 4},
         [ARG_1] = {"uattr", 4},
         [ARG_2] = {"size", 4},
     }},
    {"breakpoint", 983041, {}},
    {"brk",
     4045,
     {
         [ARG_0] = {"brk", 4},
     }},
    {"cacheflush",
     4147,
     {
         [ARG_0] = {"vaddr_from", 4},
         [ARG_1] = {"vaddr_to", 4},
         [ARG_2] = {"flags", 4},
     }},
    {"capget",
     4204,
     {
         [ARG_0] = {"header", 4},
         [ARG_1] = {"dataptr", 4},
     }},
    {"capset",
     4205,
     {
         [ARG_0] = {"header", 4},
         [ARG_1] = {"data", 4},
     }},
    {"chdir",
     4012,
     {
         [ARG_0] = {"filename", 4},
     }},
    {"chmod",
     4015,
     {
         [ARG_0] = {"filename", 4},
         [ARG_1] = {"mode", 2},
     }},
    {"chown",
     4202,
     {
         [ARG_0] = {"filename", 4},
         [ARG_1] = {"user", 4},
         [ARG_2] = {"group", 4},
     }},
    /*
        {"chown16",
         TEMPLATE_NUM,
         {
                 [ARG_0] = {"filename", 4}, [ARG_1] = {"user", 2},
                 [ARG_2] = {"group", 2},
         }},
    */
    {"chroot",
     4061,
     {
         [ARG_0] = {"filename", 4},
     }},
    {"clock_adjtime",
     4341,
     {
         [ARG_0] = {"which_clock", 4},
         [ARG_1] = {"utx", 4},
     }},
    {"clock_getres",
     4264,
     {
         [ARG_0] = {"which_clock", 4},
         [ARG_1] = {"tp", 4},
     }},
    {"clock_gettime",
     4263,
     {
         [ARG_0] = {"which_clock", 4},
         [ARG_1] = {"tp", 4},
     }},
    {"clock_nanosleep",
     4265,
     {
         [ARG_0] = {"which_clock", 4},
         [ARG_1] = {"flags", 4},
         [ARG_2] = {"rqtp", 4},
         [ARG_3] = {"rmtp", 4},
     }},
    {"clock_settime",
     4262,
     {
         [ARG_0] = {"which_clock", 4},
         [ARG_1] = {"tp", 4},
     }},
    {"clone",
     4120,
     {
         [ARG_0] = {"clone_flags", 4},
         [ARG_1] = {"newsp", 4},
         [ARG_2] = {"parent_tidptr", 4},
         [ARG_3] = {"tls", 4},
         [ARG_4] = {"child_tidptr", 4},
     }},
    {"close",
     4006,
     {
         [ARG_0] = {"fd", 4},
     }},
    {"connect",
     4170,
     {
         [ARG_0] = {"fd", 4},
         [ARG_1] = {"uservaddr", 4},
         [ARG_2] = {"addrlen", 4},
     }},
    {"copy_file_range",
     4360,
     {
         [ARG_0] = {"fd_in", 4},
         [ARG_1] = {"off_in", 4},
         [ARG_2] = {"fd_out", 4},
         [ARG_3] = {"off_out", 4},
         [ARG_4] = {"len", 4},
         [ARG_5] = {"flags", 4},
     }},
    {"creat",
     4008,
     {
         [ARG_0] = {"pathname", 4},
         [ARG_1] = {"mode", 2},
     }},
    {"delete_module",
     4129,
     {
         [ARG_0] = {"name_user", 4},
         [ARG_1] = {"flags", 4},
     }},
    {"dup",
     4041,
     {
         [ARG_0] = {"fildes", 4},
     }},
    {"dup2",
     4063,
     {
         [ARG_0] = {"oldfd", 4},
         [ARG_1] = {"newfd", 4},
     }},
    {"dup3",
     4327,
     {
         [ARG_0] = {"oldfd", 4},
         [ARG_1] = {"newfd", 4},
         [ARG_2] = {"flags", 4},
     }},
    {"epoll_create",
     4248,
     {
         [ARG_0] = {"size", 4},
     }},
    {"epoll_create1",
     4326,
     {
         [ARG_0] = {"flags", 4},
     }},
    {"epoll_ctl",
     4249,
     {
         [ARG_0] = {"epfd", 4},
         [ARG_1] = {"op", 4},
         [ARG_2] = {"fd", 4},
         [ARG_3] = {"event", 4},
     }},
    {"epoll_pwait",
     4313,
     {
         [ARG_0] = {"epfd", 4},
         [ARG_1] = {"events", 4},
         [ARG_2] = {"maxevents", 4},
         [ARG_3] = {"timeout", 4},
         [ARG_4] = {"sigmask", 4},
         [ARG_5] = {"sigsetsize", 4},
     }},
    {"epoll_wait",
     4250,
     {
         [ARG_0] = {"epfd", 4},
         [ARG_1] = {"events", 4},
         [ARG_2] = {"maxevents", 4},
         [ARG_3] = {"timeout", 4},
     }},
    {"eventfd",
     4319,
     {
         [ARG_0] = {"count", 4},
     }},
    {"eventfd2",
     4325,
     {
         [ARG_0] = {"count", 4},
         [ARG_1] = {"flags", 4},
     }},
    {"execve",
     4011,
     {
         [ARG_0] = {"filename", 4},
         [ARG_1] = {"argv", 4},
         [ARG_2] = {"envp", 4},
     }},
    {"execveat",
     4356,
     {
         [ARG_0] = {"fd", 4},
         [ARG_1] = {"filename", 4},
         [ARG_2] = {"argv", 4},
         [ARG_3] = {"envp", 4},
         [ARG_4] = {"flags", 4},
     }},
    {"exit",
     4001,
     {
         [ARG_0] = {"error_code", 4},
     }},
    {"exit_group",
     4246,
     {
         [ARG_0] = {"error_code", 4},
     }},
    {"faccessat",
     4300,
     {
         [ARG_0] = {"dfd", 4},
         [ARG_1] = {"filename", 4},
         [ARG_2] = {"mode", 4},
     }},
    {"fallocate",
     4320,
     {
         [ARG_0] = {"fd", 4},
         [ARG_1] = {"mode", 4},
         [ARG_2] = {"offset", 8},
         [ARG_3] = {"len", 8},
     }},
    {"fanotify_init",
     4336,
     {
         [ARG_0] = {"flags", 4},
         [ARG_1] = {"event_f_flags", 4},
     }},
    {"fanotify_mark",
     4337,
     {
         [ARG_0] = {"fanotify_fd", 4},
         [ARG_1] = {"flags", 4},
         [ARG_2] = {"mask", 8},
         [ARG_3] = {"dfd", 4},
         [ARG_4] = {"pathname", 4},
     }},
    {"fchdir",
     4133,
     {
         [ARG_0] = {"fd", 4},
     }},
    {"fchmod",
     4094,
     {
         [ARG_0] = {"fd", 4},
         [ARG_1] = {"mode", 2},
     }},
    {"fchmodat",
     4299,
     {
         [ARG_0] = {"dfd", 4},
         [ARG_1] = {"filename", 4},
         [ARG_2] = {"mode", 2},
     }},
    {"fchown",
     4095,
     {
         [ARG_0] = {"fd", 4},
         [ARG_1] = {"user", 4},
         [ARG_2] = {"group", 4},
     }},
    /*
        {"fchown16",
         TEMPLATE_NUM,
         {
                 [ARG_0] = {"fd", 4}, [ARG_1] = {"user", 2}, [ARG_2] = {"group",
       2},
         }},
    */
    {"fchownat",
     4291,
     {
         [ARG_0] = {"dfd", 4},
         [ARG_1] = {"filename", 4},
         [ARG_2] = {"user", 4},
         [ARG_3] = {"group", 4},
         [ARG_4] = {"flag", 4},
     }},
    {"fcntl",
     4055,
     {
         [ARG_0] = {"fd", 4},
         [ARG_1] = {"cmd", 4},
         [ARG_2] = {"arg", 4},
     }},
    {"fcntl64",
     4220,
     {
         [ARG_0] = {"fd", 4},
         [ARG_1] = {"cmd", 4},
         [ARG_2] = {"arg", 4},
     }},
    {"fdatasync",
     4152,
     {
         [ARG_0] = {"fd", 4},
     }},
    {"fgetxattr",
     4229,
     {
         [ARG_0] = {"fd", 4},
         [ARG_1] = {"name", 4},
         [ARG_2] = {"value", 4},
         [ARG_3] = {"size", 4},
     }},
    {"finit_module",
     4348,
     {
         [ARG_0] = {"fd", 4},
         [ARG_1] = {"uargs", 4},
         [ARG_2] = {"flags", 4},
     }},
    {"flistxattr",
     4232,
     {
         [ARG_0] = {"fd", 4},
         [ARG_1] = {"list", 4},
         [ARG_2] = {"size", 4},
     }},
    {"flock",
     4143,
     {
         [ARG_0] = {"fd", 4},
         [ARG_1] = {"cmd", 4},
     }},
    {"fork", 2, {}},
    {"fremovexattr",
     4235,
     {
         [ARG_0] = {"fd", 4},
         [ARG_1] = {"name", 4},
     }},
    {"fsetxattr",
     4226,
     {
         [ARG_0] = {"fd", 4},
         [ARG_1] = {"name", 4},
         [ARG_2] = {"value", 4},
         [ARG_3] = {"size", 4},
         [ARG_4] = {"flags", 4},
     }},
    {"fstat64",
     4215,
     {
         [ARG_0] = {"fd", 4},
         [ARG_1] = {"statbuf", 4},
     }},
    {"fstatat64",
     4293,
     {
         [ARG_0] = {"dfd", 4},
         [ARG_1] = {"filename", 4},
         [ARG_2] = {"statbuf", 4},
         [ARG_3] = {"flag", 4},
     }},
    {"fstatfs",
     4100,
     {
         [ARG_0] = {"fd", 4},
         [ARG_1] = {"buf", 4},
     }},
    {"fstatfs64",
     4256,
     {
         [ARG_0] = {"fd", 4},
         [ARG_1] = {"sz", 4},
         [ARG_2] = {"buf", 4},
     }},
    {"fsync",
     4118,
     {
         [ARG_0] = {"fd", 4},
     }},
    {"ftruncate",
     4093,
     {
         [ARG_0] = {"fd", 4},
         [ARG_1] = {"length", 4},
     }},
    {"ftruncate64",
     4212,
     {
         [ARG_0] = {"fd", 4},
         [ARG_1] = {"length", 8},
     }},
    {"futex",
     4238,
     {
         [ARG_0] = {"uaddr", 4},
         [ARG_1] = {"op", 4},
         [ARG_2] = {"val", 4},
         [ARG_3] = {"utime", 4},
         [ARG_4] = {"uaddr2", 4},
         [ARG_5] = {"val3", 4},
     }},
    {"futimesat",
     4292,
     {
         [ARG_0] = {"dfd", 4},
         [ARG_1] = {"filename", 4},
         [ARG_2] = {"utimes", 4},
     }},
    {"getcpu",
     4312,
     {
         [ARG_0] = {"cpup", 4},
         [ARG_1] = {"nodep", 4},
         [ARG_2] = {"unused", 4},
     }},
    {"getcwd",
     4203,
     {
         [ARG_0] = {"buf", 4},
         [ARG_1] = {"size", 4},
     }},
    {"getdents",
     4141,
     {
         [ARG_0] = {"fd", 4},
         [ARG_1] = {"dirent", 4},
         [ARG_2] = {"count", 4},
     }},
    {"getdents64",
     4219,
     {
         [ARG_0] = {"fd", 4},
         [ARG_1] = {"dirent", 4},
         [ARG_2] = {"count", 4},
     }},
    {"getegid", 202, {}},
    {"getegid16", 50, {}},
    {"geteuid", 201, {}},
    {"geteuid16", 49, {}},
    {"getgid", 200, {}},
    {"getgid16", 47, {}},
    {"getgroups",
     4080,
     {
         [ARG_0] = {"gidsetsize", 4},
         [ARG_1] = {"grouplist", 4},
     }},
    /*
        {"getgroups16",
         TEMPLATE_NUM,
         {
                 [ARG_0] = {"gidsetsize", 4}, [ARG_1] = {"grouplist", 4},
         }},
    */
    {"getitimer",
     4105,
     {
         [ARG_0] = {"which", 4},
         [ARG_1] = {"value", 4},
     }},
    {"get_mempolicy",
     4269,
     {
         [ARG_0] = {"policy", 4},
         [ARG_1] = {"nmask", 4},
         [ARG_2] = {"maxnode", 4},
         [ARG_3] = {"addr", 4},
         [ARG_4] = {"flags", 4},
     }},
    {"getpeername",
     4171,
     {
         [ARG_0] = {"fd", 4},
         [ARG_1] = {"usockaddr", 4},
         [ARG_2] = {"usockaddr_len", 4},
     }},
    {"getpgid",
     4132,
     {
         [ARG_0] = {"pid", 4},
     }},
    {"getpgrp", 65, {}},
    {"getpid", 20, {}},
    {"getppid", 64, {}},
    {"getpriority",
     4096,
     {
         [ARG_0] = {"which", 4},
         [ARG_1] = {"who", 4},
     }},
    {"getrandom",
     4353,
     {
         [ARG_0] = {"buf", 4},
         [ARG_1] = {"count", 4},
         [ARG_2] = {"flags", 4},
     }},
    {"getresgid",
     4191,
     {
         [ARG_0] = {"rgidp", 4},
         [ARG_1] = {"egidp", 4},
         [ARG_2] = {"sgidp", 4},
     }},
    /*
        {"getresgid16",
         TEMPLATE_NUM,
         {
                 [ARG_0] = {"rgidp", 4}, [ARG_1] = {"egidp", 4},
                 [ARG_2] = {"sgidp", 4},
         }},
    */
    {"getresuid",
     4186,
     {
         [ARG_0] = {"ruidp", 4},
         [ARG_1] = {"euidp", 4},
         [ARG_2] = {"suidp", 4},
     }},
    /*
        {"getresuid16",
         TEMPLATE_NUM,
         {
                 [ARG_0] = {"ruidp", 4}, [ARG_1] = {"euidp", 4},
                 [ARG_2] = {"suidp", 4},
         }},
    */
    {"getrlimit",
     4076,
     {
         [ARG_0] = {"resource", 4},
         [ARG_1] = {"rlim", 4},
     }},
    {"get_robust_list",
     4310,
     {
         [ARG_0] = {"pid", 4},
         [ARG_1] = {"head_ptr", 4},
         [ARG_2] = {"len_ptr", 4},
     }},
    {"getrusage",
     4077,
     {
         [ARG_0] = {"who", 4},
         [ARG_1] = {"ru", 4},
     }},
    {"getsid",
     4151,
     {
         [ARG_0] = {"pid", 4},
     }},
    {"getsockname",
     4172,
     {
         [ARG_0] = {"fd", 4},
         [ARG_1] = {"usockaddr", 4},
         [ARG_2] = {"usockaddr_len", 4},
     }},
    {"getsockopt",
     4173,
     {
         [ARG_0] = {"fd", 4},
         [ARG_1] = {"level", 4},
         [ARG_2] = {"optname", 4},
         [ARG_3] = {"optval", 4},
         [ARG_4] = {"optlen", 4},
     }},
    {"gettid", 224, {}},
    {"gettimeofday",
     4078,
     {
         [ARG_0] = {"tv", 4},
         [ARG_1] = {"tz", 4},
     }},
    {"getuid", 199, {}},
    {"getuid16", 24, {}},
    {"getxattr",
     4227,
     {
         [ARG_0] = {"pathname", 4},
         [ARG_1] = {"name", 4},
         [ARG_2] = {"value", 4},
         [ARG_3] = {"size", 4},
     }},
    {"init_module",
     4128,
     {
         [ARG_0] = {"umod", 4},
         [ARG_1] = {"len", 4},
         [ARG_2] = {"uargs", 4},
     }},
    {"inotify_add_watch",
     4285,
     {
         [ARG_0] = {"fd", 4},
         [ARG_1] = {"pathname", 4},
         [ARG_2] = {"mask", 4},
     }},
    {"inotify_init", 316, {}},
    {"inotify_init1",
     4329,
     {
         [ARG_0] = {"flags", 4},
     }},
    {"inotify_rm_watch",
     4286,
     {
         [ARG_0] = {"fd", 4},
         [ARG_1] = {"wd", 4},
     }},
    {"io_cancel",
     4245,
     {
         [ARG_0] = {"ctx_id", 4},
         [ARG_1] = {"iocb", 4},
         [ARG_2] = {"result", 4},
     }},
    {"ioctl",
     4054,
     {
         [ARG_0] = {"fd", 4},
         [ARG_1] = {"cmd", 4},
         [ARG_2] = {"arg", 4},
     }},
    {"io_destroy",
     4242,
     {
         [ARG_0] = {"ctx", 4},
     }},
    {"io_getevents",
     4243,
     {
         [ARG_0] = {"ctx_id", 4},
         [ARG_1] = {"min_nr", 4},
         [ARG_2] = {"nr", 4},
         [ARG_3] = {"events", 4},
         [ARG_4] = {"timeout", 4},
     }},
    {"ioprio_get",
     4315,
     {
         [ARG_0] = {"which", 4},
         [ARG_1] = {"who", 4},
     }},
    {"ioprio_set",
     4314,
     {
         [ARG_0] = {"which", 4},
         [ARG_1] = {"who", 4},
         [ARG_2] = {"ioprio", 4},
     }},
    {"io_setup",
     4241,
     {
         [ARG_0] = {"nr_events", 4},
         [ARG_1] = {"ctxp", 4},
     }},
    {"io_submit",
     4244,
     {
         [ARG_0] = {"ctx_id", 4},
         [ARG_1] = {"nr", 4},
         [ARG_2] = {"iocbpp", 4},
     }},
    {"ipc",
     4117,
     {
         [ARG_0] = {"call", 4},
         [ARG_1] = {"first", 4},
         [ARG_2] = {"second", 4},
         [ARG_3] = {"third", 4},
         [ARG_4] = {"ptr", 4},
         [ARG_5] = {"fifth", 4},
     }},  // obsolete, no longer available for EABI
    {"kcmp",
     4347,
     {
         [ARG_0] = {"pid1", 4},
         [ARG_1] = {"pid2", 4},
         [ARG_2] = {"type", 4},
         [ARG_3] = {"idx1", 4},
         [ARG_4] = {"idx2", 4},
     }},
    {"kexec_load",
     4311,
     {
         [ARG_0] = {"entry", 4},
         [ARG_1] = {"nr_segments", 4},
         [ARG_2] = {"segments", 4},
         [ARG_3] = {"flags", 4},
     }},
    {"keyctl",
     4282,
     {
         [ARG_0] = {"option", 4},
         [ARG_1] = {"arg2", 4},
         [ARG_2] = {"arg3", 4},
         [ARG_3] = {"arg4", 4},
         [ARG_4] = {"arg5", 4},
     }},
    {"kill",
     4037,
     {
         [ARG_0] = {"pid", 4},
         [ARG_1] = {"sig", 4},
     }},
    {"lchown",
     4016,
     {
         [ARG_0] = {"filename", 4},
         [ARG_1] = {"user", 4},
         [ARG_2] = {"group", 4},
     }},
    /*
        {"lchown16",
         TEMPLATE_NUM,
         {
                 [ARG_0] = {"filename", 4}, [ARG_1] = {"user", 2},
                 [ARG_2] = {"group", 2},
         }},
    */
    {"lgetxattr",
     4228,
     {
         [ARG_0] = {"pathname", 4},
         [ARG_1] = {"name", 4},
         [ARG_2] = {"value", 4},
         [ARG_3] = {"size", 4},
     }},
    {"link",
     4009,
     {
         [ARG_0] = {"oldname", 4},
         [ARG_1] = {"newname", 4},
     }},
    {"linkat",
     4296,
     {
         [ARG_0] = {"olddfd", 4},
         [ARG_1] = {"oldname", 4},
         [ARG_2] = {"newdfd", 4},
         [ARG_3] = {"newname", 4},
         [ARG_4] = {"flags", 4},
     }},
    {"listen",
     4174,
     {
         [ARG_0] = {"fd", 4},
         [ARG_1] = {"backlog", 4},
     }},
    {"listxattr",
     4230,
     {
         [ARG_0] = {"pathname", 4},
         [ARG_1] = {"list", 4},
         [ARG_2] = {"size", 4},
     }},
    {"llistxattr",
     4231,
     {
         [ARG_0] = {"pathname", 4},
         [ARG_1] = {"list", 4},
         [ARG_2] = {"size", 4},
     }},
    /*
        {"llseek",
         TEMPLATE_NUM,
         {
                 [ARG_0] = {"fd", 4}, [ARG_1] = {"offset_high", 4},
                 [ARG_2] = {"offset_low", 4}, [ARG_3] = {"result", 4},
                 [ARG_4] = {"whence", 4},
         }},
    */
    {"lookup_dcookie",
     4247,
     {
         [ARG_0] = {"cookie64", 8},
         [ARG_1] = {"buf", 4},
         [ARG_2] = {"len", 4},
     }},
    {"lremovexattr",
     4234,
     {
         [ARG_0] = {"pathname", 4},
         [ARG_1] = {"name", 4},
     }},
    {"lseek",
     4019,
     {
         [ARG_0] = {"fd", 4},
         [ARG_1] = {"offset", 4},
         [ARG_2] = {"whence", 4},
     }},
    {"lsetxattr",
     4225,
     {
         [ARG_0] = {"pathname", 4},
         [ARG_1] = {"name", 4},
         [ARG_2] = {"value", 4},
         [ARG_3] = {"size", 4},
         [ARG_4] = {"flags", 4},
     }},
    {"lstat64",
     4214,
     {
         [ARG_0] = {"filename", 4},
         [ARG_1] = {"statbuf", 4},
     }},
    {"madvise",
     4218,
     {
         [ARG_0] = {"start", 4},
         [ARG_1] = {"len_in", 4},
         [ARG_2] = {"behavior", 4},
     }},
    {"mbind",
     4268,
     {
         [ARG_0] = {"start", 4},
         [ARG_1] = {"len", 4},
         [ARG_2] = {"mode", 4},
         [ARG_3] = {"nmask", 4},
         [ARG_4] = {"maxnode", 4},
         [ARG_5] = {"flags", 4},
     }},
    {"membarrier",
     4358,
     {
         [ARG_0] = {"cmd", 4},
         [ARG_1] = {"flags", 4},
     }},
    {"memfd_create",
     4354,
     {
         [ARG_0] = {"uname", 4},
         [ARG_1] = {"flags", 4},
     }},
    {"mincore",
     4217,
     {
         [ARG_0] = {"start", 4},
         [ARG_1] = {"len", 4},
         [ARG_2] = {"vec", 4},
     }},
    {"mkdir",
     4039,
     {
         [ARG_0] = {"pathname", 4},
         [ARG_1] = {"mode", 2},
     }},
    {"mkdirat",
     4289,
     {
         [ARG_0] = {"dfd", 4},
         [ARG_1] = {"pathname", 4},
         [ARG_2] = {"mode", 2},
     }},
    {"mknod",
     4014,
     {
         [ARG_0] = {"filename", 4},
         [ARG_1] = {"mode", 2},
         [ARG_2] = {"dev", 4},
     }},
    {"mknodat",
     4290,
     {
         [ARG_0] = {"dfd", 4},
         [ARG_1] = {"filename", 4},
         [ARG_2] = {"mode", 2},
         [ARG_3] = {"dev", 4},
     }},
    {"mlock",
     4154,
     {
         [ARG_0] = {"start", 4},
         [ARG_1] = {"len", 4},
     }},
    {"mlock2",
     4359,
     {
         [ARG_0] = {"start", 4},
         [ARG_1] = {"len", 4},
         [ARG_2] = {"flags", 4},
     }},
    {"mlockall",
     4156,
     {
         [ARG_0] = {"flags", 4},
     }},
    {"mmap",
     4090,
     {
         [ARG_0] = {"addr", 4},
         [ARG_1] = {"len", 4},
         [ARG_2] = {"prot", 4},
         [ARG_3] = {"flags", 4},
         [ARG_4] = {"fd", 4},
         [ARG_5] = {"offset", 4},
     }},  // obsolete, no longer available for EABI
    {"mmap2",
     4210,
     {
         [ARG_0] = {"addr", 4},
         [ARG_1] = {"len", 4},
         [ARG_2] = {"prot", 4},
         [ARG_3] = {"flags", 4},
         [ARG_4] = {"fd", 4},
         [ARG_5] = {"pgoffset", 4},
     }},
    {"mount",
     4021,
     {
         [ARG_0] = {"dev_name", 4},
         [ARG_1] = {"dir_name", 4},
         [ARG_2] = {"type", 4},
         [ARG_3] = {"flags", 4},
         [ARG_4] = {"data", 4},
     }},
    {"move_pages",
     4308,
     {
         [ARG_0] = {"pid", 4},
         [ARG_1] = {"nr_pages", 4},
         [ARG_2] = {"pages", 4},
         [ARG_3] = {"nodes", 4},
         [ARG_4] = {"status", 4},
         [ARG_5] = {"flag", 4},
     }},
    {"mprotect",
     4125,
     {
         [ARG_0] = {"start", 4},
         [ARG_1] = {"len", 4},
         [ARG_2] = {"prot", 4},
     }},
    {"mq_getsetattr",
     4276,
     {
         [ARG_0] = {"mqdes", 4},
         [ARG_1] = {"u_mqstat", 4},
         [ARG_2] = {"u_omqstat", 4},
     }},
    {"mq_notify",
     4275,
     {
         [ARG_0] = {"mqdes", 4},
         [ARG_1] = {"u_notification", 4},
     }},
    {"mq_open",
     4271,
     {
         [ARG_0] = {"u_name", 4},
         [ARG_1] = {"oflag", 4},
         [ARG_2] = {"mode", 2},
         [ARG_3] = {"u_attr", 4},
     }},
    {"mq_timedreceive",
     4274,
     {
         [ARG_0] = {"mqdes", 4},
         [ARG_1] = {"u_msg_ptr", 4},
         [ARG_2] = {"msg_len", 4},
         [ARG_3] = {"u_msg_prio", 4},
         [ARG_4] = {"u_abs_timeout", 4},
     }},
    {"mq_timedsend",
     4273,
     {
         [ARG_0] = {"mqdes", 4},
         [ARG_1] = {"u_msg_ptr", 4},
         [ARG_2] = {"msg_len", 4},
         [ARG_3] = {"msg_prio", 4},
         [ARG_4] = {"u_abs_timeout", 4},
     }},
    {"mq_unlink",
     4272,
     {
         [ARG_0] = {"u_name", 4},
     }},
    {"mremap",
     4167,
     {
         [ARG_0] = {"addr", 4},
         [ARG_1] = {"old_len", 4},
         [ARG_2] = {"new_len", 4},
         [ARG_3] = {"flags", 4},
         [ARG_4] = {"new_addr", 4},
     }},
    /*
        {"msgctl",
         TEMPLATE_NUM,
         {
                 [ARG_0] = {"msqid", 4}, [ARG_1] = {"cmd", 4}, [ARG_2] = {"buf",
       4},
         }},
    */
    /*
        {"msgget",
         TEMPLATE_NUM,
         {
                 [ARG_0] = {"key", 4}, [ARG_1] = {"msgflg", 4},
         }},
    */
    /*
        {"msgrcv",
         TEMPLATE_NUM,
         {
                 [ARG_0] = {"msqid", 4}, [ARG_1] = {"msgp", 4},
                 [ARG_2] = {"msgsz", 4}, [ARG_3] = {"msgtyp", 4},
                 [ARG_4] = {"msgflg", 4},
         }},
    */
    /*
        {"msgsnd",
         TEMPLATE_NUM,
         {
                 [ARG_0] = {"msqid", 4}, [ARG_1] = {"msgp", 4},
                 [ARG_2] = {"msgsz", 4}, [ARG_3] = {"msgflg", 4},
         }},
    */
    {"msync",
     4144,
     {
         [ARG_0] = {"start", 4},
         [ARG_1] = {"len", 4},
         [ARG_2] = {"flags", 4},
     }},
    {"munlock",
     4155,
     {
         [ARG_0] = {"start", 4},
         [ARG_1] = {"len", 4},
     }},
    {"munlockall", 153, {}},
    {"munmap",
     4091,
     {
         [ARG_0] = {"addr", 4},
         [ARG_1] = {"len", 4},
     }},
    {"name_to_handle_at",
     4339,
     {
         [ARG_0] = {"dfd", 4},
         [ARG_1] = {"name", 4},
         [ARG_2] = {"handle", 4},
         [ARG_3] = {"mnt_id", 4},
         [ARG_4] = {"flag", 4},
     }},
    {"nanosleep",
     4166,
     {
         [ARG_0] = {"rqtp", 4},
         [ARG_1] = {"rmtp", 4},
     }},
    /*
        {"newfstat",
         TEMPLATE_NUM,
         {
                 [ARG_0] = {"fd", 4}, [ARG_1] = {"statbuf", 4},
         }},
    */
    /*
        {"newlstat",
         TEMPLATE_NUM,
         {
                 [ARG_0] = {"filename", 4}, [ARG_1] = {"statbuf", 4},
         }},
    */
    /*
        {"newstat",
         TEMPLATE_NUM,
         {
                 [ARG_0] = {"filename", 4}, [ARG_1] = {"statbuf", 4},
         }},
    */
    /*
        {"newuname",
         TEMPLATE_NUM,
         {
                 [ARG_0] = {"name", 4},
         }},
    */
    {"nfsservctl",
     4189,
     {
         [ARG_0] = {"cmd", 4},
         [ARG_1] = {"argp", 4},
         [ARG_2] = {"resp", 4},
     }},
    {"nice",
     4034,
     {
         [ARG_0] = {"increment", 4},
     }},
    /*
        {"old_getrlimit",
         TEMPLATE_NUM,
         {
                 [ARG_0] = {"resource", 4}, [ARG_1] = {"rlim", 4},
         }},
    */
    /*
        {"old_oldumount",
         TEMPLATE_NUM,
         {
                 [ARG_0] = {"name", 4},
         }},
    */
    /*
        {"old_select",
         TEMPLATE_NUM,
         {
                 [ARG_0] = {"arg", 4},
         }},
    */
    {"open",
     4005,
     {
         [ARG_0] = {"filename", 4},
         [ARG_1] = {"flags", 4},
         [ARG_2] = {"mode", 2},
     }},
    {"openat",
     4288,
     {
         [ARG_0] = {"dfd", 4},
         [ARG_1] = {"filename", 4},
         [ARG_2] = {"flags", 4},
         [ARG_3] = {"mode", 2},
     }},
    {"open_by_handle_at",
     4340,
     {
         [ARG_0] = {"mountdirfd", 4},
         [ARG_1] = {"handle", 4},
         [ARG_2] = {"flags", 4},
     }},
    {"pause", 29, {}},
    /*
        {"pciconfig_iobase",
         TEMPLATE_NUM,
         {
                 [ARG_0] = {"which", 4}, [ARG_1] = {"bus", 4},
                 [ARG_2] = {"devfn", 4},
         }},
    */
    /*
        {"pciconfig_read",
         TEMPLATE_NUM,
         {
                 [ARG_0] = {"bus", 4}, [ARG_1] = {"dfn", 4}, [ARG_2] = {"off",
       4}, [ARG_3] = {"len", 4}, [ARG_4] = {"buf", 4},
         }},
    */
    /*
        {"pciconfig_write",
         TEMPLATE_NUM,
         {
                 [ARG_0] = {"bus", 4}, [ARG_1] = {"dfn", 4}, [ARG_2] = {"off",
       4}, [ARG_3] = {"len", 4}, [ARG_4] = {"buf", 4},
         }},
    */
    {"perf_event_open",
     4333,
     {
         [ARG_0] = {"attr_uptr", 4},
         [ARG_1] = {"pid", 4},
         [ARG_2] = {"cpu", 4},
         [ARG_3] = {"group_fd", 4},
         [ARG_4] = {"flags", 4},
     }},
    {"personality",
     4136,
     {
         [ARG_0] = {"personality", 4},
     }},
    {"pipe",
     4042,
     {
         [ARG_0] = {"fildes", 4},
     }},
    {"pipe2",
     4328,
     {
         [ARG_0] = {"fildes", 4},
         [ARG_1] = {"flags", 4},
     }},
    {"pivot_root",
     4216,
     {
         [ARG_0] = {"new_root", 4},
         [ARG_1] = {"put_old", 4},
     }},
    {"poll",
     4188,
     {
         [ARG_0] = {"ufds", 4},
         [ARG_1] = {"nfds", 4},
         [ARG_2] = {"timeout_msecs", 4},
     }},
    {"ppoll",
     4302,
     {
         [ARG_0] = {"ufds", 4},
         [ARG_1] = {"nfds", 4},
         [ARG_2] = {"tsp", 4},
         [ARG_3] = {"sigmask", 4},
         [ARG_4] = {"sigsetsize", 4},
     }},
    {"prctl",
     4192,
     {
         [ARG_0] = {"option", 4},
         [ARG_1] = {"arg2", 4},
         [ARG_2] = {"arg3", 4},
         [ARG_3] = {"arg4", 4},
         [ARG_4] = {"arg5", 4},
     }},
    {"pread64",
     4200,
     {
         [ARG_0] = {"fd", 4},
         [ARG_1] = {"buf", 4},
         [ARG_2] = {"count", 4},
         [ARG_3] = {"pos", 8},
     }},
    {"preadv",
     4330,
     {
         [ARG_0] = {"fd", 4},
         [ARG_1] = {"vec", 4},
         [ARG_2] = {"vlen", 4},
         [ARG_3] = {"pos_l", 4},
         [ARG_4] = {"pos_h", 4},
     }},
    {"preadv2",
     4361,
     {
         [ARG_0] = {"fd", 4},
         [ARG_1] = {"vec", 4},
         [ARG_2] = {"vlen", 4},
         [ARG_3] = {"pos_l", 4},
         [ARG_4] = {"pos_h", 4},
         [ARG_5] = {"flags", 4},
     }},
    {"prlimit64",
     4338,
     {
         [ARG_0] = {"pid", 4},
         [ARG_1] = {"resource", 4},
         [ARG_2] = {"new_rlim", 4},
         [ARG_3] = {"old_rlim", 4},
     }},
    {"process_vm_readv",
     4345,
     {
         [ARG_0] = {"pid", 4},
         [ARG_1] = {"lvec", 4},
         [ARG_2] = {"liovcnt", 4},
         [ARG_3] = {"rvec", 4},
         [ARG_4] = {"riovcnt", 4},
         [ARG_5] = {"flags", 4},
     }},
    {"process_vm_writev",
     4346,
     {
         [ARG_0] = {"pid", 4},
         [ARG_1] = {"lvec", 4},
         [ARG_2] = {"liovcnt", 4},
         [ARG_3] = {"rvec", 4},
         [ARG_4] = {"riovcnt", 4},
         [ARG_5] = {"flags", 4},
     }},
    {"pselect6",
     4301,
     {
         [ARG_0] = {"n", 4},
         [ARG_1] = {"inp", 4},
         [ARG_2] = {"outp", 4},
         [ARG_3] = {"exp", 4},
         [ARG_4] = {"tsp", 4},
         [ARG_5] = {"sig", 4},
     }},
    {"ptrace",
     4026,
     {
         [ARG_0] = {"request", 4},
         [ARG_1] = {"pid", 4},
         [ARG_2] = {"addr", 4},
         [ARG_3] = {"data", 4},
     }},
    {"pwrite64",
     4201,
     {
         [ARG_0] = {"fd", 4},
         [ARG_1] = {"buf", 4},
         [ARG_2] = {"count", 4},
         [ARG_3] = {"pos", 8},
     }},
    {"pwritev",
     4331,
     {
         [ARG_0] = {"fd", 4},
         [ARG_1] = {"vec", 4},
         [ARG_2] = {"vlen", 4},
         [ARG_3] = {"pos_l", 4},
         [ARG_4] = {"pos_h", 4},
     }},
    {"pwritev2",
     4362,
     {
         [ARG_0] = {"fd", 4},
         [ARG_1] = {"vec", 4},
         [ARG_2] = {"vlen", 4},
         [ARG_3] = {"pos_l", 4},
         [ARG_4] = {"pos_h", 4},
         [ARG_5] = {"flags", 4},
     }},
    {"quotactl",
     4131,
     {
         [ARG_0] = {"cmd", 4},
         [ARG_1] = {"special", 4},
         [ARG_2] = {"id", 4},
         [ARG_3] = {"addr", 4},
     }},
    {"read",
     4003,
     {
         [ARG_0] = {"fd", 4},
         [ARG_1] = {"buf", 4},
         [ARG_2] = {"count", 4},
     }},
    {"readahead",
     4223,
     {
         [ARG_0] = {"fd", 4},
         [ARG_1] = {"offset", 8},
         [ARG_2] = {"count", 4},
     }},
    {"readdir",
     4089,
     {
         [ARG_0] = {"fd", 4},
         [ARG_1] = {"dirent", 4},
         [ARG_2] = {"count", 4},
     }},  // obsolete, no longer available for EABI
    {"readlink",
     4085,
     {
         [ARG_0] = {"path", 4},
         [ARG_1] = {"buf", 4},
         [ARG_2] = {"bufsiz", 4},
     }},
    {"readlinkat",
     4298,
     {
         [ARG_0] = {"dfd", 4},
         [ARG_1] = {"pathname", 4},
         [ARG_2] = {"buf", 4},
         [ARG_3] = {"bufsiz", 4},
     }},
    {"readv",
     4145,
     {
         [ARG_0] = {"fd", 4},
         [ARG_1] = {"vec", 4},
         [ARG_2] = {"vlen", 4},
     }},
    {"reboot",
     4088,
     {
         [ARG_0] = {"magic1", 4},
         [ARG_1] = {"magic2", 4},
         [ARG_2] = {"cmd", 4},
         [ARG_3] = {"arg", 4},
     }},
    {"recv",
     4175,
     {
         [ARG_0] = {"fd", 4},
         [ARG_1] = {"ubuf", 4},
         [ARG_2] = {"size", 4},
         [ARG_3] = {"flags", 4},
     }},
    {"recvfrom",
     4176,
     {
         [ARG_0] = {"fd", 4},
         [ARG_1] = {"ubuf", 4},
         [ARG_2] = {"size", 4},
         [ARG_3] = {"flags", 4},
         [ARG_4] = {"addr", 4},
         [ARG_5] = {"addr_len", 4},
     }},
    {"recvmmsg",
     4335,
     {
         [ARG_0] = {"fd", 4},
         [ARG_1] = {"mmsg", 4},
         [ARG_2] = {"vlen", 4},
         [ARG_3] = {"flags", 4},
         [ARG_4] = {"timeout", 4},
     }},
    {"recvmsg",
     4177,
     {
         [ARG_0] = {"fd", 4},
         [ARG_1] = {"msg", 4},
         [ARG_2] = {"flags", 4},
     }},
    {"remap_file_pages",
     4251,
     {
         [ARG_0] = {"start", 4},
         [ARG_1] = {"size", 4},
         [ARG_2] = {"prot", 4},
         [ARG_3] = {"pgoff", 4},
         [ARG_4] = {"flags", 4},
     }},
    {"removexattr",
     4233,
     {
         [ARG_0] = {"pathname", 4},
         [ARG_1] = {"name", 4},
     }},
    {"rename",
     4038,
     {
         [ARG_0] = {"oldname", 4},
         [ARG_1] = {"newname", 4},
     }},
    {"renameat",
     4295,
     {
         [ARG_0] = {"olddfd", 4},
         [ARG_1] = {"oldname", 4},
         [ARG_2] = {"newdfd", 4},
         [ARG_3] = {"newname", 4},
     }},
    {"renameat2",
     4351,
     {
         [ARG_0] = {"olddfd", 4},
         [ARG_1] = {"oldname", 4},
         [ARG_2] = {"newdfd", 4},
         [ARG_3] = {"newname", 4},
         [ARG_4] = {"flags", 4},
     }},
    {"request_key",
     4281,
     {
         [ARG_0] = {"_type", 4},
         [ARG_1] = {"_description", 4},
         [ARG_2] = {"_callout_info", 4},
         [ARG_3] = {"destringid", 4},
     }},
    {"restart_syscall", 0, {}},
    {"rmdir",
     4040,
     {
         [ARG_0] = {"pathname", 4},
     }},
    {"rt_sigaction",
     4194,
     {
         [ARG_0] = {"sig", 4},
         [ARG_1] = {"act", 4},
         [ARG_2] = {"oact", 4},
         [ARG_3] = {"sigsetsize", 4},
     }},
    {"rt_sigpending",
     4196,
     {
         [ARG_0] = {"uset", 4},
         [ARG_1] = {"sigsetsize", 4},
     }},
    {"rt_sigprocmask",
     4195,
     {
         [ARG_0] = {"how", 4},
         [ARG_1] = {"nset", 4},
         [ARG_2] = {"oset", 4},
         [ARG_3] = {"sigsetsize", 4},
     }},
    {"rt_sigqueueinfo",
     4198,
     {
         [ARG_0] = {"pid", 4},
         [ARG_1] = {"sig", 4},
         [ARG_2] = {"uinfo", 4},
     }},
    {"rt_sigreturn", 173, {}},
    {"rt_sigsuspend",
     4199,
     {
         [ARG_0] = {"unewset", 4},
         [ARG_1] = {"sigsetsize", 4},
     }},
    {"rt_sigtimedwait",
     4197,
     {
         [ARG_0] = {"uthese", 4},
         [ARG_1] = {"uinfo", 4},
         [ARG_2] = {"uts", 4},
         [ARG_3] = {"sigsetsize", 4},
     }},
    {"rt_tgsigqueueinfo",
     4332,
     {
         [ARG_0] = {"tgid", 4},
         [ARG_1] = {"pid", 4},
         [ARG_2] = {"sig", 4},
         [ARG_3] = {"uinfo", 4},
     }},
    {"sched_getaffinity",
     4240,
     {
         [ARG_0] = {"pid", 4},
         [ARG_1] = {"len", 4},
         [ARG_2] = {"user_mask_ptr", 4},
     }},
    {"sched_getattr",
     4350,
     {
         [ARG_0] = {"pid", 4},
         [ARG_1] = {"uattr", 4},
         [ARG_2] = {"size", 4},
         [ARG_3] = {"flags", 4},
     }},
    {"sched_getparam",
     4159,
     {
         [ARG_0] = {"pid", 4},
         [ARG_1] = {"param", 4},
     }},
    {"sched_get_priority_max",
     4163,
     {
         [ARG_0] = {"policy", 4},
     }},
    {"sched_get_priority_min",
     4164,
     {
         [ARG_0] = {"policy", 4},
     }},
    {"sched_getscheduler",
     4161,
     {
         [ARG_0] = {"pid", 4},
     }},
    {"sched_rr_get_interval",
     4165,
     {
         [ARG_0] = {"pid", 4},
         [ARG_1] = {"interval", 4},
     }},
    {"sched_setaffinity",
     4239,
     {
         [ARG_0] = {"pid", 4},
         [ARG_1] = {"len", 4},
         [ARG_2] = {"user_mask_ptr", 4},
     }},
    {"sched_setattr",
     4349,
     {
         [ARG_0] = {"pid", 4},
         [ARG_1] = {"uattr", 4},
         [ARG_2] = {"flags", 4},
     }},
    {"sched_setparam",
     4158,
     {
         [ARG_0] = {"pid", 4},
         [ARG_1] = {"param", 4},
     }},
    {"sched_setscheduler",
     4160,
     {
         [ARG_0] = {"pid", 4},
         [ARG_1] = {"policy", 4},
         [ARG_2] = {"param", 4},
     }},
    {"sched_yield", 158, {}},
    {"seccomp",
     4352,
     {
         [ARG_0] = {"op", 4},
         [ARG_1] = {"flags", 4},
         [ARG_2] = {"uargs", 4},
     }},
    /*
        {"select",
         TEMPLATE_NUM,
         {
                 [ARG_0] = {"n", 4}, [ARG_1] = {"inp", 4}, [ARG_2] = {"outp",
       4}, [ARG_3] = {"exp", 4}, [ARG_4] = {"tvp", 4},
         }},
    */
    /*
        {"semctl",
         TEMPLATE_NUM,
         {
                 [ARG_0] = {"semid", 4}, [ARG_1] = {"semnum", 4},
                 [ARG_2] = {"cmd", 4}, [ARG_3] = {"arg", 4},
         }},
    */
    /*
        {"semget",
         TEMPLATE_NUM,
         {
                 [ARG_0] = {"key", 4}, [ARG_1] = {"nsems", 4},
                 [ARG_2] = {"semflg", 4},
         }},
    */
    /*
        {"semop",
         TEMPLATE_NUM,
         {
                 [ARG_0] = {"semid", 4}, [ARG_1] = {"tsops", 4},
                 [ARG_2] = {"nsops", 4},
         }},
    */
    /*
        {"semtimedop",
         TEMPLATE_NUM,
         {
                 [ARG_0] = {"semid", 4}, [ARG_1] = {"tsops", 4},
                 [ARG_2] = {"nsops", 4}, [ARG_3] = {"timeout", 4},
         }},
    */
    {"send",
     4178,
     {
         [ARG_0] = {"fd", 4},
         [ARG_1] = {"buff", 4},
         [ARG_2] = {"len", 4},
         [ARG_3] = {"flags", 4},
     }},
    {"sendfile",
     4207,
     {
         [ARG_0] = {"out_fd", 4},
         [ARG_1] = {"in_fd", 4},
         [ARG_2] = {"offset", 4},
         [ARG_3] = {"count", 4},
     }},
    {"sendfile64",
     4237,
     {
         [ARG_0] = {"out_fd", 4},
         [ARG_1] = {"in_fd", 4},
         [ARG_2] = {"offset", 4},
         [ARG_3] = {"count", 4},
     }},
    {"sendmmsg",
     4343,
     {
         [ARG_0] = {"fd", 4},
         [ARG_1] = {"mmsg", 4},
         [ARG_2] = {"vlen", 4},
         [ARG_3] = {"flags", 4},
     }},
    {"sendmsg",
     4179,
     {
         [ARG_0] = {"fd", 4},
         [ARG_1] = {"msg", 4},
         [ARG_2] = {"flags", 4},
     }},
    {"sendto",
     4180,
     {
         [ARG_0] = {"fd", 4},
         [ARG_1] = {"buff", 4},
         [ARG_2] = {"len", 4},
         [ARG_3] = {"flags", 4},
         [ARG_4] = {"addr", 4},
         [ARG_5] = {"addr_len", 4},
     }},
    {"setdomainname",
     4121,
     {
         [ARG_0] = {"name", 4},
         [ARG_1] = {"len", 4},
     }},
    {"setfsgid",
     4139,
     {
         [ARG_0] = {"gid", 4},
     }},
    /*
        {"setfsgid16",
         TEMPLATE_NUM,
         {
                 [ARG_0] = {"gid", 2},
         }},
    */
    {"setfsuid",
     4138,
     {
         [ARG_0] = {"uid", 4},
     }},
    /*
        {"setfsuid16",
         TEMPLATE_NUM,
         {
                 [ARG_0] = {"uid", 2},
         }},
    */
    {"setgid",
     4046,
     {
         [ARG_0] = {"gid", 4},
     }},
    /*
        {"setgid16",
         TEMPLATE_NUM,
         {
                 [ARG_0] = {"gid", 2},
         }},
    */
    {"setgroups",
     4081,
     {
         [ARG_0] = {"gidsetsize", 4},
         [ARG_1] = {"grouplist", 4},
     }},
    /*
        {"setgroups16",
         TEMPLATE_NUM,
         {
                 [ARG_0] = {"gidsetsize", 4}, [ARG_1] = {"grouplist", 4},
         }},
    */
    {"sethostname",
     4074,
     {
         [ARG_0] = {"name", 4},
         [ARG_1] = {"len", 4},
     }},
    {"setitimer",
     4104,
     {
         [ARG_0] = {"which", 4},
         [ARG_1] = {"value", 4},
         [ARG_2] = {"ovalue", 4},
     }},
    {"set_mempolicy",
     4270,
     {
         [ARG_0] = {"mode", 4},
         [ARG_1] = {"nmask", 4},
         [ARG_2] = {"maxnode", 4},
     }},
    {"setns",
     4344,
     {
         [ARG_0] = {"fd", 4},
         [ARG_1] = {"nstype", 4},
     }},
    {"setpgid",
     4057,
     {
         [ARG_0] = {"pid", 4},
         [ARG_1] = {"pgid", 4},
     }},
    {"setpriority",
     4097,
     {
         [ARG_0] = {"which", 4},
         [ARG_1] = {"who", 4},
         [ARG_2] = {"niceval", 4},
     }},
    {"setregid",
     4071,
     {
         [ARG_0] = {"rgid", 4},
         [ARG_1] = {"egid", 4},
     }},
    /*
        {"setregid16",
         TEMPLATE_NUM,
         {
                 [ARG_0] = {"rgid", 2}, [ARG_1] = {"egid", 2},
         }},
    */
    {"setresgid",
     4190,
     {
         [ARG_0] = {"rgid", 4},
         [ARG_1] = {"egid", 4},
         [ARG_2] = {"sgid", 4},
     }},
    /*
        {"setresgid16",
         TEMPLATE_NUM,
         {
                 [ARG_0] = {"rgid", 2}, [ARG_1] = {"egid", 2},
                 [ARG_2] = {"sgid", 2},
         }},
    */
    {"setresuid",
     4185,
     {
         [ARG_0] = {"ruid", 4},
         [ARG_1] = {"euid", 4},
         [ARG_2] = {"suid", 4},
     }},
    /*
        {"setresuid16",
         TEMPLATE_NUM,
         {
                 [ARG_0] = {"ruid", 2}, [ARG_1] = {"euid", 2},
                 [ARG_2] = {"suid", 2},
         }},
    */
    {"setreuid",
     4070,
     {
         [ARG_0] = {"ruid", 4},
         [ARG_1] = {"euid", 4},
     }},
    /*
        {"setreuid16",
         TEMPLATE_NUM,
         {
                 [ARG_0] = {"ruid", 2}, [ARG_1] = {"euid", 2},
         }},
    */
    {"setrlimit",
     4075,
     {
         [ARG_0] = {"resource", 4},
         [ARG_1] = {"rlim", 4},
     }},
    {"set_robust_list",
     4309,
     {
         [ARG_0] = {"head", 4},
         [ARG_1] = {"len", 4},
     }},
    {"setsid", 66, {}},
    {"setsockopt",
     4181,
     {
         [ARG_0] = {"fd", 4},
         [ARG_1] = {"level", 4},
         [ARG_2] = {"optname", 4},
         [ARG_3] = {"optval", 4},
         [ARG_4] = {"optlen", 4},
     }},
    {"set_tid_address",
     4252,
     {
         [ARG_0] = {"tidptr", 4},
     }},
    {"settimeofday",
     4079,
     {
         [ARG_0] = {"tv", 4},
         [ARG_1] = {"tz", 4},
     }},
    /*
        {"set_tls",
         TEMPLATE_NUM,
         {
                 [ARG_0] = {"val", 4},
         }},
    */
    {"setuid",
     4023,
     {
         [ARG_0] = {"uid", 4},
     }},
    /*
        {"setuid16",
         TEMPLATE_NUM,
         {
                 [ARG_0] = {"uid", 2},
         }},
    */
    {"setxattr",
     4224,
     {
         [ARG_0] = {"pathname", 4},
         [ARG_1] = {"name", 4},
         [ARG_2] = {"value", 4},
         [ARG_3] = {"size", 4},
         [ARG_4] = {"flags", 4},
     }},
    /*
        {"shmat",
         TEMPLATE_NUM,
         {
                 [ARG_0] = {"shmid", 4}, [ARG_1] = {"shmaddr", 4},
                 [ARG_2] = {"shmflg", 4},
         }},
    */
    /*
        {"shmctl",
         TEMPLATE_NUM,
         {
                 [ARG_0] = {"shmid", 4}, [ARG_1] = {"cmd", 4}, [ARG_2] = {"buf",
       4},
         }},
    */
    /*
        {"shmdt",
         TEMPLATE_NUM,
         {
                 [ARG_0] = {"shmaddr", 4},
         }},
    */
    /*
        {"shmget",
         TEMPLATE_NUM,
         {
                 [ARG_0] = {"key", 4}, [ARG_1] = {"size", 4},
                 [ARG_2] = {"shmflg", 4},
         }},
    */
    {"shutdown",
     4182,
     {
         [ARG_0] = {"fd", 4},
         [ARG_1] = {"how", 4},
     }},
    {"sigaction",
     4067,
     {
         [ARG_0] = {"sig", 4},
         [ARG_1] = {"act", 4},
         [ARG_2] = {"oact", 4},
     }},
    {"sigaltstack",
     4206,
     {
         [ARG_0] = {"uss", 4},
         [ARG_1] = {"uoss", 4},
     }},
    {"signalfd",
     4317,
     {
         [ARG_0] = {"ufd", 4},
         [ARG_1] = {"user_mask", 4},
         [ARG_2] = {"sizemask", 4},
     }},
    {"signalfd4",
     4324,
     {
         [ARG_0] = {"ufd", 4},
         [ARG_1] = {"user_mask", 4},
         [ARG_2] = {"sizemask", 4},
         [ARG_3] = {"flags", 4},
     }},
    {"sigpending",
     4073,
     {
         [ARG_0] = {"set", 4},
     }},
    {"sigprocmask",
     4126,
     {
         [ARG_0] = {"how", 4},
         [ARG_1] = {"nset", 4},
         [ARG_2] = {"oset", 4},
     }},
    {"sigreturn", 119, {}},
    {"sigsuspend",
     4072,
     {
         [ARG_0] = {"unused1", 4},
         [ARG_1] = {"unused2", 4},
         [ARG_2] = {"mask", 4},
     }},
    {"socket",
     4183,
     {
         [ARG_0] = {"family", 4},
         [ARG_1] = {"type", 4},
         [ARG_2] = {"protocol", 4},
     }},
    {"socketcall",
     4102,
     {
         [ARG_0] = {"call", 4},
         [ARG_1] = {"args", 4},
     }},  // obsolete, no longer available for EABI
    {"socketpair",
     4184,
     {
         [ARG_0] = {"family", 4},
         [ARG_1] = {"type", 4},
         [ARG_2] = {"protocol", 4},
         [ARG_3] = {"usockvec", 4},
     }},
    {"splice",
     4304,
     {
         [ARG_0] = {"fd_in", 4},
         [ARG_1] = {"off_in", 4},
         [ARG_2] = {"fd_out", 4},
         [ARG_3] = {"off_out", 4},
         [ARG_4] = {"len", 4},
         [ARG_5] = {"flags", 4},
     }},
    {"stat64",
     4213,
     {
         [ARG_0] = {"filename", 4},
         [ARG_1] = {"statbuf", 4},
     }},
    {"statfs",
     4099,
     {
         [ARG_0] = {"pathname", 4},
         [ARG_1] = {"buf", 4},
     }},
    {"statfs64",
     4255,
     {
         [ARG_0] = {"path", 4},
         [ARG_1] = {"sz", 4},
         [ARG_2] = {"buf", 4},
     }},
    {"stime",
     4025,
     {
         [ARG_0] = {"tptr", 4},
     }},  // obsolete, no longer available for EABI
    {"swapoff",
     4115,
     {
         [ARG_0] = {"specialfile", 4},
     }},
    {"swapon",
     4087,
     {
         [ARG_0] = {"specialfile", 4},
         [ARG_1] = {"swap_flags", 4},
     }},
    {"symlink",
     4083,
     {
         [ARG_0] = {"oldname", 4},
         [ARG_1] = {"newname", 4},
     }},
    {"symlinkat",
     4297,
     {
         [ARG_0] = {"oldname", 4},
         [ARG_1] = {"newdfd", 4},
         [ARG_2] = {"newname", 4},
     }},
    {"sync", 36, {}},
    /*
        {"sync_file_range2",
         TEMPLATE_NUM,
         {
                 [ARG_0] = {"fd", 4}, [ARG_1] = {"flags", 4},
                 [ARG_2] = {"offset", 8}, [ARG_3] = {"nbytes", 8},
         }},
    */
    {"syncfs",
     4342,
     {
         [ARG_0] = {"fd", 4},
     }},
    {"syscall", 113, {}},  // obsolete, no longer available for EABI
                           /*
                               {"sysctl",
                                TEMPLATE_NUM,
                                {
                                        [ARG_0] = {"args", 4},
                                }},
                           */
    {"sysfs",
     4135,
     {
         [ARG_0] = {"option", 4},
         [ARG_1] = {"arg1", 4},
         [ARG_2] = {"arg2", 4},
     }},
    {"sysinfo",
     4116,
     {
         [ARG_0] = {"info", 4},
     }},
    {"syslog",
     4103,
     {
         [ARG_0] = {"type", 4},
         [ARG_1] = {"buf", 4},
         [ARG_2] = {"len", 4},
     }},
    {"tee",
     4306,
     {
         [ARG_0] = {"fdin", 4},
         [ARG_1] = {"fdout", 4},
         [ARG_2] = {"len", 4},
         [ARG_3] = {"flags", 4},
     }},
    {"tgkill",
     4266,
     {
         [ARG_0] = {"tgid", 4},
         [ARG_1] = {"pid", 4},
         [ARG_2] = {"sig", 4},
     }},
    {"time",
     4013,
     {
         [ARG_0] = {"tloc", 4},
     }},  // obsolete, no longer available for EABI
    {"timer_create",
     4257,
     {
         [ARG_0] = {"which_clock", 4},
         [ARG_1] = {"timer_event_spec", 4},
         [ARG_2] = {"created_timer_id", 4},
     }},
    {"timer_delete",
     4261,
     {
         [ARG_0] = {"timer_id", 4},
     }},
    {"timerfd_create",
     4321,
     {
         [ARG_0] = {"clockid", 4},
         [ARG_1] = {"flags", 4},
     }},
    {"timerfd_gettime",
     4322,
     {
         [ARG_0] = {"ufd", 4},
         [ARG_1] = {"otmr", 4},
     }},
    {"timerfd_settime",
     4323,
     {
         [ARG_0] = {"ufd", 4},
         [ARG_1] = {"flags", 4},
         [ARG_2] = {"utmr", 4},
         [ARG_3] = {"otmr", 4},
     }},
    {"timer_getoverrun",
     4260,
     {
         [ARG_0] = {"timer_id", 4},
     }},
    {"timer_gettime",
     4259,
     {
         [ARG_0] = {"timer_id", 4},
         [ARG_1] = {"setting", 4},
     }},
    {"timer_settime",
     4258,
     {
         [ARG_0] = {"timer_id", 4},
         [ARG_1] = {"flags", 4},
         [ARG_2] = {"new_setting", 4},
         [ARG_3] = {"old_setting", 4},
     }},
    {"times",
     4043,
     {
         [ARG_0] = {"tbuf", 4},
     }},
    {"tkill",
     4236,
     {
         [ARG_0] = {"pid", 4},
         [ARG_1] = {"sig", 4},
     }},
    {"truncate",
     4092,
     {
         [ARG_0] = {"path", 4},
         [ARG_1] = {"length", 4},
     }},
    {"truncate64",
     4211,
     {
         [ARG_0] = {"path", 4},
         [ARG_1] = {"length", 8},
     }},
    {"umask",
     4060,
     {
         [ARG_0] = {"mask", 4},
     }},
    {"umount",
     4022,
     {
         [ARG_0] = {"name", 4},
         [ARG_1] = {"flags", 4},
     }},
    {"unlink",
     4010,
     {
         [ARG_0] = {"pathname", 4},
     }},
    {"unlinkat",
     4294,
     {
         [ARG_0] = {"dfd", 4},
         [ARG_1] = {"pathname", 4},
         [ARG_2] = {"flag", 4},
     }},
    {"unshare",
     4303,
     {
         [ARG_0] = {"unshare_flags", 4},
     }},
    {"uselib",
     4086,
     {
         [ARG_0] = {"library", 4},
     }},
    {"userfaultfd",
     4357,
     {
         [ARG_0] = {"flags", 4},
     }},
    {"usr26", 983043, {}},
    {"usr32", 983044, {}},
    {"ustat",
     4062,
     {
         [ARG_0] = {"dev", 4},
         [ARG_1] = {"ubuf", 4},
     }},
    {"utime",
     4030,
     {
         [ARG_0] = {"filename", 4},
         [ARG_1] = {"times", 4},
     }},
    {"utimensat",
     4316,
     {
         [ARG_0] = {"dfd", 4},
         [ARG_1] = {"filename", 4},
         [ARG_2] = {"utimes", 4},
         [ARG_3] = {"flags", 4},
     }},
    {"utimes",
     4267,
     {
         [ARG_0] = {"filename", 4},
         [ARG_1] = {"utimes", 4},
     }},
    {"vfork", 190, {}},
    {"vhangup", 111, {}},
    {"vmsplice",
     4307,
     {
         [ARG_0] = {"fd", 4},
         [ARG_1] = {"iov", 4},
         [ARG_2] = {"nr_segs", 4},
         [ARG_3] = {"flags", 4},
     }},
    {"vserver", 313, {}},  // unimplemented system call
    {"wait4",
     4114,
     {
         [ARG_0] = {"upid", 4},
         [ARG_1] = {"stat_addr", 4},
         [ARG_2] = {"options", 4},
         [ARG_3] = {"ru", 4},
     }},
    {"waitid",
     4278,
     {
         [ARG_0] = {"which", 4},
         [ARG_1] = {"upid", 4},
         [ARG_2] = {"infop", 4},
         [ARG_3] = {"options", 4},
         [ARG_4] = {"ru", 4},
     }},
    {"write",
     4004,
     {
         [ARG_0] = {"fd", 4},
         [ARG_1] = {"buf", 4},
         [ARG_2] = {"count", 4},
     }},
    {"writev",
     4146,
     {
         [ARG_0] = {"fd", 4},
         [ARG_1] = {"vec", 4},
         [ARG_2] = {"vlen", 4},
     }},
};

const size_t mipso32_syscall_list_size =
    sizeof(mipso32_syscall_list) / sizeof(mipso32_syscall_list[0]);
// List of syscalls that are not found in the template
//_llseek
//_newselect
//_sysctl
// afs_syscall
// break
// cachectl
// create_module
// fadvise64
// fork
// fstat
// ftime
// get_kernel_syms
// getegid
// geteuid
// getgid
// getpgrp
// getpid
// getpmsg
// getppid
// gettid
// getuid
// gtty
// idle
// inotify_init
// ioperm
// iopl
// lock
// lstat
// migrate_pages
// modify_ldt
// mpx
// munlockall
// pause
// pkey_alloc
// pkey_free
// pkey_mprotect
// prof
// profil
// putpmsg
// query_module
// restart_syscall
// rt_sigreturn
// sched_yield
// set_thread_area
// setsid
// sgetmask
// signal
// sigreturn
// ssetmask
// stat
// statx
// stty
// sync
// sync_file_range
// sysmips
// timerfd
// ulimit
// umount2
// uname
// vhangup
// vm86
// vserver
// waitpid

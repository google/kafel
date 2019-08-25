# WHAT IS IT?
Kafel is a language and library for specifying syscall filtering policies.
The policies are compiled into BPF code that can be used with seccomp-filter.

This is NOT an official Google product.

# Usage

## With verbose error reporting
```c
struct sock_fprog prog;
kafel_ctxt_t ctxt = kafel_ctxt_create();
kafel_set_input_string(ctxt, seccomp_policy);
if (kafel_compile(ctxt, &prog)) {
  fprintf(stderr, "policy compilation failed: %s", kafel_error_msg(ctxt));
  kafel_ctxt_destroy(&ctxt);
  exit(-1);
}
kafel_ctxt_destroy(&ctxt);
prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog, 0, 0);
free(prog.filter);
```

## Without verbose error reporting
```c
struct sock_fprog prog;
if (kafel_compile_string(seccomp_policy, &prog)) {
  fputs("policy compilation failed", stderr);
  exit(-1);
}
prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog, 0, 0);
free(prog.filter);
```

# Policy language

A simple language is used to define policies.

Policy file consists of statements.

A statement can be:
 * a constant definition
 * a policy definition
 * a policy definition statement
 * a default action statement

Policy definition statements placed at file scope will be added to the implicit
top level policy.
This top level policy is going to be compiled.

## Default action statement

```
DEFAULT the_action
```

Specifies that action `the_action` should be taken when no rule matches.

The default action must be specified just once.

If the policy file specifies no default actions, the default action will
be KILL

## Numbers

Kafel supports following number notations:
 * Decimal `42`
 * Hexadecimal `0xfa1`
 * Octal `0777`
 * Binary `0b10101`

## Constant definitions

You may define numeric constants to make your policies more readable.
Constant definitions may be placed almost anywhere in the policy file.
A constant definition cannot be placed inside of a policy definition.
The defined constants can then be used anywhere where a number is expected.

```
#define MYCONST 123
```

## Policy definitions

Policy definition is a list of action blocks and use statements separated by
commas.

__samples/__ contains some example policies that demonstrate supported features.

### Use statements

A `USE someOtherPolicy` behaves as if `someOtherPolicy` body was pasted in its
place. You may only use policies defined before the use statement.

With use statements you can create meaningful groups of filtering rules that are
building blocks of bigger policies.

### Action blocks

Action block consist of a target and list of syscall matching rules separated
with commas.

Target of first rule matched is the policy decision.

Following table list Kafel targets and their corresponding seccomp-filter
return values.

Kafel                          | seccomp-filter
------------------------------ | ---------------------------
`ALLOW`                        | `SECCOMP_RET_ALLOW`
`LOG`                          | `SECCOMP_RET_LOG`
`KILL`, `KILL_THREAD`, `DENY`  | `SECCOMP_RET_KILL`
`KILL_PROCESS`                 | `SECCOMP_RET_KILL_PROCESS`
`USER_NOTIF`                   | `SECCOMP_RET_USER_NOTIF`
`ERRNO(number)`                | `SECCOMP_RET_ERRNO+number`
`TRAP(number)`                 | `SECCOMP_RET_TRAP+number`
`TRACE(number)`                | `SECCOMP_RET_TRACE+number`

### Syscall matching rules

A rules consist of syscall name and optional list of boolean expressions.

List of boolean expressions separated by commas.
A comma is semantically equivalent to `||` but has the lowest precedence,
therefore it may be easier to read.

#### Syscall naming

Normally syscalls are specified by their names as defined in Linux kernel.
However, you may also filter __custom syscalls__ that are not in the standard
syscall list.
You can either define a constant and use it in place of syscall name or
utilize `SYSCALL` keyword.

```
#define mysyscall -1

POLICY my_const {
  ALLOW {
    mysyscall
  }
}

POLICY my_literal {
  ALLOW {
    SYSCALL[-1]
  }
}
```

#### Argument filtering

Boolean expressions are used to filter syscalls based on their arguments.
A expression resembles C language syntax, except that there are no
arithmetic operators.

```
some_syscall(first_arg, my_arg_name) { first_arg == 42 && my_arg_name != 42 }
```

Bitwise and (`&`) and or ('|') operators can be used to test for flags.

```
mmap { (prot & PROT_EXEC) == 0 },
open { flags == O_RDONLY|O_CLOEXEC }
```

You don't have to declare arguments for well-known syscalls but can just use
their regular names as specified in Linux kernel and `man` pages.

```
write { fd == 1 }
```

## Include directive

In order to simplify reuse and composition of policies, kafel provides include
support.

```
#include "some_other_file.policy"
```

Kafel looks for included files only under directories explicitly added to the
search paths.

```c
kafel_include_add_search_path(ctxt, "includes/path");
```

Adds `includes/path` to search paths - the example include directive will refer
then to `includes/path/some_other_file.policy`.

Include directive is terminated by a newline or a semicolon.
Multiple files, separated by whitespace, can be specified in one directive.

```
#include "first.policy" "second.policy"; #include "third.policy"
```

# Example

When used with [nsjail](https://github.com/google/nsjail), the following command allows to create a fairly constrained environment for your shell

```
$ ./nsjail --chroot / --seccomp_string 'POLICY a { ALLOW { write, execve, brk, access, mmap, open, newfstat, close, read, mprotect, arch_prctl, munmap, getuid, getgid, getpid, rt_sigaction, geteuid, getppid, getcwd, getegid, ioctl, fcntl, newstat, clone, wait4, rt_sigreturn, exit_group } } USE a DEFAULT KILL' -- /bin/sh -i
```
```
[2017-01-15T21:53:08+0100] Mode: STANDALONE_ONCE
[2017-01-15T21:53:08+0100] Jail parameters: hostname:'NSJAIL', chroot:'/', process:'/bin/sh', bind:[::]:0, max_conns_per_ip:0, uid:(ns:1000, global:1000), gid:(ns:1000, global:1000), time_limit:0, personality:0, daemonize:false, clone_newnet:true, clone_newuser:true, clone_newns:true, clone_newpid:true, clone_newipc:true, clonew_newuts:true, clone_newcgroup:false, keep_caps:false, tmpfs_size:4194304, disable_no_new_privs:false, pivot_root_only:false
[2017-01-15T21:53:08+0100] Mount point: src:'/' dst:'/' type:'' flags:0x5001 options:''
[2017-01-15T21:53:08+0100] Mount point: src:'(null)' dst:'/proc' type:'proc' flags:0x0 options:''
[2017-01-15T21:53:08+0100] PID: 18873 about to execute '/bin/sh' for [STANDALONE_MODE]
/bin/sh: 0: can't access tty; job control turned off
$ set
IFS='
'
OPTIND='1'
PATH='/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'
PPID='0'
PS1='$ '
PS2='> '
PS4='+ '
PWD='/'
$ id
Bad system call
$ exit
[2017-01-15T21:53:17+0100] PID: 18873 exited with status: 159, (PIDs left: 0)
```

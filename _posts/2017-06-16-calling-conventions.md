---
layout: single
author_profile: true
permalink: /calling-conventions/
---

In the first part I will include a little "cheat-sheet" and at the
end there will be an in depth description and demonstration of major ones.

{% include toc %}

## Introduction

This page can be used as fast reference for calling conventions.
They are vital part of analyzing what binaries do.

## Reference

| ARCHitecture | Convention name        | Parameters in registers            | Parameter order on stack | Stack cleanup |
| ------------ | ---------------        | -----------------------            | ------------------------ | ------------- |
| 8086         | pascal                 |                                    | LTR                      | Calle         |
| IA-32        | **cdecl**              |                                    | RTL                      | Caller        |
| IA-32        | stdcall                |                                    | RTL                      | Calle         |
| IA-32        | fastcall               | ECX, EDX                           | RTL                      | Calle         |
| x86_64       | **System V AMD64 ABI** | RDI, RSI, RDX, RCX, R8, R9, XMM0-7 | RTL                      | Caller        |

For an external reference visit this [link](https://en.wikipedia.org/wiki/X86_calling_conventions?oldformat=true).

## General method

1. Depending on the convention(order) set the arguments onto the stack/registers.
2. Call the function
3. Create and destroy the [stack frame](/stack-frame)
  * Store EBP on stack
  * Move the current stack address into EBP
  * Set up the space for local variables with `sub esp, N`
  * Now the function will execute its code
  * The result is returned in AL, AX, EAX, EDX:EAX depending on its size or the
floating point number will be returned in ST0
  * Restore the stack state
  * Return from the function
4. Clean the stack(from the function with `ret N`, or after the function with `add ESP, N`)

## IA-32
### cdecl - GCC
This is the main calling convention on 32bit Linux systems.
You will likely see this convention a lot.
Name decoration of this function will most likely look like `_symbol`.

```nasm
func:
	push ebp
	mov ebp, esp
	sub esp, local_data
	;...
	mov esp, ebp
	pop ebp
	ret

main:
	push arg_n
	;...
	push arg_3
	push arg_2
	push arg_1
	call func
	add esp, 4*n
	ret
```
### stdcall
This calling convention is mainly used on windows platforms(Win32 API).

```nasm
func:
	push ebp
	mov ebp, esp
	sub esp, local_data
	;...
	mov esp, ebp
	pop ebp
	ret 4*n

main:
	push arg_n
	;...
	push arg_3
	push arg_2
	push arg_1
	call func
	ret
```

### fastcall
Usage of this calling convention might vary. But since two first parameters
are passed to function inside registers it is fast.

```nasm
func:
	push ebp
	mov ebp, esp
	sub esp, local_data
	;...
	mov esp, ebp
	pop ebp
	ret

main:
	mov ebx, arg_1
	mov ecx, arg_2
	push arg_n
	;...
	push arg_5
	push arg_4
	push arg_3
	call func
	add esp, 4*n
	ret
```

## x86_64
64bit systems.
### System V AMD64 ABI
The main calling convention on 64bit Linux systems.

```nasm
func:
	push ebp
	mov ebp, esp
	sub esp, local_data
	;...
	mov esp, ebp
	pop ebp
	ret

main:
	mov rdi, arg_1
	mov rsi, arg_2
	mov rdx, arg_3
	mov rcx, arg_4
	mov r8 , arg_5
	mov r9 , arg_6
	; XMM0-7 are used for certain floating-point arguments
	push arg_n
	; ...
	push arg_9
	push arg_8
	push arg_7
	call func
	add esp, 4*n
	ret
```

## 8086
16bit systems.
### Pascal

```nasm
func:
	push ebp
	mov ebp, esp
	sub esp, local_data
	; ...
	mov esp, ebp
	pop ebp
	ret 4*n

main:
	push arg_1
	push arg_2
	push arg_3
	; ...
	push arg_n
	call func
	ret
```
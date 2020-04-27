---
pagetitle:  Notes for the Stack Buffer Overflow internship at INRIA Sophia
title:      Notes for the Stack Buffer Overflow internship at INRIA Sophia
author:     Florian Hofhammer
date:       2020-04-27
---

# Virtual Machine setup

## Basic information

The virtual machine used for the experiments is based on the Ubuntu 20.04 Desktop distribution with Linux kernel 5.4.0, GLIBC 2.31 and GCC 9.3.0 and runs in VirtualBox 6.1.
Updates are regularly installed to keep the system up to date.   
ASLR is permanently deactivated on the machine by issuing the command `echo "kernel.randomize_va_space = 0" | sudo tee /etc/sysctl.d/01-disable-aslr.conf`.   
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
The compiler flags for `gcc` generally used are `-m32 -fno-stack-protector -z execstack -D_FORTIFY_SOURCE=0` (see e.g. the [common Makefile](./Makefile.common) and the [directory specific Makefile](./Smashing%20the%20stack%20-%20Aleph1/Makefile)).
Without those, current stack overflow mitigation measures do not allow to successfully overflow the buffers on the stack as described in the paper.

## example3.c
The executable only provided a segfault because the return address was incorrectly overwritten (checked with `gdb`).
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

### exploit3

`exploit3` works exactly the same way as `exploit2` but instead of just writing the shellcode to the buffer, it fills half of the buffer with `NOP` instructions (`0x90` on x86) before writing the shellcode to the buffer.

This makes it easier to execute the shellcode, as it is not necessary to exactly hit the buffer address where the shellcode resides when overwriting the return address.
It now is completely sufficient to overwrite the return address with an arbitrary address pointing into the first half of the buffer which gives us a certain degree of freedom and error resilience.

However, it is again not possible to just issue the call provided in the original paper (`exploit3 600`).
When debugging the `vulnerable` executable, it is easy to see that the return address in fact points into the buffer but only at a part of the buffer where the stack address resides (i.e. to a part of the buffer after the NOP sled and the shellcode).
Because of the NOP sled in front of the shellcode, it is then pretty easy to find an offset that reliably lets the program return onto the stack where our shellcode resides (e.g. `exploit3 600 350` or `exploit 600 400`).

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

1. Find the address of the `system` function in libc via `gdb` (note: ASLR is still disabled, the address thus stays the same)
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

For example with the command `./width $(python3 -c "import sys; sys.stdout.buffer.write(b'A' * 88 + b'\xf6\x91\x04\x08'  + b'A' * 36)")`, we jump to the secret function that is not used during normal execution.
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
   Thus, we can only control the number to write via `%n` by padding the string with junk between the address and the `%n` placeholder.
   This is a problem because the command line (here: bash 5.0.3) only accepts string of a certain length as parameter to a function.
   Because hex addresses transformed into decimal numbers are huge and our padding thus has to be extremely long, we cannot directly write the address we want with the help of `%n`.    
   When looking at the data in `.fini_array`, we see that the pointer located there points to an address starting with 0x0804.
   The address located there thus is in the address space of our ELF executable.
   It is thus sufficient to overwrite only the lower two bytes of this pointer with the lower two bytes of the address of our array in the `.bss` section.
   This can be achieved by using `%hn` instead of `%n` as format string placeholder.
4. The `.fini_array` section is subject of RELRO (relocation read-only).
   Even though it is marked writable in the output of `readelf -S ret2dtors`, it is marked as read-only by the dynamic linker on program start.
   Thus, we only get a segmentation fault when trying to overwrite a pointer in this section like described above.   
   The solution is to disable RELRO by passing the additional linker flag `-z norelro` when linking the executable.

In conclusion, an exploit is possible (command `./ret2dtors "$(./shellcode)" "$(python3 -c "import sys; sys.stdout.buffer.write(b'\x68\xb1\x04\x08' + b'A' * 45724 + b'%hn')")"` where `shellcode` is a helper executable just outputting shellcode (see [shellcode.c](./ASLR%20Smack%20and%20Laugh%20reference%20-%20Tilo%20Mueller/shellcode.c))) but only with severe changes.   
Firstly, it is not possible to use the heap.
We have to rely on an array in the `.bss` or `.data` section (c.f. [ret2bss](#ret2bss) and [ret2data](#ret2data)), i.e. a global array.   
Secondly, we have to link the executable with RELRO disabled.

# Stack canary bypassing

In the previous sections, I have described how to bypass ASLR, non-executable stack, etc. based on several tutorials.
This section now aims to bypass stack protection by stack canaries and analyzes how stack canaries are used.

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
Thus, it is easy to leak the canary: whenever we guess right, the process exits normally.
Whenever we guess incorrectly, the process yields an error message.

The approach to leak the stack canary is then to overwrite the canary byte by byte until for each byte we don't receive an error message and the process exits normally.
This is possible because of the [previously](#stack-analysis---getcanary-and-getcanarythreaded) observed behavior that the stack canary doesn't change on forking, as the child process' memory is an exact copy of the parent process' memory.
This includes the stack including the stack canaries as well.

This is exactly what is done in the [leak_canary.py](./Stack%20canary%20bypassing/leak_canary.py) Python script: it connects to the vulnerable server over and over again and with each request tries to overwrite a byte of the stack canary.
If it succeeds (i.e. no error message is returned), the current byte is saved and the next canary byte is evaluated.
Step by step, this script recovers all 8 of the stack canary bytes.

The important observation is that even after we leaked the stack canary, the main process is still running correctly.
This means that we could exploit the stack buffer overflow and overwrite the return address with any value we wish, as we previously recovered the stack canary successfully.

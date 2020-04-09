# Virtual Machine setup

The virtual machine used for the experiments is based on Ubuntu 19.10 Desktop, Linux kernel 5.3.
Updates are regularly installed to keep the system up to date.   
ASLR is permanently deactivated on the machine by issuing the command `echo "kernel.randomize_va_space = 0" | sudo tee /etc/sysctl.d/01-disable-aslr.conf`.

As the GDB version 8.3 included in the default Ubuntu repositories kept crashing, I installed GDB 9.1 from the source provided on the [official website](https://www.gnu.org/software/gdb/).
Additionally, I installed `peda`, `pwndbg` and `gef` for easier debugging using an install script from a [GitHub repository](https://github.com/apogiatzis/gdb-peda-pwndbg-gef).   
I also mounted the directory containing the internship data and files into the virtual machine and installed the OpenSSH Server to be able to `ssh` into the virtual machine and execute all the code whilst not having to make any changes to the host machine.
It is, however, important to point out that if accessing a shell via `ssh` in the VM, the stack addresses may differ from those when directly opening a terminal in the VM.
In addition, the `ssh` session adds additional information to the environment by setting environment variables which might lead to different offsets on the stack.

Apart from that, no changes to the system were made.

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

After having a lot of problems with this issue, I found a comment online suggesting to add the `-mpreferred-stack-boundary=2` compiler flag which instructs `gcc` to align on 4 bytes (2^2) instead of 16 bytes.
__This additional flag is used throughout all of the following examples!__
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

With modern compilers (`gcc 9.2.1`), the stack offset is different than that given in Aleph1's original paper: instead of calling `exploit2 600 1564` for a buffer size of 600 bytes filled with shellcode and stack address as well as an offset of 1564 bytes from the base stack address, it is sufficient to call `exploit2 600` which doesn't use an offset at all.

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

However, a similar problem compared to `exploit3` occurs with `exploit4`.
As the compiler and runtime on modern machines differ from the ones used by Aleph1, it is necessary to add an offset.
Calling `exploit4 600` and then `vulnerable $RET` is not sufficient and only yields a segmentation fault.
When debugging the `vulnerable` executable, it is easy to see that the return address is correctly rewritten by the input given in the environment variable `RET` but that the address in that environment variable is way too low.
Thus, we have to increase the address in order to jump into the NOP sled inside the environment variable `EGG`.
Calling e.g. `exploit4 600 -2000` gives a working offset so that the address saved in `RET` points into the NOP sled saved in `EGG`.

### eggshell

The `eggshell` executable basically does the same thing as `exploit4`.
The difference is that it is suitable for different processor architectures and also has a more sophisticated command line interface.
It also writes the overflow buffer to the environment variable `BOF` instead of `RET`.

However, the original version by Aleph1 contains an error: when creating the NOP sled, the stop condition is tested by `i <= eggsize ...`.
Therefore, the pointer into the egg buffer `ptr` is incremented once too often so that setting `egg[eggsize - 1] = '\0';` later in the code overwrites the last byte of the shellcode instead of just appending a zero byte to the NOP sled and shellcode.
Thus, the shellcode tries to execute `/bin/s` instead of `/bin/sh`, which of course doesn't yield the expected result.

Changing the comparison from `i <= eggsize ...` to `i < eggsize ...` fixes that problem, as one less NOP instruction is written to the egg buffer and thus the actual shellcode starts at a lower position in the buffer.

Again, providing no offset, the address in `BOF` does not point to the `EGG` environment variable.
Just like with `exploit4`, it is easy to find a fitting offset with a debugger by looking at the difference of the provided (incorrect) address and the address of the `EGG` variable (e.g. by issuing `search "EGG"` in `gdb` with the `pwndbg` plugin).
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
(python -c "from struct import pack; print(
    'A' * 104 +                         # Padding to reach the return address
    pack('<Q', 0x0000555555555273) +    # Address of pop rdi; ret in function __libc_csu_init
    pack('<Q', 0x000055555555603f) +    # Address of "/bin/sh" in function main
    pack('<Q', 0x00007ffff7e1a4e0)      # Address of function system
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
(python -c "from struct import pack; print(
    'A' * 104 +                         # Padding to reach the return address
    pack('<Q', 0x00005555555551da) +    # Address of ret in function vuln
    pack('<Q', 0x0000555555555273) +    # Address of pop rdi; ret in function __libc_csu_init
    pack('<Q', 0x000055555555603f) +    # Address of "/bin/sh" in function main
    pack('<Q', 0x00007ffff7e1a4e0)      # Address of function system
    )"; cat) | ./vulnerable
```

If the SUID bit is set on the executable and it is owned by root, we can spawn a root shell with the following code:
```bash
(python -c "from struct import pack; print(
    'A' * 104 +                         # Padding to reach the return address
    pack('<Q', 0x00005555555551da) +    # Address of ret in function vuln
    pack('<Q', 0x0000555555555273) +    # Address of pop rdi; ret in function __libc_csu_init
    pack('<Q', 0x0000000000000000) +    # Value 0 => uid of root
    pack('<Q', 0x0000555555555271) +    # Address of pop rsi; pop r15; ret in function __libc_csu_init
    pack('<Q', 0x0000000000000000) +    # Value 0 => uid of root (into rsi)
    pack('<Q', 0x4141411411414141) +    # Junk (into r15)
    pack('<Q', 0x00007ffff7edcc20) +    # Address of function setreuid
    pack('<Q', 0x0000555555555273) +    # Address of pop rdi; ret in function __libc_csu_init
    pack('<Q', 0x000055555555603f) +    # Address of "/bin/sh" in function main
    pack('<Q', 0x00007ffff7e1a4e0)      # Address of function system
    )"; cat) | ./vulnerable
```
This code additionally calls `setreuid(0, 0)` before spawning the shell.

Note: when working through this exercise, I could not just get the addresses from the executable but had to get the addresses from gdb.
This is because the executable by default is compiled as PIE (Position Independent Executable).
The addresses in the executable (e.g. showed by `objdump -d vulnerable`) are only offsets from the base address. 
The base address (`0x0000555555554000`) is always the same, because ASLR is disabled.
When knowing this base address, one could just calculate all other addresses in the executable by adding the given offset to the base address.   
If compiled with the compiler flag `-fno-pic` and the linker flag `-no-pie`, the executable would contain the absolute addresses of the instructions instead of relative ones relative to the base address.
This would make it probably easier to find the addresses (in the code snippet above: addresses for the `ret` instruction, `pop rdi; ret` and `/bin/sh`) because it would be sufficient to just look at the executable without loading it into a debugger.
However, it would probably still be necessary to get the address of the `system` function by loading it into a debugger, as libc is only dynamically loaded on runtime and the address thus can only be determined by either knowing the offset of `system` in libc and at which base address libc will be loaded or by loading the executable into gdb and just printing the address with `p system`.

# ASLR Smack and Laugh

The [ASLR Smack & Laugh Reference](ttps://api.semanticscholar.org/CorpusID:16401261) by Tilo Müller, published in 2008, describes several methods how to bypass protection by Address Space Layout Randomization built into the Linux kernel.   
As he uses a Linux installation with kernel 2.6.23, glibc 2.6.1 and gcc 4.2.3, several of his described exploits might not work as described on modern machines.
Additionally, his machine is a 32 bit machine which is why all the executables are compiled in 32 bit mode (see the [Makefile](./ASLR%20Smack%20and%20Laugh%20reference%20-%20Tilo%20Mueller/Makefile)).

For these exploits, ASLR is of course activated in the Linux kernel (e.g. by issuing the command `echo 2 | sudo tee /proc/sys/kernel/randomize_va_space`).

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
* Execute the program (here: `./ret2text $(python -c "print('A' * 16 + '\xff\x91\x04\x08')")`)

An interesting observation is that it is completely sufficient to call `./ret2text $(python -c "print('A' * 16")`.
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

# Virtual Machine setup

The virtual machine used for the experiments is based on Ubuntu 19.10 Desktop.
Updates are regularly installed to keep the system up to date.

As the GDB version 8.3 included in the default Ubuntu repositories kept crashing, I installed GDB 9.1 from the source provided on the [official website](https://www.gnu.org/software/gdb/).
Additionally, I installed `peda`, `pwndbg` and `gef` for easier debugging using an install script from a [GitHub repository](https://github.com/apogiatzis/gdb-peda-pwndbg-gef).   
I also mounted the directory containing the internship data and files into the virtual machine and installed the OpenSSH Server to be able to `ssh` into the virtual machine and execute all the code whilst not having to make any changes to the host machine.
It is, however, important to point out that if accessing a shell via `ssh` in the VM, the stack addresses differ from those when directly opening a terminal in the VM.
In addition, the `ssh` session adds additional information to the environment by setting environment variables which might lead to different offsets on the stack.

Apart from that, no changes to the system were made.

# Smashing the Stack for fun and profit - Aleph1

As a starting exercise, I am trying to recreate the examples and exploits from the original paper.
The compiler flags for `gcc` generally used are `-m32 -fno-stack-protector -z execstack -D_FORTIFY_SOURCE=0` (see e.g. the [Makefile](./Smashing\ the\ stack\ -\ Aleph1/Code/Makefile)).
Without those, current stack overflow mitigation measures do not allow to successfully overflow the buffers on the stack as described in the paper.
Additionally, ASLR is permanently deactivated on the machine by issuing the command `echo "kernel.randomize_va_space = 0" | sudo tee /etc/sysctl.d/01-disable-aslr.conf`.

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

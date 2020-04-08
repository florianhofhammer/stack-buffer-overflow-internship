# Build 32 bit executables without stack protection (canaries, NX bit, overflow checks), with .text, .bss, .data not randomized and stack aligned to 4 bytes
CFLAGS= -m32 -fno-stack-protector -fno-pic -D_FORTIFY_SOURCE=0 -mpreferred-stack-boundary=2 -g
LFLAGS= -m32 -no-pie -z execstack

# Suppress warning for format string vulnerability
formatStringDos: CFLAGS += -Wno-format-security

# Include the common Makefile
include ../Makefile.common

# Build 64 bit executables without stack protection (canaries, NX bit, overflow checks)
CFLAGS= -m64 -fno-stack-protector -D_FORTIFY_SOURCE=0 -g
LFLAGS= -m64 -z execstack

# Disable PIE for Part 3 of the tutorial, make steck non-executable
vulnerable_advanced: CFLAGS += -fno-pic
vulnerable_advanced: LFLAGS= -m64 -no-pie

# Include the common Makefile
include ../Makefile.common

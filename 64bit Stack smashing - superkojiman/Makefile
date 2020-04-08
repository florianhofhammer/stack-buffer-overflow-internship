# Build 64 bit executables without stack protection (canaries, NX bit, overflow checks)
CFLAGS= -m64 -fno-stack-protector -D_FORTIFY_SOURCE=0 -g
LFLAGS= -m64 -z execstack

# Disable stack canaries and prevent gcc from compiling as PIE for Part 3 of the tutorial
vulnerable_advanced: CFLAGS= -m64 -fno-stack-protector -fno-pic -g
vulnerable_advanced: LFLAGS += -no-pie

# Include the common Makefile
include ../Makefile.common

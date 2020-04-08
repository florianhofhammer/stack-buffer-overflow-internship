# Build 32 bit executables without stack protection (canaries, NX bit, overflow checks) and stack aligned to 4 bytes
CFLAGS= -m32 -fno-stack-protector -D_FORTIFY_SOURCE=0 -mpreferred-stack-boundary=2 -g
LFLAGS= -m32 -z execstack

# Include the common Makefile
include ../Makefile.common

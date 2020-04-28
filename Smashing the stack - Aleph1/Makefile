# Build 32 bit executables without stack protection (canaries, NX bit, overflow checks) and stack aligned to 4 bytes
CFLAGS = -m32 -fno-stack-protector -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0 -mpreferred-stack-boundary=2 -g
LFLAGS = -m32 -z execstack

# Include the common Makefile
include ../Makefile.common

.PHONY: optimized
# Enable compiler optimizations, then run the default target (i.e. all executables)
optimized: CFLAGS += -O3
optimized: .DEFAULT_GOAL


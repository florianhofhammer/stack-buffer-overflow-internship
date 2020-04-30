# Build 32 bit executables without stack protection (canaries, NX bit, overflow checks), with .text, .bss, .data not randomized and stack aligned to 4 bytes
CFLAGS= -m32 -fno-stack-protector -fno-pic -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0 -mpreferred-stack-boundary=2 -g
LFLAGS= -m32 -no-pie -z execstack

# Include the common Makefile
include ../Makefile.common

.PHONY: optimized
# Enable compiler optimizations and suppress warnings, then run the default target (i.e. all executables)
optimized: CFLAGS += -O3 -Wno-stringop-overflow
optimized: .DEFAULT_GOAL

# Suppress warning for format string vulnerability
formatStringDos divulge ret2dtors: CFLAGS += -Wno-format-security
# Disable RelRO for ret2dtors
ret2dtors: LFLAGS += -z norelro

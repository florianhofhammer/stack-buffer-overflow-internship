# Build 64 bit executables without stack protection (canaries, NX bit, overflow checks)
CFLAGS= -m64 -fno-stack-protector -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0 -g
LFLAGS= -m64 -z execstack

# Include the common Makefile
include ../Makefile.common

.PHONY: optimized
# Enable compiler optimizations, then run the default target (i.e. all executables)
optimized: CFLAGS += -O3
optimized: .DEFAULT_GOAL

# Disable PIE for Part 3 of the tutorial, make stack non-executable
vulnerable_advanced: CFLAGS += -fno-pic
vulnerable_advanced: LFLAGS= -m64 -no-pie

# Build 64 bit executables with full (i.e. GCC default) stack protection and debugging symbols
CFLAGS= -m64 -g
LFLAGS= -m64

# Include the common Makefile
include ../Makefile.common

.PHONY: optimized
# Enable compiler optimizations and suppress warnings caused by optimization, then run the default target (i.e. all executables)
optimized: CFLAGS += -O3 -Wno-unused-result -Wno-attribute-warning
optimized: .DEFAULT_GOAL

# Link getCanaryThreaded executable against pthread library
getCanaryThreaded: LFLAGS += -lpthread

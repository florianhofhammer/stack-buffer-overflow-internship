# Build 64 bit executables with full (i.e. GCC default) stack protection and debugging symbols
CFLAGS= -m64 -g
LFLAGS= -m64

# Link getCanaryThreaded executable against pthread library
getCanaryThreaded: LFLAGS += -lpthread

# Include the common Makefile
include ../Makefile.common

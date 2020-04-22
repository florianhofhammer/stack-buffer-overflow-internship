# Build 64 bit executables without stack protection (NX bit, overflow checks)
CFLAGS= -m64 -D_FORTIFY_SOURCE=0 -g
LFLAGS= -m64 -z execstack

# Build getCanary executable in 64 bit and with debugging symbols but all default protections enabled
getCanary: CFLAGS= -m64 -g
getCanary: LFLAGS= -m64

# Build getCanaryThreaded executable in 64 bit and with debugging symbols but all default protections enabled, link against pthread library
getCanaryThreaded: CFLAGS= -m64 -g
getCanaryThreaded: LFLAGS= -m64 -lpthread

# Include the common Makefile
include ../Makefile.common

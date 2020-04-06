# Currently set no additional compiler flags
EXTRAFLAGS=

# Disable stack canaries and prevent gcc from compiling as PIE for Part 3 of the tutorial
vulnerable_advanced: CFLAGS= -fno-stack-protector -no-pie -g

# Include the common Makefile
include ../Makefile.common

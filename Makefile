CC=gcc
CFLAGS= -m32 -fno-stack-protector -z execstack -D_FORTIFY_SOURCE=0 -g -mpreferred-stack-boundary=2# --static
#LFLAGS=
EXECS = $(patsubst %.c, %, $(wildcard *.c))

.PHONY: default all

# Build all executables by default
default: all

# Build all the executables
all: $(EXECS)

# Compile code to object files
%.o: %.s
	$(CC) $(CFLAGS) -c $<

# Compile code to assembly
%.s: %.c
	$(CC) $(CFLAGS) -S -c $<

# Build example1 executable
$(EXECS): %: %.o %.s
	$(CC) $(CFLAGS) -o $@ $< $(LFLAGS)

# Clean directory: remove object files and executables
.PHONY: clean cleanobj cleanasm
# Remove object files
cleanobj:
	-rm *.o
# Remove assembly files
cleanasm:
	-rm *.s
# Remove executables
clean: cleanobj
	-rm *.s $(EXECS)

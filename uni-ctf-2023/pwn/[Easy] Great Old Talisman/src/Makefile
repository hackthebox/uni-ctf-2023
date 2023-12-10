# Name of PROG and CFLAGS shall be changed.

PROG = great_old_talisman # CHANGE THIS
SRC = main.c
CFLAGS = -fstack-protector-all -no-pie -Wl,-z,relro -w #-Xlinker -rpath=./glibc/ -Xlinker -I./glibc/ld-linux-x86-64.so.2

all: compile 

compile:
	@echo "Compiling $(SRC) -> $(PROG)"
	gcc  $(SRC) -o $(PROG) $(CFLAGS)

clean:
	rm -f $(PROG)



CC = gcc

CFLAGS = -g -Wall -DSECP256K1_WIDEMUL_INT128

CPPFLAGS += -I../include -I../src 
CPPFLAGS += -I../secp256k1/include -I../secp256k1/src

LDFLAGS += -L../secp256k1/.libs
LDLIBS += -lsecp256k1
BINS = main

all: $(BINS)

main: main.o
	$(CC) $(LDFLAGS) $< $(LDLIBS) -o $@

main.o: main.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $< -o $@

clean:
	rm *.o $(BINS)

# My notes: (of GNU)
# LDFLAGS   - flags that compiler needs to pass to linker while invoking it. -- Ex: -Lmy-lib-dir
# LDLIBS    - library flag/name that compiler needs to pass to linker while invoking it. -- Ex: -lfoo.
# LOADLIBES - this is depreciated ut still supported. An alternative to LDLIBS.
# CPPFLAGS  - flags that compiler need to pass to the preprocessor. -- Ex: -Imy-include-dir, -DMACRO=1
# if rule of a target (let's say main) is left empty then GNU make executes: (for C files)
#	$(CC) $(CFLAGS) $(CPPFLAGS) $(LDFLAGS) main.c $(LDLIBS) -o main
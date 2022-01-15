CC = gcc
CFLAGS = -g -Wall

CPPFLAGS += -I../include -I../src -I$(HOME)/bin/include
LDFLAGS += -L$(HOME)/bin/lib/
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
# Lab server (64-bit) + the deliberately vulnerable 32-bit `stack` program.
#
#   stack          the lab hole: executable stack, no canary (SEED buffer-overflow lab)
#   stack-patched  same source with the protections on: the "patched" victim
#
# `stack` is static so the runtime image needs no 32-bit libc.
BUF_SIZE ?= 100

all: server stack stack-patched

server: server.c
	gcc -O0 -o $@ server.c

stack: stack.c
	gcc -m32 -static -O0 -DBUF_SIZE=$(BUF_SIZE) -DSHOW_FP \
	    -z execstack -fno-stack-protector -o $@ stack.c

stack-patched: stack.c
	gcc -m32 -static -O0 -DBUF_SIZE=$(BUF_SIZE) -DSHOW_FP \
	    -z noexecstack -fstack-protector-all -o $@ stack.c

clean:
	rm -f server stack stack-patched

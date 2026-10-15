CC ?= gcc
CFLAGS ?= -O2 -std=c11 -Wall -Wextra
LDFLAGS ?= -lOpenCL

.PHONY: all test clean

all: dfpow-gpu

dfpow-gpu: main.c dfpow_gpu.cl
	$(CC) $(CFLAGS) -o $@ main.c $(LDFLAGS)

test: dfpow-gpu
	./dfpow-gpu all 128

clean:
	rm -f dfpow-gpu

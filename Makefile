CC = gcc
CLANG = clang
ARCH_INC = -I/usr/include/x86_64-linux-gnu

all: build/libaether_mem.so build/aether_wake.bpf.o build/aether_runtime

build:
	mkdir -p build

build/libaether_mem.so: src/mem/aether_mem.c | build
	$(CC) -shared -fPIC -O2 -Wall -Wextra -o $@ $< -lpthread -ldl

build/aether_wake.bpf.o: src/bpf/aether_wake.bpf.c | build
	$(CLANG) -O2 -g -target bpf -D__TARGET_ARCH_x86 $(ARCH_INC) -Wall -c $< -o $@

build/aether_runtime: src/runtime/aether_runtime.c | build
	$(CC) -O2 -Wall -Wextra -o $@ $< -lbpf -lpthread

run: all
	sudo ./build/aether_runtime 8765 examples/stateful_ws_server.py

bench:
	python3 benchmarks/bench_100_ws.py

clean:
	rm -rf build

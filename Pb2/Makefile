# Makefile to build eBPF and Go userspace loader

BPF_CLANG=clang
BPF_CFLAGS=-O2 -g -Wall -target bpf -D__TARGET_ARCH=x86
BPF_SRC=bpf/process_drop.c
BPF_OBJ=bpf/process_drop.o

GO_SRC=main.go
GO_BIN=main

.PHONY: all clean

all: $(BPF_OBJ) $(GO_BIN)

$(BPF_OBJ): $(BPF_SRC)
	@echo "[+] Compiling eBPF program..."
	$(BPF_CLANG) $(BPF_CFLAGS) -c $< -o $@

$(GO_BIN): $(GO_SRC)
	@echo "[+] Building Go userspace loader..."
	go build -o $(GO_BIN) $(GO_SRC)

clean:
	@echo "[+] Cleaning build files..."
	rm -f $(BPF_OBJ) $(GO_BIN)

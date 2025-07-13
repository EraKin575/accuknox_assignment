# Makefile for building eBPF XDP program and Go userspace loader

# Paths
BPF_SRC      := bpf/tcp_packet.c
BPF_OBJ      := bpf/tcp_packet.o
GO_SRC       := main.go
GO_BIN       := loader

# Compiler and flags
CLANG        := clang
LLC          := llc
GO           := go

CFLAGS       := -O2 -g -Wall -target bpf -D__TARGET_ARCH_x86
INCLUDES     := -I./headers -I/usr/include

.PHONY: all bpf go clean run

# Default target
all: $(BPF_OBJ) $(GO_BIN)

# Compile eBPF C program to object file
$(BPF_OBJ): $(BPF_SRC)
	$(CLANG) $(CFLAGS) -c -o $@ $<

# Build Go userspace loader
$(GO_BIN): $(GO_SRC)
	$(GO) build -o $@ $<

# Run the loader with default arguments
run: all
	sudo ./$(GO_BIN) -iface eth0 -port 4040 -obj $(BPF_OBJ)

# Clean generated files
clean:
	rm -f $(BPF_OBJ) $(GO_BIN)

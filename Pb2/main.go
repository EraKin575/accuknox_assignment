package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

const (
	mapKey uint32 = 0
)

func main() {
	// CLI flags
	cgroupPath := flag.String("cgroup", "/sys/fs/cgroup/mygroup", "Path to cgroup v2 directory")
	procName := flag.String("proc", "curl", "Allowed process name (e.g. curl)")
	objPath := flag.String("obj", "tcp_comm_filter.o", "Path to compiled eBPF object file")
	flag.Parse()

	// Load compiled BPF object
	spec, err := ebpf.LoadCollectionSpec(*objPath)
	if err != nil {
		log.Fatalf("failed to load BPF spec: %v", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		log.Fatalf("failed to create BPF collection: %v", err)
	}
	defer coll.Close()

	// Get the BPF program by name
	prog := coll.Programs["filter_tcp_connect"]
	if prog == nil {
		log.Fatalf("program filter_tcp_connect not found")
	}

	// Get the allowed_comm map
	allowedMap := coll.Maps["allowed_comm"]
	if allowedMap == nil {
		log.Fatalf("map allowed_comm not found")
	}

	// Prepare padded process name (16 bytes)
	var comm [16]byte
	copy(comm[:], *procName)

	// Write it into the map
	if err := allowedMap.Update(mapKey, comm, ebpf.UpdateAny); err != nil {
		log.Fatalf("failed to update map: %v", err)
	}

	// Open the cgroup directory
	cgroupFd, err := os.Open(*cgroupPath)
	if err != nil {
		log.Fatalf("failed to open cgroup path: %v", err)
	}
	defer cgroupFd.Close()

	// Attach program to cgroup (connect4 = IPv4 TCP connect)
	l, err := link.AttachCgroup(link.CgroupOptions{
		Path:    cgroupFd.Name(),
		Attach:  ebpf.AttachCGroupInet4Connect,
		Program: prog,
	})
	if err != nil {
		log.Fatalf("failed to attach to cgroup: %v", err)
	}
	defer l.Close()

	fmt.Printf("✅ Attached program to cgroup %s, allowed process: %s\n", *cgroupPath, *procName)
	fmt.Println("Press ENTER to exit...")
	fmt.Scanln()
}

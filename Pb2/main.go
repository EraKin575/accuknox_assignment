package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"log"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/vishvananda/netlink"
)

const (
	mapKey uint32 = 0
)

func main() {
	// CLI arguments
	iface := flag.String("iface", "wlp57s0", "Interface to attach tc program to")
	proc := flag.String("proc", "nc", "Allowed process name (e.g. nc)")
	objPath := flag.String("obj", "tc_ingress.o", "Path to compiled eBPF object file")
	flag.Parse()

	// Load the eBPF object
	spec, err := ebpf.LoadCollectionSpec(*objPath)
	if err != nil {
		log.Fatalf("failed to load eBPF spec: %v", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		log.Fatalf("failed to create collection: %v", err)
	}
	defer coll.Close()

	// Get program
	prog := coll.Programs["tc_ingress"]
	if prog == nil {
		log.Fatalf("program tc_ingress not found")
	}

	// Get the BPF map
	allowedMap := coll.Maps["allowed_comm"]
	if allowedMap == nil {
		log.Fatalf("map allowed_comm not found")
	}

	// Pad proc name to 16 bytes (task->comm is fixed length)
	var comm [16]byte
	copy(comm[:], *proc)

	// Write it to the map
	if err := allowedMap.Update(mapKey, comm, ebpf.UpdateAny); err != nil {
		log.Fatalf("failed to update allowed_comm map: %v", err)
	}

	// Attach using tc
	linkIface, err := netlink.LinkByName(*iface)
	if err != nil {
		log.Fatalf("could not find interface %s: %v", *iface, err)
	}

	// First ensure qdisc is present
	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: linkIface.Attrs().Index,
			Handle:    netlink.MakeHandle(0xffff, 0),
			Parent:    netlink.HANDLE_CLSACT,
		},
		QdiscType: "clsact",
	}
	_ = netlink.QdiscAdd(qdisc) // ignore error if already exists

	// Attach program
     tcLink, err := link.AttachTCX(
		link.TCXOptions{
			Program:   prog,
			Interface: linkIface.Attrs().Index,
			
		},
	 )
	if err != nil {
		log.Fatalf("failed to attach tc program: %v", err)
	}
	defer tcLink.Close()

	fmt.Printf("✅ Program attached to %s, allowed process: %s\n", *iface, *proc)
	fmt.Println("Press ENTER to exit...")
	fmt.Scanln()
}

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
	configMapKey uint32 = 0
)

func main() {
	iface := flag.String("iface", "eth0", "Interface to attach XDP to")
	port := flag.Uint("port", 8080, "TCP port to drop")
	obj := flag.String("obj", "tcp_drop.o", "eBPF object file")
	flag.Parse()

	// Load compiled BPF object
	spec, err := ebpf.LoadCollectionSpec(*obj)
	if err != nil {
		log.Fatalf("Failed to load BPF spec: %v", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		log.Fatalf("Failed to create BPF collection: %v", err)
	}
	defer coll.Close()

	prog := coll.Programs["tcp_drop"]
	if prog == nil {
		log.Fatalf("Program tcp_drop not found")
	}

	// Get map and update port
	configMap := coll.Maps["config_map"]
	if configMap == nil {
		log.Fatalf("Map config_map not found")
	}

	portVal := make([]byte, 2)
	binary.BigEndian.PutUint16(portVal, uint16(*port))

	err = configMap.Update(configMapKey, portVal, ebpf.UpdateAny)
	if err != nil {
		log.Fatalf("Failed to update config_map: %v", err)
	}

	// Attach program to interface using XDP
	linkIface, err := netlink.LinkByName(*iface)
	if err != nil {
		log.Fatalf("Could not find interface %s: %v", *iface, err)
	}

	lnk, err := link.AttachXDP(link.XDPOptions{
		Program:   prog,
		Interface: linkIface.Attrs().Index,
		Flags:     link.XDPGenericMode,
	})
	if err != nil {
		log.Fatalf("Failed to attach XDP program: %v", err)
	}
	defer lnk.Close()

	fmt.Printf("XDP program attached to %s, dropping TCP dst port %d\n", *iface, *port)
	fmt.Println("Press Enter to detach and exit...")
	fmt.Scanln()
}

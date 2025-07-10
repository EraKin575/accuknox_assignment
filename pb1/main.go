package main

import (
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
	// Command-line flags
	iface := flag.String("iface", "eth0", "Interface to attach XDP to")
	port := flag.Uint("port", 4040, "TCP port to drop")
	obj := flag.String("obj", "tcp_packet.o", "eBPF object file")
	flag.Parse()

	// Load eBPF object (compiled with -target bpf)
	spec, err := ebpf.LoadCollectionSpec(*obj)
	if err != nil {
		log.Fatalf("Failed to load BPF spec: %v", err)
	}

	// Load the BPF collection (programs + maps)
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		log.Fatalf("Failed to create BPF collection: %v", err)
	}
	defer coll.Close()

	// Get the XDP program named "tcp_drop"
	prog := coll.Programs["tcp_drop"]
	if prog == nil {
		log.Fatalf("Program 'tcp_drop' not found in object")
	}

	// Get the map named "config_map"
	configMap := coll.Maps["config_map"]
	if configMap == nil {
		log.Fatalf("Map 'config_map' not found in object")
	}

	// Update the map with the desired TCP port (uint16)
	portVal := uint16(*port)
	fmt.Printf("Updating config_map: drop TCP dest port %d (0x%04x)\n", portVal, portVal)
	err = configMap.Update(configMapKey, &portVal, ebpf.UpdateAny)
	if err != nil {
		log.Fatalf("Failed to update config_map: %v", err)
	}

	// Lookup the network interface by name
	linkIface, err := netlink.LinkByName(*iface)
	if err != nil {
		log.Fatalf("Could not find interface %s: %v", *iface, err)
	}

	// Attach the XDP program to the interface in generic mode
	lnk, err := link.AttachXDP(link.XDPOptions{
		Program:   prog,
		Interface: linkIface.Attrs().Index,
		Flags:     link.XDPGenericMode, // or link.XDPDriverMode if supported
	})
	if err != nil {
		log.Fatalf("Failed to attach XDP program: %v", err)
	}
	defer lnk.Close()

	fmt.Printf("✅ XDP program 'tcp_drop' attached to %s\n", *iface)
	fmt.Println("🔒 TCP packets to destination port", *port, "will be dropped")
	fmt.Println("⏳ Press Enter to detach and exit...")
	fmt.Scanln()
}

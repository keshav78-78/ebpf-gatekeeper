package main

import (
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

func main() {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("remove memlock: %v", err)
	}

	const objPath = "bpf/xdp_dropper.bpf.o"
	spec, err := ebpf.LoadCollectionSpec(objPath)
	if err != nil {
		log.Fatalf("loading BPF spec: %v", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		log.Fatalf("creating BPF collection: %v", err)
	}
	defer coll.Close()

	var prog *ebpf.Program
	if p, ok := coll.Programs["drop_tcp_port"]; ok {
		prog = p
	} else if p, ok := coll.Programs["xdp"]; ok {
		prog = p
	} else {
		for _, p := range coll.Programs {
			prog = p
			break
		}
	}

	if prog == nil {
		log.Fatalf("could not find XDP program in collection")
	}

	ifaceName := "lo"
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		log.Fatalf("getting interface %s: %v", ifaceName, err)
	}

	l, err := link.AttachXDP(link.XDPOptions{
		Program:   prog,
		Interface: iface.Index,
	})
	if err != nil {
		log.Fatalf("attaching XDP program: %v", err)
	}
	defer l.Close()

	log.Printf("XDP program attached on %s (ifindex=%d). Drop port 4040.", ifaceName, iface.Index)
	log.Println("Press Ctrl+C to detach and exit.")

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop

	log.Println("detaching and exiting...")
}

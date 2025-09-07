package main

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

func main() {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("remove memlock: %v", err)
	}

	const objPath = "bpf/xdp_dropper_dynamic.bpf.o"
	spec, err := ebpf.LoadCollectionSpec(objPath)
	if err != nil {
		log.Fatalf("loading BPF spec: %v", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		log.Fatalf("creating BPF collection: %v", err)
	}
	defer coll.Close()

	prog, ok := coll.Programs["drop_tcp_port_dynamic"]
	if !ok {
		log.Fatalf("could not find program drop_tcp_port_dynamic in collection")
	}

	configMap, ok := coll.Maps["config_map"]
	if !ok {
		log.Fatalf("could not find config_map in collection")
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

	log.Printf("Dynamic gatekeeper attached to %s.", ifaceName)
	log.Println("Enter a port number to block (or 0 to disable). Press Ctrl+C to exit.")

	go func() {
		scanner := bufio.NewScanner(os.Stdin)
		for {
			fmt.Print("Enter port to block > ")
			if !scanner.Scan() {
				return
			}

			portStr := strings.TrimSpace(scanner.Text())
			port, err := strconv.ParseUint(portStr, 10, 16)
			if err != nil {
				log.Printf("Invalid port number: %v", err)
				continue
			}

			key := uint32(0)
			value := uint16(port)

			if err := configMap.Update(&key, &value, ebpf.UpdateAny); err != nil {
				log.Printf("Failed to update config map: %v", err)
			} else {
				if value == 0 {
					log.Printf("Port filtering is now DISABLED.")
				} else {
					log.Printf("--> Now blocking TCP traffic on port %d.", value)
				}
			}
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop

	log.Println("detaching and exiting...")
}

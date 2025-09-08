package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go bpf ../../bpf/process_filter.bpf.c -- -I/usr/include -I/usr/include/x86_64-linux-gnu

const (
	targetProcessName = "myprocess"
	cgroupPath        = "/sys/fs/cgroup/process_gatekeeper"
)

func findProcessPID(name string) (int, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return -1, err
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pidNum, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		commPath := filepath.Join("/proc", entry.Name(), "comm")
		comm, err := os.ReadFile(commPath)
		if err == nil && strings.TrimSpace(string(comm)) == name {
			return pidNum, nil
		}
		cmdlinePath := filepath.Join("/proc", entry.Name(), "cmdline")
		cmdline, err := os.ReadFile(cmdlinePath)
		if err == nil && strings.Contains(string(cmdline), name) {
			return pidNum, nil
		}
	}
	return -1, fmt.Errorf("process '%s' not found", name)
}

func ensureCgroup() error {
	return os.MkdirAll(cgroupPath, 0755)
}

func moveToCgroup(pid int) error {
	procsFile := filepath.Join(cgroupPath, "cgroup.procs")
	data := []byte(strconv.Itoa(pid) + "\n")
	if err := os.WriteFile(procsFile, data, 0644); err != nil {
		return err
	}
	return nil
}

func cleanupCgroup() {
	_ = os.Remove(cgroupPath)
}

func main() {
	log.Println("Starting process-aware gatekeeper...")

	if os.Geteuid() != 0 {
		log.Fatal("must run as root")
	}

	if err := ensureCgroup(); err != nil {
		log.Fatalf("setup cgroup: %v", err)
	}
	defer cleanupCgroup()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		for {
			pid, err := findProcessPID(targetProcessName)
			if err == nil {
				_ = moveToCgroup(pid)
			}
			time.Sleep(2 * time.Second)
		}
	}()

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("remove memlock: %v", err)
	}

	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("Loading BPF objects: %v", err)
	}
	defer objs.Close()

	kp, err := link.Kprobe("tcp_connect", objs.TraceTcpConnect, nil)
	if err != nil {
		log.Fatalf("Attaching kprobe: %v", err)
	}
	defer kp.Close()
	log.Println("Attached kprobe to trace TCP connections.")

	l, err := link.AttachCgroup(link.CgroupOptions{
		Path:    cgroupPath,
		Attach:  ebpf.AttachCGroupInetEgress,
		Program: objs.FilterEgress,
	})
	if err != nil {
		log.Fatalf("Attaching cgroup egress program: %v", err)
	}
	defer l.Close()
	log.Printf("Attached egress filter to cgroup %s.", cgroupPath)

	log.Println("Policy active: 'myprocess' can only connect to TCP port 4040.")
	log.Println("Press Ctrl+C to exit and clean up.")

	<-stop
	log.Println("Shutting down")
}

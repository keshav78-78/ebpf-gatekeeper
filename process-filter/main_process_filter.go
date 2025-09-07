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
)

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

func setupCgroup(pid int) error {
	log.Printf("Setting up cgroup for PID %d at %s", pid, cgroupPath)

	if err := os.MkdirAll(cgroupPath, 0755); err != nil {
		return fmt.Errorf("failed to create cgroup directory: %w", err)
	}

	procsFile := filepath.Join(cgroupPath, "cgroup.procs")
	data := []byte(strconv.Itoa(pid) + "\n")
	if err := os.WriteFile(procsFile, data, 0644); err != nil {
		return fmt.Errorf("failed to move PID %d to cgroup: %w", pid, err)
	}
	log.Printf("Successfully moved PID %d to cgroup %s", pid, cgroupPath)
	return nil
}

func cleanupCgroup() {
	log.Printf("Cleaning up cgroup at %s", cgroupPath)

	procsFile := filepath.Join(cgroupPath, "cgroup.procs")
	content, err := os.ReadFile(procsFile)
	if err == nil && len(content) > 0 {
		parent := filepath.Dir(cgroupPath)
		parentProcs := filepath.Join(parent, "cgroup.procs")
		if _, statErr := os.Stat(parentProcs); statErr == nil {
			if werr := os.WriteFile(parentProcs, content, 0644); werr != nil {
				log.Printf("Warning: failed to move PIDs back to parent cgroup: %v", werr)
			}
		} else {
			log.Printf("Parent cgroup procs file not found: %v", statErr)
		}
	}

	if err := os.Remove(cgroupPath); err != nil {
		log.Printf("Warning: failed to remove cgroup directory: %v", err)
	}
}

func main() {
	log.Println("Starting process-aware gatekeeper...")

	if os.Geteuid() != 0 {
		log.Fatal("This program must be run as root (sudo) to manage cgroups.")
	}

	pid, err := findProcessPID(targetProcessName)
	if err != nil {
		log.Fatalf("Could not find target process: %v\nPlease start a process named '%s' in another terminal.", err, targetProcessName)
	}
	log.Printf("Found target process '%s' with PID: %d", targetProcessName, pid)
	if err := setupCgroup(pid); err != nil {
		log.Fatalf("Failed to set up cgroup: %v", err)
	}
	defer cleanupCgroup()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh
	log.Println("Received signal, exiting...")
}

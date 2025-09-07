eBPF Gatekeeper 🛡️

Overview 📝

eBPF Gatekeeper is a demonstration of network traffic filtering using eBPF (Extended Berkeley Packet Filter) with Go. This project provides a set of tools to control network traffic at the packet level, offering both static and dynamic filtering capabilities, as well as process-aware filtering.

Features ✨

  Static Traffic Filtering** 🚦: The `gatekeeper` application blocks TCP traffic on a hardcoded port (4040) using an XDP (eXpress Data Path) program for high-performance packet processing.
  Dynamic Traffic Filtering** ⚙️: The `dynamic-gatekeeper` allows for runtime configuration of traffic filtering rules. Users can specify a port to block dynamically, providing a flexible way to manage network policies.
  Process-Aware Filtering** 🎯: The `process-gatekeeper` can identify a process by its name, move it to a dedicated cgroup, and apply network filtering rules to that specific process, enabling fine-grained control over application traffic.

System Requirements 💻

   Go programming language
   Clang/LLVM
   A Linux kernel with eBPF support (version 4.8 or later recommended)

Installation and Building 🛠️

To build the eBPF programs and Go applications, execute the following command from the root of the project directory:

```bash
make all
```

This will compile the eBPF source code and the Go applications, placing the resulting binaries in the `bin/` directory.

Usage 🚀

Static Gatekeeper

The static gatekeeper blocks TCP traffic on port 4040. To run this application, use the following command:

```bash
sudo ./bin/gatekeeper
```

Dynamic Gatekeeper

The dynamic gatekeeper allows for real-time control over which TCP port to block. To use the dynamic gatekeeper, run:

```bash
sudo ./bin/dynamic-gatekeeper
```

After launching the application, you will be prompted to enter a port number to block. To disable port filtering, enter `0`.

Process-Aware Gatekeeper

The process-aware gatekeeper identifies a running process named "myprocess" and moves it to a cgroup for traffic filtering. A process with this name must be running for the gatekeeper to function correctly.

To run the process-aware gatekeeper, execute:

```bash
sudo ./bin/process-gatekeeper
```

Note: All gatekeeper applications require root privileges to load and attach eBPF programs to network interfaces and to manage cgroups.

Project Structure 📁

  - `bpf/`: Contains the eBPF C source code for the XDP and process filtering programs.
  - `cmd/`: Contains the Go source code for the user-space applications that interact with the eBPF programs.
  - `process-filter/`: Contains the Go source code for the process-aware gatekeeper.
  - `makefile`: Provides rules for building and cleaning the project.

Cleanup 🧹

To remove all compiled object files and binaries, run:

```bash
make clean
```

package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/sys/unix"
)

const (
	bpfProgramPath = "./bpf/latency.o"
	memLockLimit   = 1000 * 1024 * 1024 // 1GB
)

type LatencyT struct {
	TimestampIn  uint64
	TimestampOut uint64
	Delta        uint64
}

type IPv4Key struct {
	SrcIP  uint32
	DstIP  uint32
	Id     uint32
	HProto uint8
	// add padding to match the size of the struct in the BPF program
	_ [3]byte
}

var (
	Latency = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "packets_count",
			Help: "Number of packets received",
		},
		[]string{"src_ip", "dst_ip"},
	)
)

func init() {
	prometheus.MustRegister(Latency)
}

func main() {
	// Set the RLIMIT_MEMLOCK resource limit
	var rLimit unix.Rlimit
	rLimit.Cur = memLockLimit
	rLimit.Max = memLockLimit
	if err := unix.Setrlimit(unix.RLIMIT_MEMLOCK, &rLimit); err != nil {
		log.Fatalf("Failed to set RLIMIT_MEMLOCK: %v", err)
	}

	// Parse the ELF file containing the BPF program
	spec, err := ebpf.LoadCollectionSpec(bpfProgramPath)
	if err != nil {
		log.Fatalf("Failed to load BPF program: %v", err)
	}

	// Load the BPF program into the kernel
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		log.Fatalf("Failed to create BPF collection: %v", err)
	}
	defer coll.Close()

	// Attach BPF programs to kprobe receive events
	tp_rcv, err := link.Kprobe("ip_rcv", coll.Programs["ip_rcv"], &link.KprobeOptions{})
	if err != nil {
		log.Fatalf("Failed to attach trace_ip: %v", err)
	}
	defer tp_rcv.Close()

	// Attach BPF programs to kprobe return events
	tp_ret, err := link.Kprobe("ip_rcv_finish", coll.Programs["ip_rcv_finish"], &link.KprobeOptions{})
	if err != nil {
		log.Fatalf("Failed to attach trace_ip_output: %v", err)
	}

	// Set up ring buffer to read data from BPF program
	reader, err := ringbuf.NewReader(coll.Maps["events"])
	if err != nil {
		log.Fatalf("Failed to get ring: %v", err)
	}

	// Handle signals for graceful shutdown
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	// Goroutine to handle graceful shutdown on receiving a signal
	go func() {
		<-sig
		tp_rcv.Close()
		tp_ret.Close()
		coll.Close()
		os.Exit(0)
	}()

	// Read and print the output from the eBPF program
	var event struct {
		TimestampIn  uint64
		TimestampOut uint64
		Delta        uint64
	}

	for {

		// Read data from the ring buffer
		data, err := reader.Read()
		if err != nil {
			log.Fatalf("Failed to read from ring buffer: %v", err)
		}

		if err := binary.Read(bytes.NewReader(data.RawSample), binary.LittleEndian, &event); err != nil {
			log.Printf("Failed to parse ring event: %v", err)
			continue
		}

		fmt.Printf("TimestampIn: %d, TimestampOut: %d, Delta: %d\n", event.TimestampIn, event.TimestampOut, event.Delta)
	}

	// // Start Prometheus HTTP server
	// http.Handle("/metrics", promhttp.Handler())
	// log.Fatal(http.ListenAndServe(":2112", nil))
}

// func toIpV4(ip uint32) string {
// 	ipOut := make(net.IP, 4)                 // Create a 4-byte IP address
// 	binary.LittleEndian.PutUint32(ipOut, ip) // Convert uint32 to byte slice in little-endian order
// 	return ipOut.String()                    // Convert IP address to string format
// }

package main

import (
	"encoding/binary"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"golang.org/x/sys/unix"
)

const (
	bpfProgramPath = "./bpf/latency.o"
	memLockLimit   = 1000 * 1024 * 1024 // 1GB
)

type LatencyT struct {
	TimestampIn uint64
	Latency     uint64
}

type IPv4Key struct {
	SrcIP  uint32
	DstIP  uint32
	HProto uint8
	Check  uint16
	// add padding to match the size of the struct in the BPF program
	_ [1]byte
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
	tp_rcv, err := link.Kprobe("ip_rcv", coll.Programs["trace_ip_rcv"], &link.KprobeOptions{})
	if err != nil {
		log.Fatalf("Failed to attach trace_ip: %v", err)
	}
	defer tp_rcv.Close()

	// Attach BPF programs to kprobe return events
	tp_ret, err := link.Kprobe("ip_output", coll.Programs["trace_ip_output"], &link.KprobeOptions{})
	if err != nil {
		log.Fatalf("Failed to attach trace_ip_output: %v", err)
	}

	// Open BPF map
	latencyMap := coll.Maps["latency_map"]
	if latencyMap == nil {
		log.Fatalf("Failed to find latency_map")
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

	go func() {
		for {
			var key IPv4Key
			var value LatencyT

			// Get data from the BPF_MAP_TYPE_HASH
			iterator := latencyMap.Iterate()

			for iterator.Next(&key, &value) {
				srcIP := toIpV4(key.SrcIP)
				dstIP := toIpV4(key.DstIP)
				Latency.WithLabelValues(srcIP, dstIP).Set(float64(value.Latency))
				// latencyHistogram.WithLabelValues(srcIP, dstIP).Observe(float64(value.TimestampIn))
				if err := iterator.Err(); err != nil {
					log.Fatalf("Failed to iterate over latency_map: %v", err)
				}
			}
		}
	}()

	// Start Prometheus HTTP server
	http.Handle("/metrics", promhttp.Handler())
	log.Fatal(http.ListenAndServe(":2112", nil))
}

func toIpV4(ip uint32) string {
	ipOut := make(net.IP, 4)                 // Create a 4-byte IP address
	binary.LittleEndian.PutUint32(ipOut, ip) // Convert uint32 to byte slice in little-endian order
	return ipOut.String()                    // Convert IP address to string format
}

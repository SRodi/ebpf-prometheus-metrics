package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"golang.org/x/sys/unix"
)

const (
	bpfProgramPath = "./bpf/latency.o"
	memLockLimit   = 100 * 1024 * 1024 // 100MB
)

type LatencyT struct {
	TimestampIn  uint64
	TimestampOut uint64
	Delta        uint64
	Layer3       L3
}

type L3 struct {
	SrcIP  uint32
	DstIP  uint32
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
	LatencyIstogram = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "latency_histogram",
			Help:    "Latency histogram",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"src_ip", "dst_ip"},
	)
)

func init() {
	prometheus.MustRegister(Latency)
	prometheus.MustRegister(LatencyIstogram)
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

	go func() {
		// Read and print the output from the eBPF program
		var event LatencyT

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

			// Convert IP addresses to string format
			srcIP := toIpV4(event.Layer3.SrcIP)
			dstIP := toIpV4(event.Layer3.DstIP)

			// Increment Prometheus metric
			Latency.WithLabelValues(srcIP, dstIP).Inc()
			LatencyIstogram.WithLabelValues(srcIP, dstIP).Observe(float64(event.Delta))

			// Print the output
			fmt.Printf("TimestampIn: %s, TimestampOut: %s, Delta: %d, SrcIP: %s, DstIP: %s, HProto: %s\n", timestampToString(event.TimestampIn), timestampToString(event.TimestampOut), event.Delta, srcIP, dstIP, protoToString(event.Layer3.HProto))
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

func protoToString(protocol uint8) string {
	switch protocol {
	case 1:
		return "ICMP"
	case 2:
		return "IGMP"
	case 6:
		return "TCP"
	case 17:
		return "UDP"
	case 89:
		return "OSPF"
	default:
		return "Unknown"
	}
}

func timestampToString(timestamp uint64) string {
	// Convert the timestamp to a time.Time object
	t := time.Unix(0, int64(timestamp))
	// Format the time.Time object to a human-readable string
	return t.Format(time.RFC3339)
}

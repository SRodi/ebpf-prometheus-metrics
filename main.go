package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"golang.org/x/sys/unix"
)

const (
	bpfProgramPath = "./bpf/latency.o"
	memLockLimit   = 1000 * 1024 * 1024 // 1GB
)

type LatencyEvent struct {
	Timestamp uint64
	SrcIP     uint32
	DstIP     uint32
}

var (
	latencyHistogram = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "packet_latency",
			Help:    "Packet latency in nanoseconds",
			Buckets: prometheus.LinearBuckets(0, 1000000, 10), // 10 buckets, each 1ms wide
		},
		[]string{"src_ip", "dst_ip"},
	)
)

func init() {
	prometheus.MustRegister(latencyHistogram)
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

	// Attach BPF programs to receive tracepoint events
	tp_rcv, err := link.Tracepoint("net", "netif_receive_skb", coll.Programs["trace_ip"], nil)
	if err != nil {
		log.Fatalf("Failed to attach trace_ip: %v", err)
	}
	tp_rcv.Close()

	// Attach BPF programs to return tracepoint events
	tp_ret, err := link.Tracepoint("net", "net_dev_queue", coll.Programs["trace_ip_return"], nil)
	if err != nil {
		log.Fatalf("Failed to attach trace_ip_return: %v", err)
	}
	tp_ret.Close()

	// Open BPF map
	latencyMap := coll.Maps["latency_map"]
	if latencyMap == nil {
		log.Fatalf("Failed to find latency_map")
	}

	// Poll the BPF map for latency data
	reader, err := perf.NewReader(latencyMap, 4096)
	if err != nil {
		log.Fatalf("Failed to create perf reader: %v", err)
	}
	defer reader.Close()

	// Handle signals for graceful shutdown
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	// Goroutine to handle graceful shutdown on receiving a signal
	go func() {
		<-sig
		// reader.Close()
		tp_rcv.Close()
		tp_ret.Close()
		coll.Close()
		os.Exit(0)
	}()

	go func() {
		for {
			record, err := reader.Read()
			if err != nil {
				log.Printf("Failed to read from perf reader: %v", err)
				continue
			}

			var event LatencyEvent
			if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event); err != nil {
				log.Printf("Failed to decode received data: %v", err)
				continue
			}

			srcIP := fmt.Sprintf("%d.%d.%d.%d", byte(event.SrcIP>>24), byte(event.SrcIP>>16), byte(event.SrcIP>>8), byte(event.SrcIP))
			dstIP := fmt.Sprintf("%d.%d.%d.%d", byte(event.DstIP>>24), byte(event.DstIP>>16), byte(event.DstIP>>8), byte(event.DstIP))
			latencyHistogram.WithLabelValues(srcIP, dstIP).Observe(float64(event.Timestamp))
		}
	}()

	// Start Prometheus HTTP server
	http.Handle("/metrics", promhttp.Handler())
	log.Fatal(http.ListenAndServe(":2112", nil))
}

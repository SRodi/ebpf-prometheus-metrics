package main

/*
#include "bpf/xdp_ebpf.c"
*/
import "C"
import (
	"log"
	"net"
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
	bpfFilePath  = "./bpf/xdp_ebpf.o"
	bpfProgName  = "xdp_prog"
	memLockLimit = 64 * 1024 * 1024 // 64 MiB
)

var (
	packets = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "xdp_packets_total",
			Help: "Total number of packets processed by XDP",
		},
		[]string{"interface"},
	)
)

func init() {
	prometheus.MustRegister(packets)
}

func main() {
	// Set the RLIMIT_MEMLOCK resource limit
	var rLimit unix.Rlimit
	rLimit.Cur = memLockLimit
	rLimit.Max = memLockLimit
	if err := unix.Setrlimit(unix.RLIMIT_MEMLOCK, &rLimit); err != nil {
		log.Fatalf("Failed to set RLIMIT_MEMLOCK: %v", err)
	}

	// Load the eBPF collection
	coll, err := ebpf.LoadCollection(bpfFilePath)
	if err != nil {
		log.Fatalf("failed to load eBPF collection: %v", err)
	}
	defer coll.Close()

	// get eth0's ifindex
	ifaceName := "eth0"
	ifaceObj, err := net.InterfaceByName(ifaceName)
	if err != nil {
		log.Fatalf("failed to get interface %s: %v", ifaceName, err)
	}

	// Attach the eBPF program to the XDP hook
	link, err := link.AttachXDP(link.XDPOptions{
		Program:   coll.Programs[bpfProgName],
		Interface: ifaceObj.Index,
	})
	if err != nil {
		log.Fatalf("failed to attach eBPF program to interface %s: %v", ifaceName, err)
	}
	// sudo bpftool link list
	// sudo bpftool link detach id <link_id>
	defer link.Close()

	// Ensure the "events" map is not nil
	eventsMap, ok := coll.Maps["events"]
	if !ok || eventsMap == nil {
		log.Fatal("eBPF map 'events' is not initialized")
	}

	// Create a perf reader with options
	reader, err := perf.NewReaderWithOptions(eventsMap, 4096, perf.ReaderOptions{})
	if err != nil {
		log.Fatalf("failed to create perf reader: %v", err)
	}
	defer reader.Close()

	// Handle signals for graceful shutdown
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		for {
			select {
			case <-sig:
				// Handle graceful shutdown on SIGINT and SIGTERM
				log.Println("Shutting down...")
				link.Close()
				reader.Close()
				os.Exit(0)
			default:
				// Read from perf event reader
				record, err := reader.Read()
				if err != nil {
					log.Printf("failed to read from perf reader: %v", err)
					continue
				}

				if record.LostSamples > 0 {
					log.Printf("lost %d samples", record.LostSamples)
					continue
				}

				// Update Prometheus metrics based on the event data
				updateMetrics("ifaceName")
			}
		}
	}()

	http.Handle("/metrics", promhttp.Handler())
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func updateMetrics(iface string) {
	packets.WithLabelValues(iface).Inc()
}

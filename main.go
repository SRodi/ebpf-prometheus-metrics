package main

/*
#include "bpf/xdp_ebpf.c"
*/
import "C"
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
	"github.com/cilium/ebpf/rlimit"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const (
	bpfFilePath  = "./bpf/xdp_ebpf.o"
	bpfProgName  = "ddos_protection"
	memLockLimit = 64 * 1024 * 1024 // 64 MiB
)

var packets = prometheus.NewGaugeVec(
	prometheus.GaugeOpts{
		Name: "xdp_packets_count",
		Help: "Total number of packets processed by XDP",
	},
	[]string{"src_ip"},
)

type RateLimitEntry struct {
	LastUpdate  uint64
	PacketCount uint32
	// padding to align to 8 bytes
	_ [4]byte
}

func init() {
	prometheus.MustRegister(packets)
}

func main() {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("failed to remove memlock: %v", err)
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
				os.Exit(0)
			default:
				// Iterate through the map.
				it := coll.Maps["rate_limit_map"].Iterate()
				var key uint32
				var value RateLimitEntry

				for it.Next(&key, &value) {
					updateMetrics(key, value)
				}

				if err := it.Err(); err != nil {
					log.Fatalf("failed to iterate map: %v", err)
				}
			}
		}
	}()

	http.Handle("/metrics", promhttp.Handler())
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func uint32ToIP(nn uint32) net.IP {
	ip := make(net.IP, 4)
	binary.LittleEndian.PutUint32(ip, nn)
	return ip
}

func updateMetrics(key uint32, value RateLimitEntry) {
	srcIp := uint32ToIP(key)

	packets.WithLabelValues(srcIp.String()).Set(float64(value.PacketCount))
}

package main

import (
	"bytes"
	"context"
	_ "embed"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// Embed the compiled eBPF object file
//
//go:embed latency_bpf.o
var ebpfProgram []byte

// Prometheus metrics
var (
	networkLatency = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "network_latency_seconds",
			Help:    "Histogram of network latency with pod names as labels.",
			Buckets: prometheus.ExponentialBuckets(0.00001, 2, 15), // From 10µs to ~32s
		},
		[]string{"src_pod", "dst_pod"},
	)

	k8sClient *kubernetes.Clientset
)

func ipToString(ip uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d", byte(ip), byte(ip>>8), byte(ip>>16), byte(ip>>24))
}

func main() {
	// Initialize Kubernetes client
	config, err := rest.InClusterConfig()
	if err != nil {
		log.Fatalf("Failed to create Kubernetes client config: %v", err)
	}
	k8sClient, err = kubernetes.NewForConfig(config)
	if err != nil {
		log.Fatalf("Failed to create Kubernetes client: %v", err)
	}

	// Load the eBPF program
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(ebpfProgram))
	if err != nil {
		log.Fatalf("Failed to load eBPF spec: %v", err)
	}

	objects := struct {
		IpRcv        *ebpf.Program `ebpf:"trace_ip_rcv"`
		DevQueueXmit *ebpf.Program `ebpf:"trace_dev_queue_xmit"`
		HistogramMap *ebpf.Map     `ebpf:"latency_histogram"`
	}{}

	if err := spec.LoadAndAssign(&objects, nil); err != nil {
		log.Fatalf("Failed to load and assign eBPF objects: %v", err)
	}
	defer objects.HistogramMap.Close()
	defer objects.IpRcv.Close()
	defer objects.DevQueueXmit.Close()

	// Attach the eBPF programs to kprobes
	ipRcvLink, err := link.Kprobe("ip_rcv", objects.IpRcv, nil)
	if err != nil {
		log.Fatalf("Failed to attach ip_rcv kprobe: %v", err)
	}
	defer ipRcvLink.Close()

	devQueueXmitLink, err := link.Kprobe("dev_queue_xmit", objects.DevQueueXmit, nil)
	if err != nil {
		log.Fatalf("Failed to attach dev_queue_xmit kprobe: %v", err)
	}
	defer devQueueXmitLink.Close()

	log.Println("eBPF programs successfully loaded and attached")

	// Collect data from the eBPF histogram map
	go func() {
		for {
			var key struct {
				SrcIP uint32
				DstIP uint32
			}
			var latency uint64

			iter := objects.HistogramMap.Iterate()
			for iter.Next(&key, &latency) {
				srcIP := ipToString(key.SrcIP)
				dstIP := ipToString(key.DstIP)
				srcPod := ipToPod(srcIP)
				dstPod := ipToPod(dstIP)

				// Convert latency from ns to seconds and observe the metric
				networkLatency.WithLabelValues(srcPod, dstPod).Observe(float64(latency) / 1e9)
			}

			if err := iter.Err(); err != nil {
				log.Printf("Error reading eBPF map: %v", err)
			}

			time.Sleep(10 * time.Second)
		}
	}()

	// Register Prometheus metrics and serve HTTP
	prometheus.MustRegister(networkLatency)
	http.Handle("/metrics", promhttp.Handler())
	log.Fatal(http.ListenAndServe(":8080", nil))
}

// ipToPod resolves an IP address to a Kubernetes pod name
func ipToPod(ip string) string {
	pods, err := k8sClient.CoreV1().Pods("").List(context.TODO(), v1.ListOptions{})
	if err != nil {
		log.Printf("Failed to list pods: %v", err)
		return ip
	}

	for _, pod := range pods.Items {
		if pod.Status.PodIP == ip {
			return pod.Name
		}
	}

	// Return IP if no pod is found
	return ip
}

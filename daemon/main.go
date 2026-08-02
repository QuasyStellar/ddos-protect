package main

import (
	"bufio"
	"errors"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

func main() {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Failed to remove memlock: %v", err)
	}

	rateLimitPps, err := strconv.ParseUint(os.Getenv("RATE_LIMIT_PPS"), 10, 32)
	if err != nil || rateLimitPps == 0 {
		if os.Getenv("RATE_LIMIT_PPS") == "0" {
			log.Printf("RATE_LIMIT_PPS=0 is not supported; defaulting to 100000. Use a small value like 10 to effectively disable rate limiting.")
		}
		rateLimitPps = 100000
	}
	globalUdpPps, err := strconv.ParseUint(os.Getenv("GLOBAL_UDP_PPS"), 10, 32)
	if err != nil || globalUdpPps == 0 {
		globalUdpPps = 2000000
	}

	// Tune host kernel parameters (requires privileged: true)
	tuneSysctl()

	spec, err := LoadXdpFilter()
	if err != nil {
		log.Fatalf("Loading spec: %v", err)
	}

	// Dynamically determine eBPF Map sizes based on available RAM
	// Prefer cgroup memory limit (container-aware) over MemTotal
	ram := getAvailableRAM()
	factor := float64(ram) / (2.0 * 1024 * 1024 * 1024) // 2GB base
	if factor < 0.25 {
		factor = 0.25
	} // Min 500MB scale
	if factor > 10.0 {
		factor = 10.0
	} // Max 20GB scale

	baseEntries := uint32(100000 * factor)
	if m := spec.Maps["rate_limit_map"]; m != nil {
		m.MaxEntries = baseEntries
	}
	if m := spec.Maps["ip_bloom_map"]; m != nil {
		m.MaxEntries = baseEntries * 10
	}
	log.Printf("Dynamically allocated map sizes for %.1f GB RAM: LRU=%d, Bloom=%d", float64(ram)/(1024*1024*1024), baseEntries, baseEntries*10)

	objs := XdpFilterObjects{}
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			log.Fatalf("Verifier error details:\n%+v", ve)
		}
		log.Fatalf("Loading objects: %v", err)
	}
	defer objs.Close()

	allowedSni := os.Getenv("ALLOWED_SNI")
	sniFiltering := uint32(0)
	if allowedSni != "" {
		sniFiltering = 1
	}

	strictTcp := uint32(0)
	if os.Getenv("STRICT_TCP_TRACKING") == "1" {
		strictTcp = 1
	}

	// Push configuration to BPF map dynamically
	err = objs.ConfigMap.Put(uint32(0), XdpFilterConfigData{
		RateLimitPps:      uint32(rateLimitPps),
		GlobalUdpPps:      uint32(globalUdpPps),
		SniFiltering:      sniFiltering,
		StrictTcpTracking: strictTcp,
	})
	if err != nil {
		log.Fatalf("Failed to write to config map: %v", err)
	}

	// Populate SNI Map
	if sniFiltering == 1 {
		for _, domain := range strings.Split(allowedSni, ",") {
			domain = strings.ToLower(strings.TrimSpace(domain))
			if domain == "" {
				continue
			}

			hash := uint64(0xcbf29ce484222325)
			for i := 0; i < len(domain); i++ {
				hash ^= uint64(domain[i])
				hash *= 0x100000001b3
			}

			if err := objs.SniMap.Put(hash, uint8(1)); err != nil {
				log.Printf("Failed to insert SNI %s into map: %v", domain, err)
			} else {
				log.Printf("Whitelisted SNI: %s (Hash: %x)", domain, hash)
			}
		}
	}

	// Populate Allowed Ports Array Map
	allowedPortsStr := os.Getenv("ALLOWED_PORTS")
	if allowedPortsStr == "" {
		allowedPortsStr = "80,443,8443" // Default safe ports
	}
	for _, pstr := range strings.Split(allowedPortsStr, ",") {
		pstr = strings.TrimSpace(pstr)
		if pstr == "" {
			continue
		}
		port, err := strconv.ParseUint(pstr, 10, 16)
		if err != nil {
			log.Printf("Invalid port in ALLOWED_PORTS %q (max 65535): %v", pstr, err)
			continue
		}
		if err := objs.AllowedPortsMap.Put(uint32(port), uint8(1)); err != nil {
			log.Printf("Failed to insert allowed port %d: %v", port, err)
		} else {
			log.Printf("Allowed Port (Fast-Path): %d", port)
		}
	}

	ifaceName := os.Getenv("IFACE")
	if ifaceName == "" {
		ifaceName = "eth0" // Fallback
	}
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		log.Fatalf("Lookup network iface %q: %s", ifaceName, err)
	}

	// Attach the program to the interface.
	l, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpDdosFilter,
		Interface: iface.Index,
	})
	if err != nil {
		log.Fatalf("Could not attach XDP program: %s", err)
	}
	defer l.Close()

	log.Printf("Attached XDP program to iface %q (index %d)", iface.Name, iface.Index)

	// Start Prometheus metrics server and BPF polling loop
	startMetricsServer(&objs)

	// Start GeoLoader to populate blocked IP zones
	blockedCountries := os.Getenv("BLOCKED_COUNTRIES")
	startGeoLoader(&objs, blockedCountries)

	// Start XDP-Aware NAT Sync for NextPATH
	startNatSync(&objs)

	// Start Phase 2: EWMA Adaptive Rate Limiter
	log.Printf("Starting Adaptive EWMA Rate Limiter (Base TCP: %d, UDP: %d)", rateLimitPps, globalUdpPps)
	startAdaptiveRateLimiter(&objs, uint32(rateLimitPps), uint32(globalUdpPps), sniFiltering, strictTcp)

	// Wait for interrupt signal.
	log.Printf("DDOS-Protect Daemon is running optimally! Press CTRL+C to exit.")
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	<-c
	log.Println("Exiting daemon...")
}

// getAvailableRAM returns the effective memory limit for the current process.
// In Docker containers, this respects the cgroup memory limit instead of
// returning the host's MemTotal (which would cause oversized BPF map allocations).
func getAvailableRAM() uint64 {
	const unlimited = uint64(9223372036854771712) // max int64 — cgroup "no limit"

	// Try cgroup v2 first
	if data, err := os.ReadFile("/sys/fs/cgroup/memory.max"); err == nil {
		s := strings.TrimSpace(string(data))
		if s != "max" {
			if v, err := strconv.ParseUint(s, 10, 64); err == nil && v < unlimited {
				return v
			}
		}
	}
	// Try cgroup v1
	if data, err := os.ReadFile("/sys/fs/cgroup/memory/memory.limit_in_bytes"); err == nil {
		if v, err := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64); err == nil && v < unlimited {
			return v
		}
	}
	// Fallback to host MemTotal
	return getSystemRAM()
}

func getSystemRAM() uint64 {
	file, err := os.Open("/proc/meminfo")
	if err != nil {
		return 2 * 1024 * 1024 * 1024 // default 2GB
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "MemTotal:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				kb, _ := strconv.ParseUint(fields[1], 10, 64)
				return kb * 1024
			}
		}
	}
	return 2 * 1024 * 1024 * 1024
}

// tuneSysctl writes optimized network parameters to the host kernel
// This requires the container to run with privileged: true
func tuneSysctl() {
	ram := getAvailableRAM()
	ramMB := ram / (1024 * 1024)

	// Scale conntrack and buffers dynamically to prevent OOM panics on small VPS
	conntrackMax := "262144"
	rmemMax := "16777216"

	if ramMB >= 8192 {
		conntrackMax = "4194304"
		rmemMax = "67108864"
	} else if ramMB >= 4096 {
		conntrackMax = "2000000"
		rmemMax = "33554432"
	} else if ramMB >= 2048 {
		conntrackMax = "1048576"
		rmemMax = "33554432"
	}

	sysctls := map[string]string{
		"/proc/sys/net/ipv4/tcp_syncookies":                            "1",
		"/proc/sys/net/ipv4/tcp_max_syn_backlog":                       "8192",
		"/proc/sys/net/core/netdev_max_backlog":                        "10000",
		"/proc/sys/net/netfilter/nf_conntrack_max":                     conntrackMax,
		"/proc/sys/net/netfilter/nf_conntrack_tcp_timeout_established": "86400",
		"/proc/sys/net/netfilter/nf_conntrack_udp_timeout":             "30",
		"/proc/sys/net/netfilter/nf_conntrack_udp_timeout_stream":      "300",
		"/proc/sys/net/ipv4/tcp_fin_timeout":                           "15",
		"/proc/sys/net/ipv4/tcp_tw_reuse":                              "1",
		"/proc/sys/net/ipv4/tcp_synack_retries":                        "2",
		"/proc/sys/net/ipv4/tcp_rfc1337":                               "1",
		"/proc/sys/net/core/rmem_max":                                  rmemMax,
		"/proc/sys/net/core/wmem_max":                                  rmemMax,
	}

	successCount := 0
	for path, value := range sysctls {
		if err := os.WriteFile(path, []byte(value+"\n"), 0644); err != nil {
			log.Printf("Warning: failed to set %s (is container privileged?): %v", path, err)
		} else {
			successCount++
		}
	}
	if successCount > 0 {
		log.Printf("Successfully tuned %d host sysctl parameters for DDoS mitigation", successCount)
	}
}

package main

import (
	"log"
	"time"

	"github.com/cilium/ebpf"
)

// EWMA Smoothing factor for rate limits
const ewmaAlpha = 0.3

func startAdaptiveRateLimiter(objs *XdpFilterObjects, baseRate uint32, baseUdp uint32, sniFiltering uint32, strictTcp uint32) {
	ticker := time.NewTicker(1 * time.Second)

	go func() {
		defer ticker.Stop()
		var lastRateDrops uint64
		var lastUdpDrops uint64

		currentRate := float64(baseRate)
		currentUdp := float64(baseUdp)

		numCPUs := ebpf.MustPossibleCPU()
		rateCpuDrops := make([]uint64, numCPUs)
		udpCpuDrops := make([]uint64, numCPUs)
		var lastRate, lastUdp uint32

		for range ticker.C {
			// 1. Fetch total drops across all CPUs
			if err := objs.StatsMap.Lookup(uint32(1), &rateCpuDrops); err != nil {
				// Reset counters to prevent multi-second spikes
				lastRateDrops, lastUdpDrops = 0, 0
				continue
			}
			if err := objs.StatsMap.Lookup(uint32(4), &udpCpuDrops); err != nil {
				lastRateDrops, lastUdpDrops = 0, 0
				continue
			}

			var totalRateDrops uint64
			var totalUdpDrops uint64
			for _, v := range rateCpuDrops {
				totalRateDrops += v
			}
			for _, v := range udpCpuDrops {
				totalUdpDrops += v
			}

			// 2. Calculate drops per second (track each counter independently)
			var rateDelta, udpDelta uint64
			if lastRateDrops != 0 {
				rateDelta = totalRateDrops - lastRateDrops
			}
			if lastUdpDrops != 0 {
				udpDelta = totalUdpDrops - lastUdpDrops
			}

			lastRateDrops = totalRateDrops
			lastUdpDrops = totalUdpDrops

			// 3. EWMA Logic for TCP/General Rate Limit
			if rateDelta > 5000 {
				// Massive attack! Drop limit exponentially
				targetRate := float64(baseRate) * 0.2 // Drop to 20%
				currentRate = (ewmaAlpha * targetRate) + ((1 - ewmaAlpha) * currentRate)
				log.Printf("[EWMA] DDoS Spike Detected! %d drops/sec. Compressing TCP Rate Limit to %d PPS", rateDelta, uint32(currentRate))
			} else if rateDelta < 5000 && currentRate < float64(baseRate) {
				// Recovery: smoothly restore to base when attack subsides
				currentRate += float64(baseRate) * 0.05
				if currentRate > float64(baseRate) {
					currentRate = float64(baseRate)
				}
			}

			// 4. EWMA Logic for Global UDP
			if udpDelta > 50000 {
				targetUdp := float64(baseUdp) * 0.5
				if targetUdp < 1000000 {
					targetUdp = 1000000
				}
				currentUdp = (ewmaAlpha * targetUdp) + ((1 - ewmaAlpha) * currentUdp)
				log.Printf("[EWMA] UDP Flood Detected! %d drops/sec. Compressing UDP Limit to %d PPS", udpDelta, uint32(currentUdp))
			} else if udpDelta < 50000 && currentUdp < float64(baseUdp) {
				currentUdp += float64(baseUdp) * 0.05
				if currentUdp > float64(baseUdp) {
					currentUdp = float64(baseUdp)
				}
			}

			// 5. Inject back into Kernel dynamically only if changed!
			if uint32(currentRate) != lastRate || uint32(currentUdp) != lastUdp {
				if err := objs.ConfigMap.Put(uint32(0), XdpFilterConfigData{
					RateLimitPps:      uint32(currentRate),
					GlobalUdpPps:      uint32(currentUdp),
					SniFiltering:      sniFiltering,
					StrictTcpTracking: strictTcp,
				}); err != nil {
					log.Printf("[EWMA] Failed to update config map: %v", err)
				}
				lastRate = uint32(currentRate)
				lastUdp = uint32(currentUdp)
			}
		}
	}()
}

// Package filter provides L3/L4 packet filtering for broader attack mitigation beyond DNS.
package filter

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"go.uber.org/zap" // Assuming you use zap from your logger.

	"yourproject/internal/blocker" // Import your existing blocker for shared IP blacklisting.
	"yourproject/internal/logger" // For logging.
)

// Config holds filter settings, load from your main config.
type Config struct {
	Interface     string        // Network interface to sniff (e.g., "eth0").
	SYNThreshold  int           // Max SYNs per IP per minute.
	UDPThreshold  int           // Max UDP packets per IP per minute.
	Window        time.Duration // Tracking window (e.g., 1m).
}

// PacketFilter monitors and filters L3/L4 traffic.
type PacketFilter struct {
	cfg          Config
	handle       *pcap.Handle
	blocker      *blocker.IPBlocker // Reuse your existing blocker.
	logger       *logger.Logger
	trackers     sync.Map           // ip → *ipTracker
	ctx          context.Context
	cancel       context.CancelFunc
}

// ipTracker holds per-IP stats.
type ipTracker struct {
	mu            sync.Mutex
	synCount      int
	udpCount      int
	lastReset     time.Time
}

// NewPacketFilter creates a new filter.
func NewPacketFilter(cfg Config, blocker *blocker.IPBlocker, logger *logger.Logger) *PacketFilter {
	ctx, cancel := context.WithCancel(context.Background())
	return &PacketFilter{
		cfg:     cfg,
		blocker: blocker,
		logger:  logger,
		ctx:     ctx,
		cancel:  cancel,
	}
}

// Start begins packet sniffing and filtering.
func (f *PacketFilter) Start() error {
	var err error
	f.handle, err = pcap.OpenLive(f.cfg.Interface, 1600, true, pcap.BlockForever)
	if err != nil {
		return fmt.Errorf("open interface: %w", err)
	}

	// Filter to TCP/UDP only (adjust BPF as needed).
	err = f.handle.SetBPFFilter("tcp or udp")
	if err != nil {
		f.handle.Close()
		return fmt.Errorf("set BPF: %w", err)
	}

	go f.cleanupLoop()
	go f.processPackets()
	return nil
}

// Stop shuts down the filter.
func (f *PacketFilter) Stop() {
	f.cancel()
	if f.handle != nil {
		f.handle.Close()
	}
}

// processPackets reads and analyzes packets.
func (f *PacketFilter) processPackets() {
	packetSource := gopacket.NewPacketSource(f.handle, f.handle.LinkType())
	for {
		select {
		case <-f.ctx.Done():
			return
		case packet := <-packetSource.Packets():
			f.analyzePacket(packet)
		}
	}
}

// analyzePacket checks for floods and blocks if needed.
func (f *PacketFilter) analyzePacket(packet gopacket.Packet) {
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		return // Non-IPv4, ignore.
	}
	ip, _ := ipLayer.(*layers.IPv4)

	srcIP := ip.SrcIP.String()
	if f.blocker.IsBlocked(srcIP) {
		// Drop: In userspace, we can't kernel-drop, but log and skip forwarding if this is a proxy.
		f.logger.LogMitigationAction(srcIP, "packet dropped (blocked IP)")
		return // Simulate drop by not processing further.
	}

	trackerIface, _ := f.trackers.LoadOrStore(srcIP, &ipTracker{lastReset: time.Now()})
	tracker := trackerIface.(*ipTracker)

	tracker.mu.Lock()
	defer tracker.mu.Unlock()

	now := time.Now()
	if now.Sub(tracker.lastReset) > f.cfg.Window {
		tracker.synCount = 0
		tracker.udpCount = 0
		tracker.lastReset = now
	}

	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		if tcp.SYN && !tcp.ACK {
			tracker.synCount++
			if tracker.synCount > f.cfg.SYNThreshold {
				f.blocker.BlockIP(srcIP, "SYN flood detected", f.cfg.Window.Seconds())
				f.logger.LogDDoSDetected(srcIP, "SYN flood", tracker.synCount)
			}
		}
	} else if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		tracker.udpCount++
		if tracker.udpCount > f.cfg.UDPThreshold {
			f.blocker.BlockIP(srcIP, "UDP flood detected", f.cfg.Window.Seconds())
			f.logger.LogDDoSDetected(srcIP, "UDP flood", tracker.udpCount)
		}
	}

	// If clean, "forward" (in reality, since we're sniffing, packets proceed unless we inject drops).
}

// cleanupLoop prunes old trackers.
func (f *PacketFilter) cleanupLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-f.ctx.Done():
			return
		case <-ticker.C:
			f.trackers.Range(func(key, value interface{}) bool {
				tracker := value.(*ipTracker)
				tracker.mu.Lock()
				if time.Since(tracker.lastReset) > 2*f.cfg.Window {
					f.trackers.Delete(key)
				}
				tracker.mu.Unlock()
				return true
			})
		}
	}
}
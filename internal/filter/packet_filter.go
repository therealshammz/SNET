package filter

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	//"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"go.uber.org/zap"

	"ddd/internal/blocker"
	"ddd/internal/logger"
)

type Config struct {
	Interface     string
	SYNThreshold  int
	UDPThreshold  int
	Window        time.Duration
	UpstreamDNS   string
}

type PacketFilter struct {
	cfg      Config
	handle   *pcap.Handle
	blocker  *blocker.IPBlocker
	log      *logger.Logger
	trackers sync.Map 
	suppress sync.Map 
	ctx      context.Context
	cancel   context.CancelFunc
}

type ipTracker struct {
	mu        sync.Mutex
	synCount  int
	udpCount  int
	lastReset time.Time
}

type suppressState struct {
	mu             sync.Mutex
	suppressed     bool
	lastBlockTime  time.Time
	dropCount      int64
	lastPacketTime time.Time
	rate           float64
}

func NewPacketFilter(cfg Config, b *blocker.IPBlocker, l *logger.Logger) *PacketFilter {
	ctx, cancel := context.WithCancel(context.Background())
	return &PacketFilter{
		cfg:     cfg,
		blocker: b,
		log:     l,
		ctx:     ctx,
		cancel:  cancel,
	}
}

func (f *PacketFilter) Start() error {
	var err error
	f.handle, err = pcap.OpenLive(f.cfg.Interface, 1600, true, pcap.BlockForever)
	if err != nil {
		return fmt.Errorf("pcap.OpenLive failed: %w", err)
	}

	if err := f.handle.SetBPFFilter("tcp or udp"); err != nil {
		f.handle.Close()
		return fmt.Errorf("BPF filter failed: %w", err)
	}

	f.log.Info("Packet filter started", "interface", f.cfg.Interface)

	go f.processPackets()
	go f.cleanupLoop()

	return nil
}

func (f *PacketFilter) Stop() {
	f.cancel()
	if f.handle != nil {
		f.handle.Close()
	}
}

func (f *PacketFilter) processPackets() {
	packetSource := gopacket.NewPacketSource(f.handle, f.handle.LinkType())
	for {
		select {
		case <-f.ctx.Done():
			return
		case packet := <-packetSource.Packets():
			f.analyze(packet)
		}
	}
}

func (f *PacketFilter) analyze(packet gopacket.Packet) {
	ip4Layer := packet.Layer(layers.LayerTypeIPv4)
	if ip4Layer == nil {
		return
	}
	ip4, _ := ip4Layer.(*layers.IPv4)
	src := ip4.SrcIP.String()

	upstreamHost, _, _ := net.SplitHostPort(f.cfg.UpstreamDNS)
	if upstreamHost == "" {
		upstreamHost = f.cfg.UpstreamDNS
	}
	if src == upstreamHost {
		return
	}

	if f.blocker.IsBlocked(src) {
		f.updateSuppression(src)
		return
	}

	trkIface, _ := f.trackers.LoadOrStore(src, &ipTracker{lastReset: time.Now()})
	trk := trkIface.(*ipTracker)

	trk.mu.Lock()
	defer trk.mu.Unlock()

	now := time.Now()
	if now.Sub(trk.lastReset) >= f.cfg.Window {
		trk.synCount = 0
		trk.udpCount = 0
		trk.lastReset = now
	}

	var reason string
	var count int

	if tcp := packet.Layer(layers.LayerTypeTCP); tcp != nil {
		t := tcp.(*layers.TCP)
		if t.SYN && !t.ACK {
			trk.synCount++
			count = trk.synCount
			if count > f.cfg.SYNThreshold {
				reason = "SYN flood detected"
			}
		}
	} else if udp := packet.Layer(layers.LayerTypeUDP); udp != nil {
		trk.udpCount++
		count = trk.udpCount
		if count > f.cfg.UDPThreshold {
			reason = "UDP flood detected"
		}
	}

	if reason != "" {
		f.blocker.BlockIP(src, reason)
		f.log.Warnw(reason, "ip", src, "count", count)

		go func() {
			cmd := exec.Command("iptables", "-A", "FORWARD", "-s", src, "-j", "DROP")
			if err := cmd.Run(); err != nil {
				f.log.Error("Failed to add iptables DROP rule", zap.String("ip", src), zap.Error(err))
			} else {
				f.log.Info("Added iptables DROP rule for IP", zap.String("ip", src), zap.String("reason", reason))
			}
		}()

		f.startSuppression(src)
	}
}

func (f *PacketFilter) startSuppression(ip string) {
	stateIface, _ := f.suppress.LoadOrStore(ip, &suppressState{})
	state := stateIface.(*suppressState)

	state.mu.Lock()
	if state.suppressed {
		state.mu.Unlock()
		return
	}
	state.suppressed = true
	state.lastBlockTime = time.Now()
	state.lastPacketTime = time.Now()
	state.rate = 0
	state.dropCount = 0
	state.mu.Unlock()

	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-f.ctx.Done():
				return
			case <-ticker.C:
				state.mu.Lock()
				if time.Since(state.lastPacketTime) > 10*time.Second {
					state.suppressed = false
					state.mu.Unlock()
					return
				}

				elapsed := time.Since(state.lastBlockTime).Seconds()
				rate := float64(state.dropCount) / elapsed
				if elapsed > 0 {
					state.rate = 0.8*state.rate + 0.2*rate
				}

				f.log.Infow("Suppressed IP status",
					"ip", ip,
					"blocked_for_sec", int(elapsed),
					"packets_dropped", state.dropCount,
					"current_rate_pps", fmt.Sprintf("%.1f", state.rate),
				)

				state.mu.Unlock()
			}
		}
	}()
}

func (f *PacketFilter) updateSuppression(ip string) {
	stateIface, ok := f.suppress.Load(ip)
	if !ok {
		return
	}
	state := stateIface.(*suppressState)

	state.mu.Lock()
	defer state.mu.Unlock()

	if !state.suppressed {
		return
	}

	state.dropCount++
	state.lastPacketTime = time.Now()
}

func (f *PacketFilter) cleanupLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-f.ctx.Done():
			return
		case <-ticker.C:
			f.trackers.Range(func(key, val interface{}) bool {
				t := val.(*ipTracker)
				t.mu.Lock()
				if time.Since(t.lastReset) > 2*f.cfg.Window {
					f.trackers.Delete(key)
				}
				t.mu.Unlock()
				return true
			})

			f.suppress.Range(func(key, val interface{}) bool {
				s := val.(*suppressState)
				s.mu.Lock()
				if time.Since(s.lastPacketTime) > 30*time.Second {
					f.suppress.Delete(key)
				}
				s.mu.Unlock()
				return true
			})
		}
	}
}

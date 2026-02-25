package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"   //path resolution
	"strings"
	"syscall"
	"time"

	"ddd/internal/blocker"
	"ddd/internal/config"
	"ddd/internal/detector"
	"ddd/internal/dns"
	"ddd/internal/filter"
	"ddd/internal/logger"
	"ddd/internal/monitor"
	"ddd/internal/stats"

	"go.uber.org/zap"
)

func main() {
	var (
		configPath = flag.String("config", "configs/config.yaml", "Path to YAML config file")
		port       = flag.Int("port", 0, "DNS server port (overrides config)")
		upstream   = flag.String("upstream", "", "Upstream DNS server (overrides config)")
		logFile    = flag.String("log", "", "Log file path (overrides config)")
		rateLimit  = flag.Int("rate-limit", 0, "Max DNS requests per IP per minute (overrides)")
		blockTime  = flag.Int("block-time", 0, "Block duration in seconds (overrides)")
		iface      = flag.String("iface", "auto", "Network interface for L4 filtering (auto = detect and prompt)")
		mode       = flag.String("mode", "dns", "Operation mode: dns (default), gateway")
	)
	flag.Parse()

	configPathResolved := *configPath
	if !filepath.IsAbs(configPathResolved) {
		exe, err := os.Executable()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Cannot get executable path: %v\n", err)
			os.Exit(1)
		}
		exeDir := filepath.Dir(exe)
		configPathResolved = filepath.Join(exeDir, configPathResolved)
	}

	if err := config.EnsureConfig(configPathResolved); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to ensure config: %v\n", err)
		os.Exit(1)
	}

	cfg, err := config.LoadFromFile(configPathResolved)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load config: %v\n", err)
		os.Exit(1)
	}

	if *port > 0 {
		cfg.Port = *port
	}
	if *upstream != "" {
		cfg.UpstreamDNS = *upstream
	}
	if *logFile != "" {
		cfg.LogFile = *logFile
	}
	if *rateLimit > 0 {
		cfg.RateLimit = *rateLimit
	}
	if *blockTime > 0 {
		cfg.BlockTime = *blockTime
	}

	log, err := logger.NewLogger(cfg.LogFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to initialize logger: %v\n", err)
		os.Exit(1)
	}
	defer log.Sync()

	log.Infow("Starting SNET",
		"mode", *mode,
		"config_file", configPathResolved,
		"port", cfg.Port,
		"upstream", cfg.UpstreamDNS,
		"rate_limit", cfg.RateLimit,
		"block_time", cfg.BlockTime,
		"iface_flag", *iface,
	)

	trafficMonitor := monitor.NewTrafficMonitor()

	statsAddr := cfg.StatsPort
	if statsAddr == "" {
		statsAddr = ":8080"
	}
	statsServer := stats.NewStatsServer(statsAddr, log, nil, cfg)
	statsServer.Start()

	ddosDetector := detector.NewDDoSDetector(
		cfg.RateLimit,
		cfg.HighRateThreshold,
		cfg.RepeatedQueriesMin,
		cfg.RandomSubdomainsMin,
		cfg.QueryBurstThreshold,
		time.Duration(cfg.QueryBurstWindowSec)*time.Second,
		log,
		statsServer,
	)

	ipBlocker := blocker.NewIPBlocker(cfg.BlockTime, log)
	statsServer.IPBlocker = ipBlocker

	// ====================== GATEWAY MODE ======================
	if *mode == "gateway" {
		log.Info("Starting in GATEWAY mode - network-wide protection")

		if err := exec.Command("sysctl", "-w", "net.ipv4.ip_forward=1").Run(); err != nil {
			log.Error("Failed to enable IP forwarding", zap.Error(err))
		} else {
			log.Info("IP forwarding enabled")
		}


				wanIface, err := getDefaultInterface()
		if err != nil {
			log.Error("Cannot detect default WAN interface", zap.Error(err))
		} else {
			natCmd := exec.Command("iptables", "-t", "nat", "-A", "POSTROUTING", "-o", wanIface, "-j", "MASQUERADE")
			if err := natCmd.Run(); err != nil {
				log.Error("Failed to add NAT rule", zap.Error(err))
			} else {
				log.Info("NAT masquerade rule added", "interface", wanIface)
			}

			defer func() {
				flushCmd := exec.Command("iptables", "-t", "nat", "-D", "POSTROUTING", "-o", wanIface, "-j", "MASQUERADE")
				flushCmd.Run()
				log.Info("Cleaned up NAT rule on shutdown")
			}()
		}

		selectedIface := *iface
		if selectedIface == "auto" || selectedIface == "" {
			if cfg.FilterInterface != "" && cfg.FilterInterface != "auto" {
				selectedIface = cfg.FilterInterface
			} else {
				interfaces, _ := listActiveInterfaces()
				if len(interfaces) > 0 {
					selectedIface = interfaces[0]
				}
			}
		}

		filterCfg := filter.Config{
			Interface:    selectedIface,
			SYNThreshold: cfg.SYNThreshold,
			UDPThreshold: cfg.UDPThreshold,
			Window:       time.Duration(cfg.FilterWindowSec) * time.Second,
			UpstreamDNS:  cfg.UpstreamDNS,
		}
		packetFilter := filter.NewPacketFilter(filterCfg, ipBlocker, log)

		if err := packetFilter.Start(); err != nil {
			log.Error("Failed to start packet filter", zap.Error(err))
		} else {
			defer packetFilter.Stop()
		}

		dnsServer := dns.NewServer(
			cfg.Port,
			cfg.UpstreamDNS,
			trafficMonitor,
			ddosDetector,
			ipBlocker,
			log,
		)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		go trafficMonitor.StartCleanup(ctx)
		go ipBlocker.StartCleanup(ctx)

		go func() {
			if err := dnsServer.Start(); err != nil {
				log.Error("DNS server error in gateway mode", zap.Error(err))
			}
		}()

		log.Info("Gateway mode active - set client default gateway to this machine's IP")
		log.Info("Press Ctrl+C to stop")

		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
		<-sigChan

		log.Info("Shutting down gateway mode...")
		dnsServer.Stop()
		log.Info("Gateway mode stopped")
		return
	}

	// ====================== DNS PROXY MODE ======================
	log.Info("Starting in DNS proxy mode")

	selectedIface := *iface
	if selectedIface == "auto" && cfg.FilterInterface != "" && cfg.FilterInterface != "auto" {
		selectedIface = cfg.FilterInterface
		log.Info("Using interface from config", "interface", selectedIface)
	}

	if selectedIface == "auto" || selectedIface == "" {
		interfaces, err := listActiveInterfaces()
		if err != nil {
			log.Warn("Failed to auto-detect network interfaces", zap.Error(err))
		} else if len(interfaces) == 0 {
			log.Warn("No active non-loopback network interfaces found")
		} else if len(interfaces) == 1 {
			selectedIface = interfaces[0]
			log.Info("Auto-detected single active interface", "interface", selectedIface)
		} else {
			fmt.Println("\nMultiple active network interfaces found. Choose one for L4 packet filtering:")
			for i, name := range interfaces {
				fmt.Printf("  %d) %s\n", i+1, name)
			}
			fmt.Print("\nEnter number (or press Enter to skip): ")

			reader := bufio.NewReader(os.Stdin)
			input, _ := reader.ReadString('\n')
			input = strings.TrimSpace(input)

			if input == "" {
				log.Info("No interface selected → L4 packet filtering disabled")
				selectedIface = ""
			} else {
				var choice int
				_, err := fmt.Sscanf(input, "%d", &choice)
				if err == nil && choice >= 1 && choice <= len(interfaces) {
					selectedIface = interfaces[choice-1]
					log.Info("Selected interface", "interface", selectedIface)
				} else {
					log.Warn("Invalid selection → L4 packet filtering disabled")
					selectedIface = ""
				}
			}
		}
	}

	var packetFilter *filter.PacketFilter
	if selectedIface != "" {
		filterCfg := filter.Config{
			Interface:    selectedIface,
			SYNThreshold: cfg.SYNThreshold,
			UDPThreshold: cfg.UDPThreshold,
			Window:       time.Duration(cfg.FilterWindowSec) * time.Second,
			UpstreamDNS:  cfg.UpstreamDNS,
		}
		packetFilter = filter.NewPacketFilter(filterCfg, ipBlocker, log)

		if err := packetFilter.Start(); err != nil {
			log.Error("Failed to start L4 packet filter",
				zap.String("interface", selectedIface),
				zap.Error(err),
			)
		} else {
			defer packetFilter.Stop()
		}
	} else {
		log.Info("L4 packet filtering skipped")
	}

	dnsServer := dns.NewServer(
		cfg.Port,
		cfg.UpstreamDNS,
		trafficMonitor,
		ddosDetector,
		ipBlocker,
		log,
	)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go trafficMonitor.StartCleanup(ctx)
	go ipBlocker.StartCleanup(ctx)

	go func() {
		if err := dnsServer.Start(); err != nil {
			log.Error("DNS server error", zap.Error(err))
			os.Exit(1)
		}
	}()

	log.Info("SNET started successfully")

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	log.Info("Shutting down SNET...")
	dnsServer.Stop()
	log.Info("SNET stopped gracefully")
}

func listActiveInterfaces() ([]string, error) {
	out, err := exec.Command("ip", "link", "show").Output()
	if err != nil {
		return nil, fmt.Errorf("ip link show failed: %w", err)
	}

	var ifaces []string
	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || !strings.Contains(line, "state UP") {
			continue
		}
		if strings.Contains(line, "lo:") || strings.Contains(line, "docker") || strings.Contains(line, "br-") {
			continue
		}

		parts := strings.SplitN(line, ": ", 2)
		if len(parts) < 2 {
			continue
		}
		namePart := strings.Split(parts[1], "@")[0]
		name := strings.TrimSpace(strings.Split(namePart, ":")[0])

		if name != "" && name != "lo" {
			ifaces = append(ifaces, name)
		}
	}

	return ifaces, nil
}

func getDefaultInterface() (string, error) {
	out, err := exec.Command("ip", "-o", "-4", "route", "show", "default").Output()
	if err != nil {
		return "", err
	}

	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) >= 5 && fields[0] == "default" {
			return fields[4], nil
		}
	}
	return "", fmt.Errorf("no default route found")
}

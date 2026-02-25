package stats

import (
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"ddd/internal/blocker"
	"ddd/internal/config"
	"ddd/internal/logger"
)

// StatsServer runs a simple HTTP server exposing /stats
type StatsServer struct {
	addr       string
	log        *logger.Logger
	IPBlocker  *blocker.IPBlocker  // exported so main.go can assign it later
	cfg        config.Config
	startTime  time.Time
	mu         sync.RWMutex
	detections []DetectionEntry // ring buffer of last 10 detections
}

// DetectionEntry for recent attacks
type DetectionEntry struct {
	Timestamp time.Time `json:"timestamp"`
	IP        string    `json:"ip"`
	Type      string    `json:"type"`
	Severity  string    `json:"severity"`
}

// NewStatsServer creates the stats server
func NewStatsServer(addr string, log *logger.Logger, blocker *blocker.IPBlocker, cfg config.Config) *StatsServer {
	return &StatsServer{
		addr:      addr,
		log:       log,
		IPBlocker: blocker,
		cfg:       cfg,
		startTime: time.Now(),
	}
}

// Start runs the HTTP server in background
func (s *StatsServer) Start() {
	http.HandleFunc("/stats", s.handleStats)
	s.log.Info("Stats endpoint listening", "addr", s.addr)

	go func() {
		if err := http.ListenAndServe(s.addr, nil); err != nil && err != http.ErrServerClosed {
			s.log.Error("Stats server failed", "error", err)
		}
	}()
}

// AddDetection adds a new detection entry
func (s *StatsServer) AddDetection(ip, typ, severity string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	entry := DetectionEntry{
		Timestamp: time.Now(),
		IP:        ip,
		Type:      typ,
		Severity:  severity,
	}

	s.detections = append(s.detections, entry)
	if len(s.detections) > 10 {
		s.detections = s.detections[1:]
	}
}

// handleStats returns current stats as JSON
func (s *StatsServer) handleStats(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var blockedList []blocker.BlockedIP
	if s.IPBlocker != nil {
		blockedList = s.IPBlocker.GetAllBlockedIPs()
	}

	data := map[string]interface{}{
		"uptime_seconds":    int(time.Since(s.startTime).Seconds()),
		"blocked_count":     len(blockedList),
		"blocked_ips":       blockedList,
		"recent_detections": s.detections,
		"config": map[string]interface{}{
			"port":                 s.cfg.Port,
			"upstream_dns":         s.cfg.UpstreamDNS,
			"rate_limit":           s.cfg.RateLimit,
			"block_time_sec":       s.cfg.BlockTime,
			"syn_threshold":        s.cfg.SYNThreshold,
			"udp_threshold":        s.cfg.UDPThreshold,
			"filter_interface":     s.cfg.FilterInterface,
			"high_rate_threshold":  s.cfg.HighRateThreshold,
			"repeated_queries_min": s.cfg.RepeatedQueriesMin,
			"random_subdomains_min": s.cfg.RandomSubdomainsMin,
			"query_burst_threshold": s.cfg.QueryBurstThreshold,
			"query_burst_window_sec": s.cfg.QueryBurstWindowSec,
		},
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*") // optional for browser testing
	json.NewEncoder(w).Encode(data)
}
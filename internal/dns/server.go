package dns

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"ddd/internal/blocker"
	"ddd/internal/detector"
	"ddd/internal/logger"
	"ddd/internal/monitor"
)

type Server struct {
	port           int
	upstreamDNS    string
	udpServer      *dns.Server
	tcpServer      *dns.Server
	trafficMonitor *monitor.TrafficMonitor
	ddosDetector   *detector.DDoSDetector
	ipBlocker      *blocker.IPBlocker
	log            *logger.Logger
	upstreamClient *dns.Client
	ctx            context.Context       // ← new
	cancel         context.CancelFunc    // ← new
	wg             sync.WaitGroup        // ← new
	dnsFilter      *DNSFilter
}

func NewServer(
	port int,
	upstreamDNS string,
	trafficMonitor *monitor.TrafficMonitor,
	ddosDetector *detector.DDoSDetector,
	ipBlocker *blocker.IPBlocker,
	log *logger.Logger,
) *Server {
	ctx, cancel := context.WithCancel(context.Background())

	s := &Server{
		port:           port,
		upstreamDNS:    upstreamDNS,
		trafficMonitor: trafficMonitor,
		ddosDetector:   ddosDetector,
		ipBlocker:      ipBlocker,
		log:            log,
		upstreamClient: &dns.Client{
			Timeout: 5 * time.Second,
		},
		ctx:    ctx,
		cancel: cancel,
	}

	addr := fmt.Sprintf(":%d", port)

	s.udpServer = &dns.Server{
		Addr:    addr,
		Net:     "udp",
		Handler: dns.HandlerFunc(s.handleDNSRequest),
	}

	s.tcpServer = &dns.Server{
		Addr:    addr,
		Net:     "tcp",
		Handler: dns.HandlerFunc(s.handleDNSRequest),
	}

	return s
}

func (s *Server) Start() error {
	s.log.Info("Starting DNS listeners",
		"port", s.port,
		"protocols", "UDP and TCP",
	)

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		if err := s.udpServer.ListenAndServe(); err != nil {
			s.log.Error("UDP DNS listener failed", "error", err)
		}
	}()

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		if err := s.tcpServer.ListenAndServe(); err != nil {
			s.log.Error("TCP DNS listener failed", "error", err)
		}
	}()

	return nil
}

func (s *Server) Stop() error {
	s.log.Info("Shutting down DNS listeners")

	s.cancel()

	errUDP := s.udpServer.Shutdown()
	if errUDP != nil {
		s.log.Error("UDP shutdown error", "error", errUDP)
	}

	errTCP := s.tcpServer.Shutdown()
	if errTCP != nil {
		s.log.Error("TCP shutdown error", "error", errTCP)
	}

	s.wg.Wait()

	s.log.Info("DNS listeners fully stopped")

	if errUDP != nil {
		return errUDP
	}
	if errTCP != nil {
		return errTCP
	}
	return nil
}

func (s *Server) handleDNSRequest(w dns.ResponseWriter, r *dns.Msg) {
	clientIP := s.extractClientIP(w.RemoteAddr())

	if s.ipBlocker.IsBlocked(clientIP) {
		s.log.Info("Blocked IP attempted request", "ip", clientIP)
		s.sendRefused(w, r)
		return
	}

	if s.ipBlocker.IsRateLimited(clientIP) {
		s.log.Info("Rate limited IP request", "ip", clientIP)
		time.Sleep(500 * time.Millisecond)
	}

	if len(r.Question) == 0 {
		s.sendRefused(w, r)
		return
	}

	question := r.Question[0]
	domain := strings.TrimSuffix(question.Name, ".")
	qtype := dns.TypeToString[question.Qtype]

	s.trafficMonitor.RecordRequest(clientIP, domain, qtype)
	s.log.LogDNSQuery(clientIP, domain, qtype)

	detectionResult := s.ddosDetector.AnalyzeTraffic(clientIP, s.trafficMonitor)
	if detectionResult.IsAttack {
		s.log.Warnw("Attack detected",
			"ip", clientIP,
			"attack_type", detectionResult.AttackType,
			"severity", detectionResult.Severity,
		)

		if detectionResult.ShouldBlock {
			s.ipBlocker.BlockIP(clientIP, detectionResult.AttackType)
			s.sendRefused(w, r)
			return
		} else {
			s.ipBlocker.RateLimitIP(clientIP)
		}
	}

	s.forwardRequest(w, r)
}

func (s *Server) forwardRequest(w dns.ResponseWriter, r *dns.Msg) {
	resp, _, err := s.upstreamClient.Exchange(r, s.upstreamDNS)
	if err != nil {
		s.log.Errorw("Error querying upstream DNS",
			"error", err,
			"upstream", s.upstreamDNS,
		)
		s.sendServerFailure(w, r)
		return
	}

	if err := w.WriteMsg(resp); err != nil {
		s.log.Errorw("Error writing response to client",
			"error", err,
		)
		return
	}
}

func (s *Server) sendRefused(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Rcode = dns.RcodeRefused
	w.WriteMsg(m)
}

func (s *Server) sendServerFailure(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Rcode = dns.RcodeServerFailure
	w.WriteMsg(m)
}

func (s *Server) extractClientIP(addr net.Addr) string {
	switch v := addr.(type) {
	case *net.UDPAddr:
		return v.IP.String()
	case *net.TCPAddr:
		return v.IP.String()
	default:
		host, _, err := net.SplitHostPort(addr.String())
		if err != nil {
			return addr.String()
		}
		return host
	}
}

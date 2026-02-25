package dns

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"net"
	"strings"
	"sync"

	"github.com/miekg/dns"
	"ddd/internal/logger"
)

type DNSFilter struct {
	blockedDomains map[string]bool
	redirectIP     net.IP
	log            *logger.Logger
	mu             sync.RWMutex
}

func NewDNSFilter(log *logger.Logger) *DNSFilter {
	return &DNSFilter{
		blockedDomains: make(map[string]bool),
		redirectIP:     net.IP{127, 0, 0, 1},
		log:            log,
	}
}

func (f *DNSFilter) LoadBlocklists(lists []string) error {
	f.mu.Lock()
	f.blockedDomains = make(map[string]bool)
	f.mu.Unlock()

	for _, list := range lists {
		var reader io.Reader
		if strings.HasPrefix(list, "http://") || strings.HasPrefix(list, "https://") {
			resp, err := http.Get(list)
			if err != nil {
				f.log.Error("Failed to download blocklist", "url", list, "error", err)
				continue
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				f.log.Error("Blocklist download failed", "url", list, "status", resp.StatusCode)
				continue
			}
			reader = resp.Body
		} else {
			file, err := os.Open(list)
			if err != nil {
				f.log.Error("Failed to open local blocklist", "file", list, "error", err)
				continue
			}
			defer file.Close()
			reader = file
		}

		data, err := io.ReadAll(reader)
		if err != nil {
			f.log.Error("Failed to read blocklist", "list", list, "error", err)
			continue
		}

		lines := strings.Split(string(data), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "!") {
				continue
			}
			parts := strings.Fields(line)
			domain := parts[len(parts)-1]
			f.mu.Lock()
			f.blockedDomains[domain] = true
			f.mu.Unlock()
		}

		f.log.Info("Loaded blocklist", "list", list, "domains_added", len(lines))
	}

	return nil
}

func (f *DNSFilter) HandleFilteredRequest(w dns.ResponseWriter, r *dns.Msg) bool {
	if len(r.Question) == 0 {
		return false
	}

	question := r.Question[0]
	domain := strings.TrimSuffix(question.Name, ".") // normalize

	f.mu.RLock()
	isBlocked := f.blockedDomains[domain]
	f.mu.RUnlock()

	if isBlocked {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Rcode = dns.RcodeNameError // NXDOMAIN
		// Or redirect to localhost for A recod
		if question.Qtype == dns.TypeA {
			m.Rcode = dns.RcodeSuccess
			rr, _ := dns.NewRR(fmt.Sprintf("%s A %s", question.Name, f.redirectIP.String()))
			m.Answer = []dns.RR{rr}
		}
		w.WriteMsg(m)
		f.log.LogDNSQuery(w.RemoteAddr().String(), domain, dns.TypeToString[question.Qtype]) // still log
		return true // handled
	}

	return false
}

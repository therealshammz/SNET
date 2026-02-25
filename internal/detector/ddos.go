package detector

import (
	"strings"
	"time"

	"ddd/internal/logger"
	"ddd/internal/monitor"
	"ddd/internal/stats"
)

type DDoSDetector struct {
	rateLimit             int
	highRateThreshold     int
	repeatedQueriesMin    int
	randomSubdomainsMin   int
	queryBurstThreshold   int
	queryBurstWindow      time.Duration
	log                   *logger.Logger
	stats                 *stats.StatsServer
}

func NewDDoSDetector(
	rateLimit int,
	highRateThreshold int,
	repeatedQueriesMin int,
	randomSubdomainsMin int,
	queryBurstThreshold int,
	queryBurstWindow time.Duration,
	log *logger.Logger,
	stats *stats.StatsServer,
) *DDoSDetector {
	return &DDoSDetector{
		rateLimit:             rateLimit,
		highRateThreshold:     highRateThreshold,
		repeatedQueriesMin:    repeatedQueriesMin,
		randomSubdomainsMin:   randomSubdomainsMin,
		queryBurstThreshold:   queryBurstThreshold,
		queryBurstWindow:      queryBurstWindow,
		log:                   log,
		stats:                 stats,
	}
}

type DetectionResult struct {
	IsAttack    bool
	AttackType  string
	Severity    string
	Description string
	ShouldBlock bool
}

func (d *DDoSDetector) AnalyzeTraffic(ip string, trafficMonitor *monitor.TrafficMonitor) *DetectionResult {
	result := &DetectionResult{
		IsAttack:    false,
		ShouldBlock: false,
	}

	recentCount := trafficMonitor.GetRecentRequestCount(ip, 1*time.Minute)
	if recentCount > d.highRateThreshold {
		result.IsAttack = true
		result.AttackType = "high_request_rate"
		result.Severity = d.calculateSeverity(recentCount, d.highRateThreshold)
		result.Description = "Excessive request rate detected"
		result.ShouldBlock = recentCount > d.highRateThreshold*2
		d.log.LogDDoSDetected(ip, "high request rate", recentCount)
		if d.stats != nil {
			d.stats.AddDetection(ip, result.AttackType, result.Severity)
		}
		return result
	}

	queries := trafficMonitor.GetRecentQueries(ip, 1*time.Minute)

	if d.checkRepeatedQueries(queries) {
		result.IsAttack = true
		result.AttackType = "repeated_queries"
		result.Severity = "medium"
		result.Description = "Repeated queries to same domain detected"
		result.ShouldBlock = true
		d.log.LogDDoSDetected(ip, "repeated queries", len(queries))
		if d.stats != nil {
			d.stats.AddDetection(ip, result.AttackType, result.Severity)
		}
		return result
	}

	if d.checkRandomSubdomains(queries) {
		result.IsAttack = true
		result.AttackType = "random_subdomain"
		result.Severity = "high"
		result.Description = "Random subdomain attack detected"
		result.ShouldBlock = true
		d.log.LogDDoSDetected(ip, "random subdomain attack", len(queries))
		if d.stats != nil {
			d.stats.AddDetection(ip, result.AttackType, result.Severity)
		}
		return result
	}

	if d.checkQueryBurst(queries) {
		result.IsAttack = true
		result.AttackType = "query_burst"
		result.Severity = "medium"
		result.Description = "Query burst detected"
		result.ShouldBlock = false
		d.log.LogDDoSDetected(ip, "query burst", len(queries))
		if d.stats != nil {
			d.stats.AddDetection(ip, result.AttackType, result.Severity)
		}
		return result
	}

	return result
}

func (d *DDoSDetector) checkRepeatedQueries(queries []monitor.QueryInfo) bool {
	if len(queries) < d.repeatedQueriesMin {
		return false
	}
	domainCounts := make(map[string]int)
	for _, q := range queries {
		domainCounts[q.Domain]++
	}
	for _, count := range domainCounts {
		if float64(count)/float64(len(queries)) > 0.5 && count > 10 {
			return true
		}
	}
	return false
}

func (d *DDoSDetector) checkRandomSubdomains(queries []monitor.QueryInfo) bool {
	if len(queries) < d.randomSubdomainsMin {
		return false
	}
	baseDomains := make(map[string][]string)
	for _, q := range queries {
		parts := strings.Split(q.Domain, ".")
		if len(parts) >= 2 {
			baseDomain := strings.Join(parts[len(parts)-2:], ".")
			subdomain := strings.Join(parts[:len(parts)-2], ".")
			if subdomain != "" {
				baseDomains[baseDomain] = append(baseDomains[baseDomain], subdomain)
			}
		}
	}
	for _, subdomains := range baseDomains {
		uniqueSubdomains := make(map[string]bool)
		for _, sub := range subdomains {
			uniqueSubdomains[sub] = true
		}
		if len(uniqueSubdomains) > 20 {
			return true
		}
		randomCount := 0
		for sub := range uniqueSubdomains {
			if d.looksRandom(sub) {
				randomCount++
			}
		}
		if randomCount > 10 {
			return true
		}
	}
	return false
}

func (d *DDoSDetector) checkQueryBurst(queries []monitor.QueryInfo) bool {
	if len(queries) < 10 {
		return false
	}
	cutoff := time.Now().Add(-d.queryBurstWindow)
	recentCount := 0
	for _, q := range queries {
		if q.Timestamp.After(cutoff) {
			recentCount++
		}
	}
	return recentCount > d.queryBurstThreshold
}

func (d *DDoSDetector) looksRandom(s string) bool {
	if len(s) < 8 {
		return false
	}
	digitCount := 0
	uniqueChars := make(map[rune]bool)
	for _, c := range s {
		uniqueChars[c] = true
		if c >= '0' && c <= '9' {
			digitCount++
		}
	}
	highDigitRatio := float64(digitCount)/float64(len(s)) > 0.4
	highEntropy := float64(len(uniqueChars))/float64(len(s)) > 0.6
	return highDigitRatio && highEntropy
}

func (d *DDoSDetector) calculateSeverity(requestCount, threshold int) string {
	ratio := float64(requestCount) / float64(threshold)
	if ratio > 5 {
		return "high"
	} else if ratio > 2 {
		return "medium"
	}
	return "low"
}

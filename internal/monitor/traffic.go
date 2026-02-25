package monitor

import (
	"context"
	"sync"
	"time"
)

type IPStats struct {
	RequestCount    int
	LastRequestTime time.Time
	Queries         []QueryInfo
	FirstSeen       time.Time
}

type QueryInfo struct {
	Domain    string
	QueryType string
	Timestamp time.Time
}

type TrafficMonitor struct {
	mu    sync.RWMutex
	stats map[string]*IPStats
}

func NewTrafficMonitor() *TrafficMonitor {
	return &TrafficMonitor{
		stats: make(map[string]*IPStats),
	}
}

func (tm *TrafficMonitor) RecordRequest(ip, domain, qtype string) {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	if _, exists := tm.stats[ip]; !exists {
		tm.stats[ip] = &IPStats{
			FirstSeen: time.Now(),
			Queries:   make([]QueryInfo, 0),
		}
	}

	stats := tm.stats[ip]
	stats.RequestCount++
	stats.LastRequestTime = time.Now()
	
	if len(stats.Queries) >= 100 {
		stats.Queries = stats.Queries[1:]
	}
	
	stats.Queries = append(stats.Queries, QueryInfo{
		Domain:    domain,
		QueryType: qtype,
		Timestamp: time.Now(),
	})
}

func (tm *TrafficMonitor) GetIPStats(ip string) *IPStats {
	tm.mu.RLock()
	defer tm.mu.RUnlock()

	if stats, exists := tm.stats[ip]; exists {
		statsCopy := &IPStats{
			RequestCount:    stats.RequestCount,
			LastRequestTime: stats.LastRequestTime,
			FirstSeen:       stats.FirstSeen,
			Queries:         make([]QueryInfo, len(stats.Queries)),
		}
		copy(statsCopy.Queries, stats.Queries)
		return statsCopy
	}
	return nil
}

func (tm *TrafficMonitor) GetRecentRequestCount(ip string, duration time.Duration) int {
	tm.mu.RLock()
	defer tm.mu.RUnlock()

	stats, exists := tm.stats[ip]
	if !exists {
		return 0
	}

	cutoff := time.Now().Add(-duration)
	count := 0
	
	for _, query := range stats.Queries {
		if query.Timestamp.After(cutoff) {
			count++
		}
	}
	
	return count
}

func (tm *TrafficMonitor) GetRecentQueries(ip string, duration time.Duration) []QueryInfo {
	tm.mu.RLock()
	defer tm.mu.RUnlock()

	stats, exists := tm.stats[ip]
	if !exists {
		return nil
	}

	cutoff := time.Now().Add(-duration)
	recent := make([]QueryInfo, 0)
	
	for _, query := range stats.Queries {
		if query.Timestamp.After(cutoff) {
			recent = append(recent, query)
		}
	}
	
	return recent
}

func (tm *TrafficMonitor) StartCleanup(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			tm.cleanup()
		}
	}
}

func (tm *TrafficMonitor) cleanup() {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	cutoff := time.Now().Add(-30 * time. Minute)
	
	for ip, stats := range tm.stats {
		if stats.LastRequestTime.Before(cutoff) {
			delete(tm.stats, ip)
		}
	}
}

func (tm *TrafficMonitor) GetAllStats() map[string]*IPStats {
	tm.mu.RLock()
	defer tm.mu.RUnlock()

	statsCopy := make(map[string]*IPStats)
	for ip, stats := range tm.stats {
		statsCopy[ip] = &IPStats{
			RequestCount:    stats.RequestCount,
			LastRequestTime: stats.LastRequestTime,
			FirstSeen:       stats.FirstSeen,
		}
	}
	
	return statsCopy
}

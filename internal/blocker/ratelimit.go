package blocker

import (
	"context"
	"sync"
	"time"

	"ddd/internal/logger"
)

type BlockedIP struct {
	IP         string    `json:"ip"`
	BlockedAt  time.Time `json:"blocked_at"`
	BlockUntil time.Time `json:"block_until"`
	Reason     string    `json:"reason"`
	BlockCount int       `json:"block_count"`
}

type IPBlocker struct {
	mu             sync.RWMutex
	blockedIPs     map[string]*BlockedIP
	rateLimitedIPs map[string]time.Time
	blockDuration  int // in seconds
	rateLimitWindow time.Duration
	log            *logger.Logger
}

func NewIPBlocker(blockDuration int, log *logger.Logger) *IPBlocker {
	return &IPBlocker{
		blockedIPs:     make(map[string]*BlockedIP),
		rateLimitedIPs: make(map[string]time.Time),
		blockDuration:  blockDuration,
		rateLimitWindow: 30 * time.Second,
		log:            log,
	}
}

func (b *IPBlocker) IsBlocked(ip string) bool {
	b.mu.RLock()
	defer b.mu.RUnlock()
	if blocked, exists := b.blockedIPs[ip]; exists {
		if time.Now().Before(blocked.BlockUntil) {
			return true
		}
		delete(b.blockedIPs, ip)
	}
	return false
}

func (b *IPBlocker) IsRateLimited(ip string) bool {
	b.mu.RLock()
	defer b.mu.RUnlock()
	if limitedUntil, exists := b.rateLimitedIPs[ip]; exists {
		if time.Now().Before(limitedUntil) {
			return true
		}
		delete(b.rateLimitedIPs, ip)
	}
	return false
}

func (b *IPBlocker) BlockIP(ip, reason string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := time.Now()
	blockUntil := now.Add(time.Duration(b.blockDuration) * time.Second)

	if blocked, exists := b.blockedIPs[ip]; exists {
		blocked.BlockUntil = blockUntil
		blocked.BlockCount++
		blocked.Reason = reason
	} else {
		b.blockedIPs[ip] = &BlockedIP{
			IP:         ip,
			BlockedAt:  now,
			BlockUntil: blockUntil,
			Reason:     reason,
			BlockCount: 1,
		}
	}

	b.log.LogIPBlocked(ip, reason, b.blockDuration)
	b.log.LogMitigationAction(ip, "block", reason)
}

func (b *IPBlocker) RateLimitIP(ip string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	limitUntil := time.Now().Add(b.rateLimitWindow)
	b.rateLimitedIPs[ip] = limitUntil
	b.log.LogIPRateLimited(ip)
	b.log.LogMitigationAction(ip, "rate_limit", "temporary rate limiting applied")
}

func (b *IPBlocker) UnblockIP(ip string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.blockedIPs, ip)
	delete(b.rateLimitedIPs, ip)
	b.log.LogMitigationAction(ip, "unblock", "manually unblocked")
}

func (b *IPBlocker) GetBlockedIP(ip string) *BlockedIP {
	b.mu.RLock()
	defer b.mu.RUnlock()
	if blocked, exists := b.blockedIPs[ip]; exists {
		if time.Now().Before(blocked.BlockUntil) {
			return &BlockedIP{
				IP:         blocked.IP,
				BlockedAt:  blocked.BlockedAt,
				BlockUntil: blocked.BlockUntil,
				Reason:     blocked.Reason,
				BlockCount: blocked.BlockCount,
			}
		}
		delete(b.blockedIPs, ip)
	}
	return nil
}

func (b *IPBlocker) GetAllBlockedIPs() []BlockedIP {
	b.mu.RLock()
	defer b.mu.RUnlock()

	var blocked []BlockedIP
	now := time.Now()
	for _, entry := range b.blockedIPs {
		if now.Before(entry.BlockUntil) {
			blocked = append(blocked, BlockedIP{
				IP:         entry.IP,
				BlockedAt:  entry.BlockedAt,
				BlockUntil: entry.BlockUntil,
				Reason:     entry.Reason,
				BlockCount: entry.BlockCount,
			})
		}
	}
	return blocked
}

func (b *IPBlocker) StartCleanup(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			b.cleanup()
		}
	}
}

func (b *IPBlocker) cleanup() {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := time.Now()
	for ip, blocked := range b.blockedIPs {
		if now.After(blocked.BlockUntil) {
			delete(b.blockedIPs, ip)
		}
	}
	for ip, limitUntil := range b.rateLimitedIPs {
		if now.After(limitUntil) {
			delete(b.rateLimitedIPs, ip)
		}
	}
}

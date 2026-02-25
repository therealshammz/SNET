// internal/monitor/anomaly.go
package monitor

import (
	"math"
	"sync"

	"gonum.org/v1/gonum/stat"
)

// AnomalyDetector tracks sliding windows and detects outliers
type AnomalyDetector struct {
	mu           sync.RWMutex
	rateWindow   []float64 // recent requests/sec per IP or global
	entropyWindow []float64 // subdomain entropy per IP
	windowSize   int
}

// NewAnomalyDetector creates a new detector
func NewAnomalyDetector(windowSize int) *AnomalyDetector {
	return &AnomalyDetector{
		windowSize: windowSize,
	}
}

// RecordRate adds a new rate observation (call from RecordRequest or filter)
func (ad *AnomalyDetector) RecordRate(rate float64, entropy float64) {
	ad.mu.Lock()
	defer ad.mu.Unlock()

	ad.rateWindow = append(ad.rateWindow, rate)
	ad.entropyWindow = append(ad.entropyWindow, entropy)

	if len(ad.rateWindow) > ad.windowSize {
		ad.rateWindow = ad.rateWindow[1:]
		ad.entropyWindow = ad.entropyWindow[1:]
	}
}

// IsAnomaly checks if current values are outliers (z-score > 3)
func (ad *AnomalyDetector) IsAnomaly(currentRate, currentEntropy float64) bool {
	ad.mu.RLock()
	defer ad.mu.RUnlock()

	if len(ad.rateWindow) < 30 { // minimum baseline
		return false
	}

	// Rate z-score
	meanRate, stdRate := stat.MeanStdDev(ad.rateWindow, nil)
	if stdRate == 0 {
		stdRate = 1.0 // avoid div by zero
	}
	zRate := (currentRate - meanRate) / stdRate

	// Entropy z-score
	meanEnt, stdEnt := stat.MeanStdDev(ad.entropyWindow, nil)
	if stdEnt == 0 {
		stdEnt = 1.0
	}
	zEnt := (currentEntropy - meanEnt) / stdEnt

	// Flag if either is extreme
	return math.Abs(zRate) > 3.0 || math.Abs(zEnt) > 3.0
}
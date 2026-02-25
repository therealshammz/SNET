package monitor

import (
	"math"
	"sync"

	"gonum.org/v1/gonum/stat"
)

type AnomalyDetector struct {
	mu           sync.RWMutex
	rateWindow   []float64 // recent requests/sec per IP or global
	entropyWindow []float64 // subdomain entropy per IP
	windowSize   int
}

func NewAnomalyDetector(windowSize int) *AnomalyDetector {
	return &AnomalyDetector{
		windowSize: windowSize,
	}
}

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

func (ad *AnomalyDetector) IsAnomaly(currentRate, currentEntropy float64) bool {
	ad.mu.RLock()
	defer ad.mu.RUnlock()

	if len(ad.rateWindow) < 30 { // minimum baseline
		return false
	}

	meanRate, stdRate := stat.MeanStdDev(ad.rateWindow, nil)
	if stdRate == 0 {
		stdRate = 1.0 // avoid div by zero
	}
	zRate := (currentRate - meanRate) / stdRate

	meanEnt, stdEnt := stat.MeanStdDev(ad.entropyWindow, nil)
	if stdEnt == 0 {
		stdEnt = 1.0
	}
	zEnt := (currentEntropy - meanEnt) / stdEnt

	// Flag if either is extreme
	return math.Abs(zRate) > 3.0 || math.Abs(zEnt) > 3.0
}

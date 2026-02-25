package logger

import (
	"fmt"
	"os"
	"path/filepath"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

type Logger struct {
	*zap.SugaredLogger
}

func NewLogger(logPath string) (*Logger, error) {
	if !filepath.IsAbs(logPath) {
		exe, err := os.Executable()
		if err != nil {
			return nil, fmt.Errorf("cannot get executable path: %w", err)
		}
		exeDir := filepath.Dir(exe)
		logPath = filepath.Join(exeDir, logPath)
	}

	logDir := filepath.Dir(logPath)
	if err := os.MkdirAll(logDir, 0755); err != nil {
		return nil, fmt.Errorf("create log dir %s: %w", logDir, err)
	}

	file, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return nil, fmt.Errorf("cannot open log file %s: %w", logPath, err)
	}

	fileCore := zapcore.NewCore(
		zapcore.NewJSONEncoder(zap.NewProductionEncoderConfig()),
		zapcore.AddSync(file),
		zapcore.InfoLevel,
	)

	consoleCore := zapcore.NewCore(
		zapcore.NewConsoleEncoder(zap.NewDevelopmentEncoderConfig()),
		zapcore.AddSync(os.Stdout),
		zapcore.InfoLevel,
	)

	core := zapcore.NewTee(fileCore, consoleCore)

	logger := zap.New(core).Sugar()

	return &Logger{logger}, nil
}

func (l *Logger) LogDNSQuery(ip, domain, qtype string) {
	l.Infow("DNS query received",
		"ip", ip,
		"domain", domain,
		"type", qtype,
	)
}

func (l *Logger) LogDDoSDetected(ip, attackType string, count int) {
	l.Warnw("DDoS pattern detected",
		"ip", ip,
		"type", attackType,
		"count", count,
	)
}

func (l *Logger) LogIPBlocked(ip, reason string, duration int) {
	l.Warnw("IP blocked",
		"ip", ip,
		"reason", reason,
		"duration_sec", duration,
	)
}

func (l *Logger) LogIPRateLimited(ip string) {
	l.Infow("IP rate limited", "ip", ip)
}

func (l *Logger) LogMitigationAction(ip, action, reason string) {
	l.Infow("Mitigation applied",
		"ip", ip,
		"action", action,
		"reason", reason,
	)
}

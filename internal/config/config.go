package config

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Port                  int    `yaml:"port"`
	UpstreamDNS           string `yaml:"upstream_dns"`
	LogFile               string `yaml:"log_file"`
	RateLimit             int    `yaml:"rate_limit"`
	BlockTime             int    `yaml:"block_time"`
	FilterInterface       string `yaml:"filter_interface"`
	StatsPort             string `yaml:"stats_port"`

	HighRateThreshold     int    `yaml:"high_rate_threshold"`
	RepeatedQueriesMin    int    `yaml:"repeated_queries_min"`
	RandomSubdomainsMin   int    `yaml:"random_subdomains_min"`
	QueryBurstThreshold   int    `yaml:"query_burst_threshold"`
	QueryBurstWindowSec   int    `yaml:"query_burst_window_sec"`

	SYNThreshold          int    `yaml:"syn_threshold"`
	UDPThreshold          int    `yaml:"udp_threshold"`
	FilterWindowSec       int    `yaml:"filter_window_sec"`
}

func DefaultConfig() Config {
	return Config{
		Port:                  8053,
		UpstreamDNS:           "8.8.8.8:53",
		LogFile:               "logs/snet.log",
		RateLimit:             100,
		BlockTime:             300,
		FilterInterface:       "auto",
		StatsPort:             ":8080",

		HighRateThreshold:     100,
		RepeatedQueriesMin:    20,
		RandomSubdomainsMin:   20,
		QueryBurstThreshold:   50,
		QueryBurstWindowSec:   10,

		SYNThreshold:          50,
		UDPThreshold:          200,
		FilterWindowSec:       60,
	}
}

func EnsureConfig(configPath string) error {
    if !filepath.IsAbs(configPath) {
        exe, err := os.Executable()
        if err != nil {
            return fmt.Errorf("cannot get executable path: %w", err)
        }
        exeDir := filepath.Dir(exe)
        configPath = filepath.Join(exeDir, configPath)
    }

    dir := filepath.Dir(configPath)
    if err := os.MkdirAll(dir, 0755); err != nil {
        return fmt.Errorf("create config dir %s: %w", dir, err)
    }

    if _, err := os.Stat(configPath); os.IsNotExist(err) {
        cfg := DefaultConfig()
        data, err := yaml.Marshal(cfg)
        if err != nil {
            return err
        }
        if err := os.WriteFile(configPath, data, 0644); err != nil {
            return err
        }
        fmt.Printf("Created default config: %s\n", configPath)
    }

    return nil
}

func LoadFromFile(path string) (Config, error) {
    if err := EnsureConfig(path); err != nil {
        return DefaultConfig(), err
    }

    data, err := os.ReadFile(path)
    if err != nil {
        return DefaultConfig(), fmt.Errorf("read config: %w", err)
    }

    cfg := DefaultConfig()
    if err := yaml.Unmarshal(data, &cfg); err != nil {
        return DefaultConfig(), fmt.Errorf("unmarshal config: %w", err)
    }

    return cfg, nil
}

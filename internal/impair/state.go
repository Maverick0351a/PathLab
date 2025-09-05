package impair

import (
	"sync"
	"time"
)

type ProfileName string

const (
	ProfileClean          ProfileName = "CLEAN"
	ProfileAbortAfterCH   ProfileName = "ABORT_AFTER_CH"
	ProfileMTUBlackhole   ProfileName = "MTU1300_BLACKHOLE"
	ProfileLatencyJitter  ProfileName = "LATENCY_50MS_JITTER_10" // placeholder
	ProfileBandwidthLimit ProfileName = "BANDWIDTH_1MBPS"        // placeholder
)

type Config struct {
	Profile       ProfileName `json:"profile"`
	ThresholdBytes int        `json:"threshold_bytes,omitempty"`
	LatencyMs     int         `json:"latency_ms,omitempty"`
	JitterMs      int         `json:"jitter_ms,omitempty"`
	BandwidthKbps int         `json:"bandwidth_kbps,omitempty"` // client->upstream cap
	BandwidthDownKbps int     `json:"bandwidth_down_kbps,omitempty"` // upstream->client cap
	BlackholeSeconds int      `json:"blackhole_seconds,omitempty"`
	Notes         string      `json:"notes,omitempty"`
	UpdatedAt     time.Time   `json:"updated_at,omitempty"`
}

type State struct {
	mu   sync.RWMutex
	curr Config
}

func (s *State) Apply(cfg Config) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cfg.UpdatedAt = time.Now().UTC()
	// sensible defaults
	if cfg.Profile == "" {
		cfg.Profile = ProfileClean
	}
	if cfg.ThresholdBytes == 0 {
		cfg.ThresholdBytes = 1300
	}
	// Latency/jitter defaults for latency profile if not provided
	if cfg.Profile == ProfileLatencyJitter {
		if cfg.LatencyMs == 0 {
			cfg.LatencyMs = 50
		}
		if cfg.JitterMs == 0 {
			cfg.JitterMs = 10
		}
	}
	// Bandwidth default (approx 1 Mbps) if not specified
	if cfg.Profile == ProfileBandwidthLimit {
		if cfg.BandwidthKbps == 0 {
			cfg.BandwidthKbps = 1000
		}
	}
	if cfg.BlackholeSeconds <= 0 {
		cfg.BlackholeSeconds = 30
	}
	s.curr = cfg
}

func (s *State) Get() Config {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.curr
}

func (s *State) Snapshot() Config {
	return s.Get()
}

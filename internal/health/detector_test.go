package health_test

import (
	"testing"
	"time"

	"github.com/aesleif/nidhogg/internal/health"
)

func TestDetectHealthy(t *testing.T) {
	cfg := health.DefaultConfig()
	stats := health.ConnStats{
		HandshakeRTT: 100 * time.Millisecond,
	}
	if level := health.Detect(stats, cfg); level != health.Healthy {
		t.Errorf("Detect = %v, want Healthy", level)
	}
}

func TestDetectDegradedWriteError(t *testing.T) {
	cfg := health.DefaultConfig()
	stats := health.ConnStats{
		HandshakeRTT: 100 * time.Millisecond,
		WriteErrors:  1,
	}
	if level := health.Detect(stats, cfg); level != health.Degraded {
		t.Errorf("Detect = %v, want Degraded", level)
	}
}

func TestDetectDegradedReadTimeout(t *testing.T) {
	cfg := health.DefaultConfig()
	stats := health.ConnStats{
		HandshakeRTT: 100 * time.Millisecond,
		ReadTimeouts: 2,
	}
	if level := health.Detect(stats, cfg); level != health.Degraded {
		t.Errorf("Detect = %v, want Degraded", level)
	}
}

func TestDetectHealthySingleReadTimeout(t *testing.T) {
	cfg := health.DefaultConfig()
	stats := health.ConnStats{
		HandshakeRTT: 100 * time.Millisecond,
		ReadTimeouts: 1,
	}
	if level := health.Detect(stats, cfg); level != health.Healthy {
		t.Errorf("Detect = %v, want Healthy (single timeout is not degraded)", level)
	}
}

func TestDetectDegradedHighLatency(t *testing.T) {
	cfg := health.DefaultConfig()
	cfg.MaxWriteLatency = 4 * time.Second
	stats := health.ConnStats{
		HandshakeRTT:    100 * time.Millisecond,
		AvgWriteLatency: 3 * time.Second, // > 50% of 4s
	}
	if level := health.Detect(stats, cfg); level != health.Degraded {
		t.Errorf("Detect = %v, want Degraded", level)
	}
}

func TestDetectCriticalWriteErrors(t *testing.T) {
	cfg := health.DefaultConfig()
	cfg.ConsecutiveFailures = 3
	stats := health.ConnStats{
		HandshakeRTT: 100 * time.Millisecond,
		WriteErrors:  3,
	}
	if level := health.Detect(stats, cfg); level != health.Critical {
		t.Errorf("Detect = %v, want Critical", level)
	}
}

func TestDetectCriticalHighRTT(t *testing.T) {
	cfg := health.DefaultConfig()
	cfg.MaxHandshakeRTT = 1 * time.Second
	stats := health.ConnStats{
		HandshakeRTT: 2 * time.Second,
	}
	if level := health.Detect(stats, cfg); level != health.Critical {
		t.Errorf("Detect = %v, want Critical", level)
	}
}

func TestDetectCriticalReadTimeouts(t *testing.T) {
	cfg := health.DefaultConfig()
	cfg.ReadTimeoutLimit = 3
	stats := health.ConnStats{
		HandshakeRTT: 100 * time.Millisecond,
		ReadTimeouts: 3,
	}
	if level := health.Detect(stats, cfg); level != health.Critical {
		t.Errorf("Detect = %v, want Critical", level)
	}
}

func TestDetectCriticalWriteLatency(t *testing.T) {
	cfg := health.DefaultConfig()
	cfg.MaxWriteLatency = 2 * time.Second
	stats := health.ConnStats{
		HandshakeRTT:    100 * time.Millisecond,
		AvgWriteLatency: 3 * time.Second,
	}
	if level := health.Detect(stats, cfg); level != health.Critical {
		t.Errorf("Detect = %v, want Critical", level)
	}
}

func TestDegradationLevelString(t *testing.T) {
	tests := []struct {
		level health.DegradationLevel
		want  string
	}{
		{health.Healthy, "healthy"},
		{health.Degraded, "degraded"},
		{health.Critical, "critical"},
	}
	for _, tt := range tests {
		if got := tt.level.String(); got != tt.want {
			t.Errorf("%d.String() = %q, want %q", tt.level, got, tt.want)
		}
	}
}

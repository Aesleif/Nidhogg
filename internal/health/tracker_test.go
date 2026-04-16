package health_test

import (
	"math"
	"net"
	"testing"
	"time"

	"github.com/aesleif/nidhogg/internal/health"
	"github.com/aesleif/nidhogg/internal/profile"
)

func TestTrackerRTT(t *testing.T) {
	tr := health.NewTracker()

	for i := 0; i < 10; i++ {
		tr.RecordRTT(100 * time.Millisecond)
	}

	avg := tr.AvgRTT()
	if avg != 100*time.Millisecond {
		t.Errorf("AvgRTT = %v, want 100ms", avg)
	}
}

func TestTrackerRTTTrendGrowing(t *testing.T) {
	tr := health.NewTracker()

	// First half: low RTT
	for i := 0; i < 10; i++ {
		tr.RecordRTT(100 * time.Millisecond)
	}
	// Second half: high RTT
	for i := 0; i < 10; i++ {
		tr.RecordRTT(300 * time.Millisecond)
	}

	trend := tr.RTTTrend()
	if trend <= 0 {
		t.Errorf("RTTTrend = %f, want > 0 (growing)", trend)
	}
}

func TestTrackerRTTTrendStable(t *testing.T) {
	tr := health.NewTracker()

	for i := 0; i < 20; i++ {
		tr.RecordRTT(100 * time.Millisecond)
	}

	trend := tr.RTTTrend()
	if math.Abs(trend) > 0.01 {
		t.Errorf("RTTTrend = %f, want ~0 (stable)", trend)
	}
}

func TestTrackerRTTTrendImproving(t *testing.T) {
	tr := health.NewTracker()

	for i := 0; i < 10; i++ {
		tr.RecordRTT(300 * time.Millisecond)
	}
	for i := 0; i < 10; i++ {
		tr.RecordRTT(100 * time.Millisecond)
	}

	trend := tr.RTTTrend()
	if trend >= 0 {
		t.Errorf("RTTTrend = %f, want < 0 (improving)", trend)
	}
}

func TestTrackerProfile(t *testing.T) {
	tr := health.NewTracker()

	if p := tr.Profile(); p != nil {
		t.Error("expected nil profile initially")
	}

	prof := &profile.Profile{Name: "test-profile"}
	tr.SetProfile(prof)

	got := tr.Profile()
	if got == nil || got.Name != "test-profile" {
		t.Errorf("Profile = %v, want test-profile", got)
	}
}

func TestTrackerActiveConns(t *testing.T) {
	tr := health.NewTracker()

	a1, b1 := net.Pipe()
	defer a1.Close()
	defer b1.Close()
	a2, b2 := net.Pipe()
	defer a2.Close()
	defer b2.Close()

	cfg := health.DefaultConfig()
	mc1 := health.NewMonitoredConn(a1, 10*time.Millisecond, cfg, "a:443")
	mc2 := health.NewMonitoredConn(a2, 10*time.Millisecond, cfg, "b:443")

	tr.TrackConn(mc1)
	tr.TrackConn(mc2)

	if n := tr.ActiveConns(); n != 2 {
		t.Errorf("ActiveConns = %d, want 2", n)
	}

	tr.UntrackConn(mc1)
	if n := tr.ActiveConns(); n != 1 {
		t.Errorf("ActiveConns = %d, want 1", n)
	}
}

func TestTrackerAggregateLevel(t *testing.T) {
	tr := health.NewTracker()

	a1, b1 := net.Pipe()
	defer a1.Close()
	defer b1.Close()

	cfg := health.DefaultConfig()
	mc1 := health.NewMonitoredConn(a1, 10*time.Millisecond, cfg, "a:443")
	tr.TrackConn(mc1)

	if l := tr.AggregateLevel(); l != health.Healthy {
		t.Errorf("AggregateLevel = %v, want Healthy", l)
	}

	// Add a conn with high RTT → Critical
	a2, b2 := net.Pipe()
	defer a2.Close()
	defer b2.Close()
	cfg2 := health.DefaultConfig()
	cfg2.MaxHandshakeRTT = 100 * time.Millisecond
	mc2 := health.NewMonitoredConn(a2, 500*time.Millisecond, cfg2, "b:443")
	tr.TrackConn(mc2)

	if l := tr.AggregateLevel(); l != health.Critical {
		t.Errorf("AggregateLevel = %v, want Critical", l)
	}
}

func TestTrackerStats(t *testing.T) {
	tr := health.NewTracker()
	tr.RecordRTT(100 * time.Millisecond)

	prof := &profile.Profile{Name: "test"}
	tr.SetProfile(prof)

	stats := tr.Stats()
	if !stats.HasProfile {
		t.Error("HasProfile should be true")
	}
	if stats.AvgRTT != 100*time.Millisecond {
		t.Errorf("AvgRTT = %v, want 100ms", stats.AvgRTT)
	}
}

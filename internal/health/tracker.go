package health

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/aesleif/nidhogg/internal/profile"
)

const rttWindowSize = 50

type TrackerStats struct {
	AvgRTT      time.Duration
	RTTTrend    float64 // >0 growing, <0 improving
	ActiveConns int
	HealthyCnt  int
	DegradedCnt int
	CriticalCnt int
	Level       DegradationLevel
	HasProfile  bool
}

type Tracker struct {
	mu         sync.RWMutex
	rttSamples [rttWindowSize]time.Duration
	rttIdx     int
	rttCount   int

	lastProfile atomic.Pointer[profile.Profile]

	connMu sync.Mutex
	conns  map[*MonitoredConn]struct{}
}

func NewTracker() *Tracker {
	return &Tracker{
		conns: make(map[*MonitoredConn]struct{}),
	}
}

func (t *Tracker) RecordRTT(rtt time.Duration) {
	t.mu.Lock()
	t.rttSamples[t.rttIdx] = rtt
	t.rttIdx = (t.rttIdx + 1) % rttWindowSize
	if t.rttCount < rttWindowSize {
		t.rttCount++
	}
	t.mu.Unlock()
}

func (t *Tracker) AvgRTT() time.Duration {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.avgRTTLocked()
}

func (t *Tracker) avgRTTLocked() time.Duration {
	if t.rttCount == 0 {
		return 0
	}
	var total time.Duration
	for i := 0; i < t.rttCount; i++ {
		total += t.rttSamples[i]
	}
	return total / time.Duration(t.rttCount)
}

// RTTTrend compares avg of first half vs second half of the window.
// Positive = RTT growing, negative = improving, ~0 = stable.
func (t *Tracker) RTTTrend() float64 {
	t.mu.RLock()
	defer t.mu.RUnlock()

	if t.rttCount < 4 {
		return 0
	}

	half := t.rttCount / 2
	var firstTotal, secondTotal time.Duration

	// Samples are stored in insertion order in ring buffer.
	// Oldest sample index depends on whether buffer is full.
	start := 0
	if t.rttCount == rttWindowSize {
		start = t.rttIdx // oldest is at current write position
	}

	for i := 0; i < half; i++ {
		idx := (start + i) % rttWindowSize
		firstTotal += t.rttSamples[idx]
	}
	for i := half; i < t.rttCount; i++ {
		idx := (start + i) % rttWindowSize
		secondTotal += t.rttSamples[idx]
	}

	firstAvg := float64(firstTotal) / float64(half)
	secondAvg := float64(secondTotal) / float64(t.rttCount-half)

	if firstAvg == 0 {
		return 0
	}
	return (secondAvg - firstAvg) / firstAvg
}

func (t *Tracker) SetProfile(p *profile.Profile) {
	t.lastProfile.Store(p)
}

func (t *Tracker) Profile() *profile.Profile {
	return t.lastProfile.Load()
}

func (t *Tracker) TrackConn(mc *MonitoredConn) {
	t.connMu.Lock()
	t.conns[mc] = struct{}{}
	t.connMu.Unlock()
}

func (t *Tracker) UntrackConn(mc *MonitoredConn) {
	t.connMu.Lock()
	delete(t.conns, mc)
	t.connMu.Unlock()
}

func (t *Tracker) ActiveConns() int {
	t.connMu.Lock()
	defer t.connMu.Unlock()
	return len(t.conns)
}

// AggregateLevel returns the worst degradation level among active connections.
func (t *Tracker) AggregateLevel() DegradationLevel {
	t.connMu.Lock()
	defer t.connMu.Unlock()

	worst := Healthy
	for mc := range t.conns {
		if l := mc.Level(); l > worst {
			worst = l
		}
	}
	return worst
}

func (t *Tracker) Stats() TrackerStats {
	t.connMu.Lock()
	var healthy, degraded, critical int
	for mc := range t.conns {
		switch mc.Level() {
		case Healthy:
			healthy++
		case Degraded:
			degraded++
		case Critical:
			critical++
		}
	}
	active := len(t.conns)
	t.connMu.Unlock()

	worst := Healthy
	if critical > 0 {
		worst = Critical
	} else if degraded > 0 {
		worst = Degraded
	}

	return TrackerStats{
		AvgRTT:      t.AvgRTT(),
		RTTTrend:    t.RTTTrend(),
		ActiveConns: active,
		HealthyCnt:  healthy,
		DegradedCnt: degraded,
		CriticalCnt: critical,
		Level:       worst,
		HasProfile:  t.lastProfile.Load() != nil,
	}
}

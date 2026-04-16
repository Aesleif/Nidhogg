package telemetry

import (
	"log/slog"
	"sync"
	"time"
)

type RegenTrigger interface {
	TriggerRegen()
}

type Aggregator struct {
	trigger   RegenTrigger
	threshold int
	mu        sync.Mutex
	profiles  map[string]*profileStats
}

type profileStats struct {
	total    int
	critical int
	resetAt  time.Time
}

const statsResetInterval = 5 * time.Minute

func NewAggregator(trigger RegenTrigger, threshold int) *Aggregator {
	return &Aggregator{
		trigger:   trigger,
		threshold: threshold,
		profiles:  make(map[string]*profileStats),
	}
}

func (a *Aggregator) Record(r Report) {
	a.mu.Lock()
	defer a.mu.Unlock()

	ps, ok := a.profiles[r.Profile]
	if !ok {
		ps = &profileStats{resetAt: time.Now()}
		a.profiles[r.Profile] = ps
	}

	if time.Since(ps.resetAt) > statsResetInterval {
		ps.total = 0
		ps.critical = 0
		ps.resetAt = time.Now()
	}

	ps.total++
	if r.Status == "critical" {
		ps.critical++
	}

	if ps.critical >= a.threshold {
		slog.Warn("telemetry: critical threshold reached, triggering regen",
			"profile", r.Profile, "critical", ps.critical, "total", ps.total)
		a.trigger.TriggerRegen()
		ps.total = 0
		ps.critical = 0
		ps.resetAt = time.Now()
	}
}

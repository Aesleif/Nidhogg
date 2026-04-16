package health

type DegradationLevel int

const (
	Healthy DegradationLevel = iota
	Degraded
	Critical
)

func (l DegradationLevel) String() string {
	switch l {
	case Healthy:
		return "healthy"
	case Degraded:
		return "degraded"
	case Critical:
		return "critical"
	}
	return "unknown"
}

// Detect evaluates connection stats against thresholds and returns the degradation level.
func Detect(stats ConnStats, cfg Config) DegradationLevel {
	// Critical: any single condition breached
	if stats.HandshakeRTT > cfg.MaxHandshakeRTT {
		return Critical
	}
	if cfg.ConsecutiveFailures > 0 && stats.WriteErrors >= cfg.ConsecutiveFailures {
		return Critical
	}
	if cfg.ReadTimeoutLimit > 0 && stats.ReadTimeouts >= cfg.ReadTimeoutLimit {
		return Critical
	}
	if cfg.MaxWriteLatency > 0 && stats.AvgWriteLatency > cfg.MaxWriteLatency {
		return Critical
	}

	// Degraded: early warning signs
	if stats.WriteErrors >= 1 {
		return Degraded
	}
	if stats.ReadTimeouts >= 2 {
		return Degraded
	}
	if cfg.MaxWriteLatency > 0 && stats.AvgWriteLatency > cfg.MaxWriteLatency/2 {
		return Degraded
	}

	return Healthy
}

package telemetry

import "github.com/aesleif/nidhogg/internal/health"

type Report struct {
	Profile    string `json:"profile"`
	Status     string `json:"status"`
	AvgRTTMs   int64  `json:"avg_rtt_ms"`
	ErrorCount int    `json:"error_count"`
}

func StatusFromLevel(l health.DegradationLevel) string {
	switch l {
	case health.Degraded:
		return "degraded"
	case health.Critical:
		return "critical"
	default:
		return "healthy"
	}
}

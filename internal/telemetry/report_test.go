package telemetry_test

import (
	"testing"

	"github.com/aesleif/nidhogg/internal/health"
	"github.com/aesleif/nidhogg/internal/telemetry"
)

func TestStatusFromLevel(t *testing.T) {
	tests := []struct {
		level health.DegradationLevel
		want  string
	}{
		{health.Healthy, "healthy"},
		{health.Degraded, "degraded"},
		{health.Critical, "critical"},
	}
	for _, tt := range tests {
		if got := telemetry.StatusFromLevel(tt.level); got != tt.want {
			t.Errorf("StatusFromLevel(%v) = %q, want %q", tt.level, got, tt.want)
		}
	}
}

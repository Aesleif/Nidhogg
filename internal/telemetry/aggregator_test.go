package telemetry_test

import (
	"sync/atomic"
	"testing"

	"github.com/aesleif/nidhogg/internal/telemetry"
)

type mockTrigger struct {
	count atomic.Int32
}

func (m *mockTrigger) TriggerRegen() {
	m.count.Add(1)
}

func TestAggregatorRecord(t *testing.T) {
	trigger := &mockTrigger{}
	agg := telemetry.NewAggregator(trigger, 3)

	agg.Record(telemetry.Report{Profile: "p1", Status: "degraded"})
	agg.Record(telemetry.Report{Profile: "p1", Status: "healthy"})

	if trigger.count.Load() != 0 {
		t.Error("expected no regen trigger for non-critical reports")
	}
}

func TestAggregatorCriticalThreshold(t *testing.T) {
	trigger := &mockTrigger{}
	agg := telemetry.NewAggregator(trigger, 3)

	agg.Record(telemetry.Report{Profile: "p1", Status: "critical"})
	agg.Record(telemetry.Report{Profile: "p1", Status: "critical"})

	if trigger.count.Load() != 0 {
		t.Error("should not trigger before threshold")
	}

	agg.Record(telemetry.Report{Profile: "p1", Status: "critical"})

	if trigger.count.Load() != 1 {
		t.Errorf("TriggerRegen called %d times, want 1", trigger.count.Load())
	}
}

func TestAggregatorDifferentProfiles(t *testing.T) {
	trigger := &mockTrigger{}
	agg := telemetry.NewAggregator(trigger, 2)

	agg.Record(telemetry.Report{Profile: "p1", Status: "critical"})
	agg.Record(telemetry.Report{Profile: "p2", Status: "critical"})

	if trigger.count.Load() != 0 {
		t.Error("different profiles should not combine toward threshold")
	}

	agg.Record(telemetry.Report{Profile: "p1", Status: "critical"})

	if trigger.count.Load() != 1 {
		t.Errorf("TriggerRegen called %d times, want 1", trigger.count.Load())
	}
}

func TestAggregatorResetsAfterTrigger(t *testing.T) {
	trigger := &mockTrigger{}
	agg := telemetry.NewAggregator(trigger, 2)

	agg.Record(telemetry.Report{Profile: "p1", Status: "critical"})
	agg.Record(telemetry.Report{Profile: "p1", Status: "critical"})

	if trigger.count.Load() != 1 {
		t.Fatal("expected first trigger")
	}

	// After reset, need threshold again
	agg.Record(telemetry.Report{Profile: "p1", Status: "critical"})
	if trigger.count.Load() != 1 {
		t.Error("should not trigger again after single report post-reset")
	}

	agg.Record(telemetry.Report{Profile: "p1", Status: "critical"})
	if trigger.count.Load() != 2 {
		t.Errorf("TriggerRegen called %d times, want 2", trigger.count.Load())
	}
}

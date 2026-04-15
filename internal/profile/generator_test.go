package profile

import (
	"testing"
	"time"

	"github.com/aesleif/nidhogg/internal/pcap"
)

func TestBuildCDF(t *testing.T) {
	values := make([]float64, 100)
	for i := range values {
		values[i] = float64(i + 1)
	}

	cdf := buildCDF(values, 100)

	if len(cdf) != 100 {
		t.Fatalf("expected 100 points, got %d", len(cdf))
	}

	if cdf[0].Percentile != 0 {
		t.Errorf("first percentile = %f, want 0", cdf[0].Percentile)
	}
	if cdf[len(cdf)-1].Percentile != 1.0 {
		t.Errorf("last percentile = %f, want 1.0", cdf[len(cdf)-1].Percentile)
	}

	// Monotonically increasing
	for i := 1; i < len(cdf); i++ {
		if cdf[i].Value < cdf[i-1].Value {
			t.Errorf("CDF not monotonic at %d: %f < %f", i, cdf[i].Value, cdf[i-1].Value)
		}
		if cdf[i].Percentile < cdf[i-1].Percentile {
			t.Errorf("percentile not monotonic at %d: %f < %f", i, cdf[i].Percentile, cdf[i-1].Percentile)
		}
	}
}

func TestBuildCDF_Empty(t *testing.T) {
	cdf := buildCDF(nil, 100)
	if cdf != nil {
		t.Errorf("expected nil for empty input, got %d points", len(cdf))
	}
}

func testSnapshot() *pcap.TrafficSnapshot {
	base := time.Now()
	samples := []pcap.PacketSample{
		// Burst 1: 3 packets, < 50ms apart
		{Size: 100, Direction: true, Timestamp: base},
		{Size: 500, Direction: false, Timestamp: base.Add(10 * time.Millisecond)},
		{Size: 200, Direction: true, Timestamp: base.Add(20 * time.Millisecond)},
		// Pause > 200ms
		// Burst 2: 2 packets
		{Size: 1500, Direction: false, Timestamp: base.Add(300 * time.Millisecond)},
		{Size: 50, Direction: true, Timestamp: base.Add(310 * time.Millisecond)},
		// Pause > 200ms
		// Burst 3: 4 packets
		{Size: 800, Direction: false, Timestamp: base.Add(600 * time.Millisecond)},
		{Size: 150, Direction: true, Timestamp: base.Add(620 * time.Millisecond)},
		{Size: 3000, Direction: false, Timestamp: base.Add(640 * time.Millisecond)},
		{Size: 100, Direction: true, Timestamp: base.Add(660 * time.Millisecond)},
	}

	return &pcap.TrafficSnapshot{
		Samples:   samples,
		Target:    "example.com",
		Duration:  700 * time.Millisecond,
		CreatedAt: base,
	}
}

func TestGenerate(t *testing.T) {
	snap := testSnapshot()
	p := Generate("test", []*pcap.TrafficSnapshot{snap})

	if p.Name != "test" {
		t.Errorf("Name = %q, want %q", p.Name, "test")
	}

	if len(p.SendSizeCDF) == 0 {
		t.Error("SendSizeCDF is empty")
	}
	if len(p.RecvSizeCDF) == 0 {
		t.Error("RecvSizeCDF is empty")
	}
	if len(p.TimingCDF) == 0 {
		t.Error("TimingCDF is empty")
	}
	if p.AvgBurstLen < 1 {
		t.Errorf("AvgBurstLen = %d, want >= 1", p.AvgBurstLen)
	}

	t.Logf("AvgBurstLen=%d, BurstPause=[%v, %v]", p.AvgBurstLen, p.BurstPause.Min, p.BurstPause.Max)
	t.Logf("SendSizeCDF: %d points, RecvSizeCDF: %d points, TimingCDF: %d points",
		len(p.SendSizeCDF), len(p.RecvSizeCDF), len(p.TimingCDF))
}

func TestSampleSize(t *testing.T) {
	snap := testSnapshot()
	p := Generate("test", []*pcap.TrafficSnapshot{snap})

	min := p.SendSizeCDF[0].Value
	max := p.SendSizeCDF[len(p.SendSizeCDF)-1].Value

	for i := 0; i < 1000; i++ {
		s := p.SampleSize()
		if float64(s) < min || float64(s) > max {
			t.Errorf("SampleSize() = %d, out of range [%.0f, %.0f]", s, min, max)
		}
	}
}

func TestSampleTiming(t *testing.T) {
	snap := testSnapshot()
	p := Generate("test", []*pcap.TrafficSnapshot{snap})

	for i := 0; i < 1000; i++ {
		d := p.SampleTiming()
		if d < 0 {
			t.Errorf("SampleTiming() = %v, should not be negative", d)
		}
	}
}

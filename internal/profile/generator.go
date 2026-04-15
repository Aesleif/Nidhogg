package profile

import (
	"sort"
	"time"

	"github.com/aesleif/nidhogg/internal/pcap"
)

const (
	cdfPoints      = 100
	burstThreshold = 50 * time.Millisecond
	pauseThreshold = 200 * time.Millisecond
	profileTTL     = 24 * time.Hour
)

// Generate builds a Profile from one or more TrafficSnapshots.
func Generate(name string, snapshots []*pcap.TrafficSnapshot) *Profile {
	var sendSizes, recvSizes []float64
	var allSamples []pcap.PacketSample

	for _, snap := range snapshots {
		for _, s := range snap.Samples {
			allSamples = append(allSamples, s)
			if s.Direction {
				sendSizes = append(sendSizes, float64(s.Size))
			} else {
				recvSizes = append(recvSizes, float64(s.Size))
			}
		}
	}

	// Sort all samples by timestamp for timing analysis
	sort.Slice(allSamples, func(i, j int) bool {
		return allSamples[i].Timestamp.Before(allSamples[j].Timestamp)
	})

	// Compute inter-packet intervals
	var intervals []float64
	for i := 1; i < len(allSamples); i++ {
		dt := allSamples[i].Timestamp.Sub(allSamples[i-1].Timestamp)
		intervals = append(intervals, float64(dt.Milliseconds()))
	}

	// Detect bursts
	avgBurst, burstPause := detectBursts(allSamples)

	now := time.Now()
	return &Profile{
		Name:        name,
		CreatedAt:   now,
		ExpiresAt:   now.Add(profileTTL),
		SendSizeCDF: buildCDF(sendSizes, cdfPoints),
		RecvSizeCDF: buildCDF(recvSizes, cdfPoints),
		TimingCDF:   buildCDF(intervals, cdfPoints),
		AvgBurstLen: avgBurst,
		BurstPause:  burstPause,
	}
}

// buildCDF constructs a CDF with the given number of points from sorted values.
func buildCDF(values []float64, points int) []CDFPoint {
	if len(values) == 0 {
		return nil
	}

	sort.Float64s(values)

	if points < 2 {
		points = 2
	}

	cdf := make([]CDFPoint, points)
	for i := 0; i < points; i++ {
		p := float64(i) / float64(points-1)
		idx := int(p * float64(len(values)-1))
		cdf[i] = CDFPoint{Value: values[idx], Percentile: p}
	}
	return cdf
}

// detectBursts analyzes samples to find burst length and pause duration.
// A burst is a series of packets with inter-packet interval < 50ms.
// A pause is an interval > 200ms.
func detectBursts(samples []pcap.PacketSample) (avgBurstLen int, pause DurationRange) {
	if len(samples) < 2 {
		return 1, DurationRange{}
	}

	var burstLengths []int
	var pauses []time.Duration
	currentBurst := 1

	for i := 1; i < len(samples); i++ {
		dt := samples[i].Timestamp.Sub(samples[i-1].Timestamp)

		if dt < burstThreshold {
			currentBurst++
		} else {
			burstLengths = append(burstLengths, currentBurst)
			currentBurst = 1

			if dt > pauseThreshold {
				pauses = append(pauses, dt)
			}
		}
	}
	burstLengths = append(burstLengths, currentBurst)

	// Average burst length
	total := 0
	for _, bl := range burstLengths {
		total += bl
	}
	avgBurstLen = total / len(burstLengths)
	if avgBurstLen < 1 {
		avgBurstLen = 1
	}

	// Pause range
	if len(pauses) > 0 {
		sort.Slice(pauses, func(i, j int) bool { return pauses[i] < pauses[j] })
		pause = DurationRange{
			Min: pauses[0],
			Max: pauses[len(pauses)-1],
		}
	}

	return avgBurstLen, pause
}

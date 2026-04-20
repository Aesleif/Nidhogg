package profile

import (
	"math/rand/v2"
	"sort"
	"time"
)

// SampleSize returns a random packet size drawn from the send size CDF.
func (p *Profile) SampleSize() int {
	v := sampleCDF(p.SendSizeCDF)
	if v < 1 {
		return 1
	}
	return int(v)
}

// SampleTiming returns a random inter-packet delay drawn from the timing CDF.
func (p *Profile) SampleTiming() time.Duration {
	ms := sampleCDF(p.TimingCDF)
	if ms < 0 {
		return 0
	}
	return time.Duration(ms) * time.Millisecond
}

// SamplePercentile returns the Value at percentile p (0..1) using linear
// interpolation between adjacent CDF points. Used for diagnostic logging
// to compare profile distributions over time.
func SamplePercentile(cdf []CDFPoint, p float64) float64 {
	if len(cdf) == 0 {
		return 0
	}
	if p <= cdf[0].Percentile {
		return cdf[0].Value
	}
	if p >= cdf[len(cdf)-1].Percentile {
		return cdf[len(cdf)-1].Value
	}
	idx := sort.Search(len(cdf), func(i int) bool {
		return cdf[i].Percentile >= p
	})
	lo := cdf[idx-1]
	hi := cdf[idx]
	if hi.Percentile == lo.Percentile {
		return lo.Value
	}
	t := (p - lo.Percentile) / (hi.Percentile - lo.Percentile)
	return lo.Value + t*(hi.Value-lo.Value)
}

// sampleCDF picks a random value from a CDF using binary search + linear interpolation.
func sampleCDF(cdf []CDFPoint) float64 {
	if len(cdf) == 0 {
		return 0
	}

	r := rand.Float64()

	// Find the first point where Percentile >= r
	idx := sort.Search(len(cdf), func(i int) bool {
		return cdf[i].Percentile >= r
	})

	if idx == 0 {
		return cdf[0].Value
	}
	if idx >= len(cdf) {
		return cdf[len(cdf)-1].Value
	}

	// Linear interpolation between cdf[idx-1] and cdf[idx]
	lo := cdf[idx-1]
	hi := cdf[idx]
	if hi.Percentile == lo.Percentile {
		return lo.Value
	}

	t := (r - lo.Percentile) / (hi.Percentile - lo.Percentile)
	return lo.Value + t*(hi.Value-lo.Value)
}

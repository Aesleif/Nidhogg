package profile

import (
	"hash/crc32"
	"time"
)

// CDFPoint represents a single point on a cumulative distribution function.
type CDFPoint struct {
	Value      float64 `json:"v"` // bytes or milliseconds
	Percentile float64 `json:"p"` // 0.0 – 1.0
}

// DurationRange represents a min/max duration range.
type DurationRange struct {
	Min time.Duration `json:"min"`
	Max time.Duration `json:"max"`
}

// Profile holds statistical characteristics of captured traffic,
// used to shape tunnel traffic to match real HTTPS patterns.
type Profile struct {
	Name        string        `json:"name"`
	CreatedAt   time.Time     `json:"created_at"`
	ExpiresAt   time.Time     `json:"expires_at"`
	SendSizeCDF []CDFPoint    `json:"send_size_cdf"`
	RecvSizeCDF []CDFPoint    `json:"recv_size_cdf"`
	TimingCDF   []CDFPoint    `json:"timing_cdf"`
	AvgBurstLen int           `json:"avg_burst_len"`
	BurstPause  DurationRange `json:"burst_pause"`
}

// VersionHash computes a CRC32 version hash from serialized profile JSON.
func VersionHash(profileJSON []byte) uint32 {
	return crc32.ChecksumIEEE(profileJSON)
}

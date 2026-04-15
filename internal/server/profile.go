package server

import (
	"context"
	"log/slog"
	"strings"
	"time"

	"github.com/aesleif/nidhogg/internal/pcap"
	"github.com/aesleif/nidhogg/internal/profile"
)

const (
	collectDuration = 10 * time.Second
	cacheSize       = 5
)

// ProfileManager periodically collects traffic snapshots from target sites
// and generates traffic profiles for tunnel shaping.
type ProfileManager struct {
	cache    *profile.Cache
	targets  []string
	interval time.Duration
}

// NewProfileManager creates a new ProfileManager.
func NewProfileManager(targets []string, interval time.Duration) *ProfileManager {
	return &ProfileManager{
		cache:    profile.NewCache(cacheSize),
		targets:  targets,
		interval: interval,
	}
}

// Start generates the first profile immediately, then periodically regenerates.
// Blocks until ctx is cancelled.
func (pm *ProfileManager) Start(ctx context.Context) {
	pm.generateProfile()

	ticker := time.NewTicker(pm.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			pm.generateProfile()
		}
	}
}

// Current returns the current active profile, or nil if none available.
func (pm *ProfileManager) Current() *profile.Profile {
	return pm.cache.Current()
}

// Push inserts a profile into the cache without collecting. Useful for tests.
func (pm *ProfileManager) Push(p *profile.Profile) {
	pm.cache.Push(p)
}

func (pm *ProfileManager) generateProfile() {
	var snapshots []*pcap.TrafficSnapshot

	for _, target := range pm.targets {
		snap, err := pcap.Collect(target, collectDuration)
		if err != nil {
			slog.Warn("profile: failed to collect", "target", target, "err", err)
			continue
		}
		slog.Info("profile: collected samples", "target", target, "samples", len(snap.Samples))
		snapshots = append(snapshots, snap)
	}

	if len(snapshots) == 0 {
		slog.Warn("profile: no snapshots collected, skipping generation")
		return
	}

	name := strings.Join(pm.targets, "+")
	prof := profile.Generate(name, snapshots)
	pm.cache.Push(prof)
	slog.Info("profile: generated",
		"name", prof.Name,
		"send_cdf_points", len(prof.SendSizeCDF),
		"avg_burst", prof.AvgBurstLen)
}

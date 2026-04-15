package server

import (
	"context"
	"log"
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
			log.Printf("profile: failed to collect from %s: %v", target, err)
			continue
		}
		log.Printf("profile: collected %d samples from %s", len(snap.Samples), target)
		snapshots = append(snapshots, snap)
	}

	if len(snapshots) == 0 {
		log.Printf("profile: no snapshots collected, skipping generation")
		return
	}

	name := strings.Join(pm.targets, "+")
	prof := profile.Generate(name, snapshots)
	pm.cache.Push(prof)
	log.Printf("profile: generated %q (%d send CDF points, avg burst %d)",
		prof.Name, len(prof.SendSizeCDF), prof.AvgBurstLen)
}

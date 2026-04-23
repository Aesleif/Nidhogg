package server

import (
	"context"
	"encoding/json"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/aesleif/nidhogg/internal/pcap"
	"github.com/aesleif/nidhogg/internal/profile"
)

const (
	collectDuration = 10 * time.Second
	cacheSize       = 5
)

// ProfileManager collects traffic snapshots from real tunnel connections
// to target hosts and generates traffic profiles for shaping.
// On startup it runs a one-time bootstrap via pcap.Collect.
type ProfileManager struct {
	cache        *profile.Cache
	targets      []string
	targetSet    map[string]struct{}
	interval     time.Duration
	minSnapshots int

	mu      sync.Mutex
	buffer  []*pcap.TrafficSnapshot
	regenCh chan struct{}
}

// NewProfileManager creates a new ProfileManager.
func NewProfileManager(targets []string, interval time.Duration, minSnapshots int) *ProfileManager {
	ts := make(map[string]struct{}, len(targets))
	for _, t := range targets {
		ts[t] = struct{}{}
	}
	return &ProfileManager{
		cache:        profile.NewCache(cacheSize),
		targets:      targets,
		targetSet:    ts,
		interval:     interval,
		minSnapshots: minSnapshots,
		regenCh:      make(chan struct{}, 1),
	}
}

// MatchTarget checks if hostPort (e.g. "google.com:443") matches a target.
// Returns the matched target name and true, or ("", false).
func (pm *ProfileManager) MatchTarget(hostPort string) (string, bool) {
	host, _, err := net.SplitHostPort(hostPort)
	if err != nil {
		return "", false
	}
	if _, ok := pm.targetSet[host]; ok {
		return host, true
	}
	return "", false
}

// Record adds a traffic snapshot from a real tunnel connection.
// If the buffer reaches minSnapshots, signals regeneration.
func (pm *ProfileManager) Record(target string, snap *pcap.TrafficSnapshot) {
	pm.mu.Lock()
	pm.buffer = append(pm.buffer, snap)
	n := len(pm.buffer)
	pm.mu.Unlock()

	slog.Debug("profile: recorded snapshot", "target", target, "samples", len(snap.Samples), "buffered", n)

	if n >= pm.minSnapshots {
		select {
		case pm.regenCh <- struct{}{}:
		default:
		}
	}
}

// Start runs bootstrap, then waits for regeneration triggers.
// Blocks until ctx is cancelled.
func (pm *ProfileManager) Start(ctx context.Context) {
	pm.bootstrap()

	ticker := time.NewTicker(pm.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			pm.regenerate("timer")
		case <-pm.regenCh:
			pm.regenerate("threshold")
		}
	}
}

// Current returns the current active profile, or nil if none available.
func (pm *ProfileManager) Current() *profile.Profile {
	return pm.cache.Current()
}

// TriggerRegen sends a non-blocking signal to regenerate the profile.
func (pm *ProfileManager) TriggerRegen() {
	select {
	case pm.regenCh <- struct{}{}:
	default:
	}
}

// Push inserts a profile into the cache without collecting. Useful for tests.
func (pm *ProfileManager) Push(p *profile.Profile) {
	pm.cache.Push(p)
}

func (pm *ProfileManager) bootstrap() {
	var snapshots []*pcap.TrafficSnapshot

	for _, target := range pm.targets {
		snap, err := pcap.Collect(target, collectDuration)
		if err != nil {
			slog.Warn("profile: bootstrap collect failed", "target", target, "err", err)
			continue
		}
		slog.Info("profile: bootstrap collected", "target", target, "samples", len(snap.Samples))
		snapshots = append(snapshots, snap)
	}

	if len(snapshots) == 0 {
		slog.Warn("profile: bootstrap failed, no snapshots collected")
		return
	}

	name := strings.Join(pm.targets, "+")
	prof := profile.Generate(name, snapshots)
	pm.cache.Push(prof)
	slog.Info("profile: generated",
		"phase", "bootstrap",
		"name", prof.Name,
		"version", profileVersion(prof),
		"send_cdf_points", len(prof.SendSizeCDF),
		"avg_burst", prof.AvgBurstLen,
		"send_p50", int(profile.SamplePercentile(prof.SendSizeCDF, 0.5)),
		"send_p95", int(profile.SamplePercentile(prof.SendSizeCDF, 0.95)),
		"send_p99", int(profile.SamplePercentile(prof.SendSizeCDF, 0.99)))
}

// profileVersion serializes prof to JSON and returns the VersionHash
// the server uses when advertising this profile to clients. Marshaling
// cost is negligible — called once per generation (rare).
func profileVersion(prof *profile.Profile) uint32 {
	data, err := json.Marshal(prof)
	if err != nil {
		return 0
	}
	return profile.VersionHash(data)
}

func (pm *ProfileManager) regenerate(trigger string) {
	pm.mu.Lock()
	snaps := pm.buffer
	pm.buffer = nil
	pm.mu.Unlock()

	if len(snaps) == 0 {
		slog.Debug("profile: buffer empty, collecting fresh snapshots", "trigger", trigger)
		for _, target := range pm.targets {
			snap, err := pcap.Collect(target, collectDuration)
			if err != nil {
				slog.Warn("profile: collect failed", "target", target, "err", err)
				continue
			}
			snaps = append(snaps, snap)
		}
	}

	if len(snaps) == 0 {
		slog.Warn("profile: regenerate failed, no data", "trigger", trigger)
		return
	}

	name := strings.Join(pm.targets, "+")
	prof := profile.Generate(name, snaps)
	pm.cache.Push(prof)
	slog.Info("profile: generated",
		"phase", "regenerated",
		"trigger", trigger,
		"snapshots", len(snaps),
		"name", prof.Name,
		"version", profileVersion(prof),
		"send_cdf_points", len(prof.SendSizeCDF),
		"avg_burst", prof.AvgBurstLen,
		"send_p50", int(profile.SamplePercentile(prof.SendSizeCDF, 0.5)),
		"send_p95", int(profile.SamplePercentile(prof.SendSizeCDF, 0.95)),
		"send_p99", int(profile.SamplePercentile(prof.SendSizeCDF, 0.99)))
}

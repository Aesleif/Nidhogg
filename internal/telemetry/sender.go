package telemetry

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/aesleif/nidhogg/internal/health"
	"github.com/aesleif/nidhogg/internal/profile"
	"github.com/aesleif/nidhogg/internal/transport"
)

type TrackerSource interface {
	Stats() health.TrackerStats
}

type ProfileSource interface {
	Active() *profile.Profile
}

type Sender struct {
	serverURL      string
	psk            []byte
	client         *http.Client
	interval       time.Duration
	tracker        TrackerSource
	switcher       ProfileSource
	profileVersion uint32
	OnProfile      func(*profile.Profile)
}

func NewSender(serverURL string, psk []byte, client *http.Client, interval time.Duration, tracker TrackerSource, sw ProfileSource) *Sender {
	return &Sender{
		serverURL: serverURL,
		psk:       psk,
		client:    client,
		interval:  interval,
		tracker:   tracker,
		switcher:  sw,
	}
}

func (s *Sender) Start(ctx context.Context) {
	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			prof := s.switcher.Active()
			if prof == nil {
				continue
			}
			stats := s.tracker.Stats()
			report := Report{
				Profile:    prof.Name,
				Status:     StatusFromLevel(stats.Level),
				AvgRTTMs:   stats.AvgRTT.Milliseconds(),
				ErrorCount: stats.DegradedCnt + stats.CriticalCnt,
			}
			newProf, err := s.send(ctx, report)
			if err != nil {
				slog.Debug("telemetry: send failed", "err", err)
				continue
			}
			if newProf != nil && s.OnProfile != nil {
				s.OnProfile(newProf)
			}
		}
	}
}

func (s *Sender) send(ctx context.Context, report Report) (*profile.Profile, error) {
	// Build header synchronously
	var header bytes.Buffer
	marker, err := transport.GenerateHandshake(s.psk)
	if err != nil {
		return nil, fmt.Errorf("generate handshake: %w", err)
	}
	header.Write(marker)
	if err := transport.WriteDest(&header, transport.Destination{Command: transport.CommandTelemetry}); err != nil {
		return nil, fmt.Errorf("write destination: %w", err)
	}
	var knownVersionBuf [4]byte
	binary.BigEndian.PutUint32(knownVersionBuf[:], s.profileVersion)
	header.Write(knownVersionBuf[:])
	header.WriteByte(0) // shaping disabled — telemetry path is not relayed
	json.NewEncoder(&header).Encode(report)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.serverURL, &header)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/octet-stream")

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("server returned %d", resp.StatusCode)
	}

	// Read profile response: [version:4B] [size:4B] [json?]
	var versionBuf [4]byte
	if _, err := io.ReadFull(resp.Body, versionBuf[:]); err != nil {
		return nil, fmt.Errorf("read profile version: %w", err)
	}
	serverVersion := binary.BigEndian.Uint32(versionBuf[:])

	var sizeBuf [4]byte
	if _, err := io.ReadFull(resp.Body, sizeBuf[:]); err != nil {
		return nil, fmt.Errorf("read profile size: %w", err)
	}
	profSize := binary.BigEndian.Uint32(sizeBuf[:])
	if profSize == 0 {
		if serverVersion != 0 {
			s.profileVersion = serverVersion
		}
		return nil, nil
	}

	profJSON := make([]byte, profSize)
	if _, err := io.ReadFull(resp.Body, profJSON); err != nil {
		return nil, fmt.Errorf("read profile data: %w", err)
	}
	prof := &profile.Profile{}
	if err := json.Unmarshal(profJSON, prof); err != nil {
		return nil, fmt.Errorf("parse profile: %w", err)
	}
	s.profileVersion = serverVersion
	return prof, nil
}

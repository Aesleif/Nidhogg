package telemetry

import (
	"bytes"
	"context"
	"crypto/ed25519"
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
	priv           ed25519.PrivateKey
	pub            ed25519.PublicKey
	client         *http.Client
	interval       time.Duration
	tracker        TrackerSource
	switcher       ProfileSource
	profileVersion uint32
	OnProfile      func(*profile.Profile)
}

func NewSender(serverURL string, priv ed25519.PrivateKey, client *http.Client, interval time.Duration, tracker TrackerSource, sw ProfileSource) *Sender {
	pub, _ := priv.Public().(ed25519.PublicKey)
	return &Sender{
		serverURL: serverURL,
		priv:      priv,
		pub:       pub,
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

// send runs the Ed25519 challenge-response against the tunnel endpoint
// and submits the telemetry report. The flow mirrors client.DialTunnel:
// send hello, read nonce from response, write signature + destination
// (Telemetry command) + version + shaping + JSON payload, then read
// back the optional profile update.
func (s *Sender) send(ctx context.Context, report Report) (*profile.Profile, error) {
	hello := transport.MarshalHello(s.pub)

	postAuthR, postAuthW := io.Pipe()
	body := io.MultiReader(bytes.NewReader(hello), postAuthR)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.serverURL, body)
	if err != nil {
		postAuthW.Close()
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/octet-stream")

	resp, err := s.client.Do(req)
	if err != nil {
		postAuthW.Close()
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	abort := func(err error) error {
		postAuthW.CloseWithError(err)
		return err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, abort(fmt.Errorf("server returned %d", resp.StatusCode))
	}

	var nonce [transport.NonceSize]byte
	if _, err := io.ReadFull(resp.Body, nonce[:]); err != nil {
		return nil, abort(fmt.Errorf("read nonce: %w", err))
	}

	sig := transport.SignChallenge(s.priv, nonce)
	if _, err := postAuthW.Write(sig); err != nil {
		return nil, abort(fmt.Errorf("write signature: %w", err))
	}

	var post bytes.Buffer
	if err := transport.WriteDest(&post, transport.Destination{Command: transport.CommandTelemetry}); err != nil {
		return nil, abort(fmt.Errorf("write destination: %w", err))
	}
	var knownVersionBuf [4]byte
	binary.BigEndian.PutUint32(knownVersionBuf[:], s.profileVersion)
	post.Write(knownVersionBuf[:])
	post.WriteByte(0) // shaping disabled — telemetry path is not relayed
	if err := json.NewEncoder(&post).Encode(report); err != nil {
		return nil, abort(fmt.Errorf("encode report: %w", err))
	}
	if _, err := postAuthW.Write(post.Bytes()); err != nil {
		return nil, abort(fmt.Errorf("write post-auth: %w", err))
	}
	// Request body is fully sent; let the server finish its response.
	postAuthW.Close()

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
	const maxProfileSize = 1 << 20
	if profSize > maxProfileSize {
		return nil, fmt.Errorf("profile size out of range: %d", profSize)
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

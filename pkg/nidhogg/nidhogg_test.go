package nidhogg

import (
	"testing"
	"time"

	"github.com/aesleif/nidhogg/internal/profile"
	"github.com/aesleif/nidhogg/internal/shaper"
)

func TestParseShapingMode(t *testing.T) {
	tests := []struct {
		input string
		want  ShapingMode
		err   bool
	}{
		{"", ShapingDisabled, false},
		{"stream", ShapingStream, false},
		{"balanced", ShapingBalanced, false},
		{"stealth", ShapingStealth, false},
		{"unknown", ShapingDisabled, true},
	}
	for _, tt := range tests {
		got, err := ParseShapingMode(tt.input)
		if (err != nil) != tt.err {
			t.Errorf("ParseShapingMode(%q) error = %v, wantErr %v", tt.input, err, tt.err)
			continue
		}
		if got != tt.want {
			t.Errorf("ParseShapingMode(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}

func TestToInternalMode(t *testing.T) {
	tests := []struct {
		pub  ShapingMode
		want shaper.ShapingMode
	}{
		{ShapingDisabled, shaper.Disabled},
		{ShapingStream, shaper.Stream},
		{ShapingBalanced, shaper.Balanced},
		{ShapingStealth, shaper.Stealth},
	}
	for _, tt := range tests {
		got := toInternalMode(tt.pub)
		if got != tt.want {
			t.Errorf("toInternalMode(%v) = %v, want %v", tt.pub, got, tt.want)
		}
	}
}

func TestToProfileInfo(t *testing.T) {
	now := time.Now()
	p := &profile.Profile{
		Name:      "test-prof",
		CreatedAt: now,
		ExpiresAt: now.Add(time.Hour),
	}
	info := toProfileInfo(p)
	if info.Name != "test-prof" {
		t.Errorf("Name = %q, want %q", info.Name, "test-prof")
	}
	if info.CreatedAt != now {
		t.Errorf("CreatedAt mismatch")
	}
	if info.ExpiresAt != now.Add(time.Hour) {
		t.Errorf("ExpiresAt mismatch")
	}
}

func TestToProfileInfoNil(t *testing.T) {
	info := toProfileInfo(nil)
	if info.Name != "" {
		t.Errorf("expected empty ProfileInfo for nil, got Name=%q", info.Name)
	}
}

func TestTunnelConnInterface(t *testing.T) {
	info := ProfileInfo{Name: "test"}
	rtt := 50 * time.Millisecond
	tc := &tunnelConn{
		profile:      info,
		handshakeRTT: rtt,
	}
	if tc.Profile().Name != "test" {
		t.Errorf("Profile().Name = %q, want %q", tc.Profile().Name, "test")
	}
	if tc.HandshakeRTT() != rtt {
		t.Errorf("HandshakeRTT() = %v, want %v", tc.HandshakeRTT(), rtt)
	}
}

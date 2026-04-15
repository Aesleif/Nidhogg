package transport

import (
	"testing"

	utls "github.com/refraction-networking/utls"
)

func TestFingerprintID_Valid(t *testing.T) {
	tests := []struct {
		name     string
		expected utls.ClientHelloID
	}{
		{"", utls.HelloRandomized},
		{"randomized", utls.HelloRandomized},
		{"chrome", utls.HelloChrome_Auto},
		{"firefox", utls.HelloFirefox_Auto},
		{"safari", utls.HelloSafari_Auto},
		{"standard", utls.ClientHelloID{}},
	}

	for _, tt := range tests {
		id, err := FingerprintID(tt.name)
		if err != nil {
			t.Errorf("FingerprintID(%q): unexpected error: %v", tt.name, err)
		}
		if id != tt.expected {
			t.Errorf("FingerprintID(%q) = %v, want %v", tt.name, id, tt.expected)
		}
	}
}

func TestFingerprintID_Invalid(t *testing.T) {
	_, err := FingerprintID("opera")
	if err == nil {
		t.Fatal("expected error for unknown fingerprint")
	}
}

package server

import (
	"bytes"
	"strings"
	"testing"
)

func TestReadAndCheckPSK_Correct(t *testing.T) {
	psk := []byte("my-secret-psk-123")
	body := bytes.NewReader([]byte("my-secret-psk-123extra-data"))

	if !ReadAndCheckPSK(body, psk) {
		t.Error("expected PSK check to pass with correct PSK")
	}
}

func TestReadAndCheckPSK_Wrong(t *testing.T) {
	psk := []byte("my-secret-psk-123")
	body := bytes.NewReader([]byte("wrong-secret-key!!extra-data"))

	if ReadAndCheckPSK(body, psk) {
		t.Error("expected PSK check to fail with wrong PSK")
	}
}

func TestReadAndCheckPSK_TooShort(t *testing.T) {
	psk := []byte("my-secret-psk-123")
	body := bytes.NewReader([]byte("short"))

	if ReadAndCheckPSK(body, psk) {
		t.Error("expected PSK check to fail with body shorter than PSK")
	}
}

func TestReadAndCheckPSK_Empty(t *testing.T) {
	psk := []byte("my-secret-psk-123")
	body := strings.NewReader("")

	if ReadAndCheckPSK(body, psk) {
		t.Error("expected PSK check to fail with empty body")
	}
}

func TestReadAndCheckPSK_ExactLength(t *testing.T) {
	psk := []byte("exact")
	body := bytes.NewReader([]byte("exact"))

	if !ReadAndCheckPSK(body, psk) {
		t.Error("expected PSK check to pass when body is exactly PSK length")
	}
}

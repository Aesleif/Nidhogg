package switcher_test

import (
	"testing"

	"github.com/aesleif/nidhogg/internal/profile"
	"github.com/aesleif/nidhogg/internal/switcher"
)

func TestSwitcherPush(t *testing.T) {
	sw := switcher.NewSwitcher(5)

	if sw.Active() != nil {
		t.Error("expected nil active initially")
	}

	p := &profile.Profile{Name: "p1"}
	sw.Push(p)

	if got := sw.Active(); got == nil || got.Name != "p1" {
		t.Errorf("Active = %v, want p1", got)
	}
	if sw.CacheLen() != 1 {
		t.Errorf("CacheLen = %d, want 1", sw.CacheLen())
	}
}

func TestSwitcherSwitch(t *testing.T) {
	sw := switcher.NewSwitcher(5)

	p1 := &profile.Profile{Name: "p1"}
	p2 := &profile.Profile{Name: "p2"}
	sw.Push(p1)
	sw.Push(p2)

	if got := sw.Active(); got.Name != "p2" {
		t.Errorf("Active = %q, want p2", got.Name)
	}

	sw.Switch()

	got := sw.Active()
	if got == nil || got.Name == "p2" {
		t.Errorf("After Switch, Active = %v, want p1", got)
	}
}

func TestSwitcherSwitchEmpty(t *testing.T) {
	sw := switcher.NewSwitcher(5)
	sw.Switch() // should not panic

	if sw.Active() != nil {
		t.Error("expected nil active after Switch on empty")
	}
}

func TestSwitcherForceProfile(t *testing.T) {
	sw := switcher.NewSwitcher(5)

	p := &profile.Profile{Name: "forced"}
	sw.ForceProfile(p)

	if got := sw.Active(); got == nil || got.Name != "forced" {
		t.Errorf("Active = %v, want forced", got)
	}
	if sw.CacheLen() != 0 {
		t.Errorf("CacheLen = %d, want 0 (ForceProfile doesn't add to cache)", sw.CacheLen())
	}
}

func TestSwitcherOnSwitch(t *testing.T) {
	sw := switcher.NewSwitcher(5)

	var calls []string
	sw.OnSwitch = func(old, new *profile.Profile) {
		oldName := "<none>"
		if old != nil {
			oldName = old.Name
		}
		calls = append(calls, oldName+"→"+new.Name)
	}

	sw.Push(&profile.Profile{Name: "a"})
	sw.Push(&profile.Profile{Name: "b"})

	if len(calls) != 2 {
		t.Fatalf("OnSwitch called %d times, want 2", len(calls))
	}
	if calls[0] != "<none>→a" {
		t.Errorf("calls[0] = %q, want <none>→a", calls[0])
	}
	if calls[1] != "a→b" {
		t.Errorf("calls[1] = %q, want a→b", calls[1])
	}
}

func TestSwitcherPushSameName(t *testing.T) {
	sw := switcher.NewSwitcher(5)

	var callCount int
	sw.OnSwitch = func(_, _ *profile.Profile) { callCount++ }

	sw.Push(&profile.Profile{Name: "same"})
	sw.Push(&profile.Profile{Name: "same"})

	if callCount != 1 {
		t.Errorf("OnSwitch called %d times, want 1 (same name skipped)", callCount)
	}
}

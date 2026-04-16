package switcher

import (
	"sync/atomic"

	"github.com/aesleif/nidhogg/internal/profile"
)

type Switcher struct {
	cache    *profile.Cache
	active   atomic.Pointer[profile.Profile]
	OnSwitch func(old, new *profile.Profile)
}

func NewSwitcher(cacheSize int) *Switcher {
	return &Switcher{
		cache: profile.NewCache(cacheSize),
	}
}

func (s *Switcher) Active() *profile.Profile {
	return s.active.Load()
}

// Push adds a profile to the cache and sets it as active.
// Calls OnSwitch if the active profile changed.
func (s *Switcher) Push(p *profile.Profile) {
	s.cache.Push(p)
	old := s.active.Swap(p)
	if old == nil || old.Name != p.Name {
		s.fireOnSwitch(old, p)
	}
}

// Switch rotates to the next profile in the cache.
func (s *Switcher) Switch() {
	next := s.cache.Next()
	if next == nil {
		return
	}
	old := s.active.Swap(next)
	if old != next {
		s.fireOnSwitch(old, next)
	}
}

// ForceProfile sets the active profile without adding to cache.
func (s *Switcher) ForceProfile(p *profile.Profile) {
	old := s.active.Swap(p)
	if old != p {
		s.fireOnSwitch(old, p)
	}
}

func (s *Switcher) CacheLen() int {
	return s.cache.Len()
}

func (s *Switcher) fireOnSwitch(old, new *profile.Profile) {
	if s.OnSwitch != nil {
		s.OnSwitch(old, new)
	}
}

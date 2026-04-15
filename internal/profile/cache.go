package profile

import "sync"

// Cache is a thread-safe LRU cache of traffic profiles.
type Cache struct {
	mu       sync.RWMutex
	profiles []*Profile
	maxSize  int
	current  int
}

// NewCache creates a cache that holds up to maxSize profiles.
func NewCache(maxSize int) *Cache {
	return &Cache{maxSize: maxSize}
}

// Current returns the active profile, or nil if the cache is empty.
func (c *Cache) Current() *Profile {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if len(c.profiles) == 0 {
		return nil
	}
	return c.profiles[c.current]
}

// Push adds a new profile to the front of the cache and makes it current.
// If the cache is full, the oldest profile is evicted.
func (c *Cache) Push(p *Profile) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.profiles = append([]*Profile{p}, c.profiles...)
	if len(c.profiles) > c.maxSize {
		c.profiles = c.profiles[:c.maxSize]
	}
	c.current = 0
}

// Next cycles to the next profile and returns it.
// Returns nil if the cache is empty.
func (c *Cache) Next() *Profile {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.profiles) == 0 {
		return nil
	}
	c.current = (c.current + 1) % len(c.profiles)
	return c.profiles[c.current]
}

// Len returns the number of cached profiles.
func (c *Cache) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.profiles)
}

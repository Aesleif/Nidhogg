package profile

import (
	"fmt"
	"testing"
)

func makeProfile(name string) *Profile {
	return &Profile{Name: name}
}

func TestCachePushAndCurrent(t *testing.T) {
	c := NewCache(5)

	c.Push(makeProfile("p1"))
	c.Push(makeProfile("p2"))
	c.Push(makeProfile("p3"))

	cur := c.Current()
	if cur == nil || cur.Name != "p3" {
		t.Errorf("Current() = %v, want p3", cur)
	}
}

func TestCacheEviction(t *testing.T) {
	c := NewCache(5)

	for i := 0; i < 6; i++ {
		c.Push(makeProfile(fmt.Sprintf("p%d", i)))
	}

	if c.Len() != 5 {
		t.Errorf("Len() = %d, want 5", c.Len())
	}

	// Current should be the last pushed
	cur := c.Current()
	if cur == nil || cur.Name != "p5" {
		t.Errorf("Current() = %v, want p5", cur)
	}
}

func TestCacheNext(t *testing.T) {
	c := NewCache(5)

	c.Push(makeProfile("p1"))
	c.Push(makeProfile("p2"))
	c.Push(makeProfile("p3"))

	// Current is p3 (index 0)
	// Next should cycle: p2, p1, p3, p2, ...
	names := []string{"p2", "p1", "p3", "p2"}
	for _, expected := range names {
		got := c.Next()
		if got == nil || got.Name != expected {
			t.Errorf("Next() = %v, want %s", got, expected)
		}
	}
}

func TestCacheEmpty(t *testing.T) {
	c := NewCache(5)

	if cur := c.Current(); cur != nil {
		t.Errorf("Current() on empty cache = %v, want nil", cur)
	}
	if next := c.Next(); next != nil {
		t.Errorf("Next() on empty cache = %v, want nil", next)
	}
}

// Copyright 2025 KeyAuthority.

package cache

import (
	"sync"
	"time"
)

type Cache struct {
	sync.RWMutex
	data      map[string]any
	expiresAt map[string]time.Time

	janitorStop chan struct{}
	janitorDone chan struct{}
}

func NewCache() *Cache {
	return &Cache{
		data:      make(map[string]any),
		expiresAt: make(map[string]time.Time),
	}
}

func (c *Cache) Get(key string) (any, bool) {
	now := time.Now()

	// Fast path: read lock only.
	c.RLock()
	exp, hasExp := c.expiresAt[key]
	if !hasExp || now.Before(exp) {
		value, exists := c.data[key]
		c.RUnlock()
		return value, exists
	}
	c.RUnlock()

	// Slow path: key appears expired, upgrade to write lock and re-check.
	c.Lock()
	defer c.Unlock()

	if exp2, ok := c.expiresAt[key]; ok && !time.Now().Before(exp2) {
		delete(c.data, key)
		delete(c.expiresAt, key)
		return nil, false
	}

	value, exists := c.data[key]
	return value, exists
}

// Snapshot returns a copy of all non-expired entries in the cache.
// Expired entries are filtered out.
func (c *Cache) Snapshot() map[string]any {
	now := time.Now()

	c.RLock()
	defer c.RUnlock()

	out := make(map[string]any, len(c.data))
	for key, value := range c.data {
		if exp, ok := c.expiresAt[key]; ok && !now.Before(exp) {
			continue
		}
		out[key] = value
	}

	return out
}

// GetOrSetFunc atomically gets a value by key or creates it by calling fn.
// If the key exists and is not expired, it is returned immediately.
// Otherwise, fn is called to produce the value, which is then cached and returned.
// If fn returns an error, nothing is cached and the error is returned.
func (c *Cache) GetOrSetFunc(key string, fn func() (any, error)) (any, error) {
	c.Lock()
	defer c.Unlock()

	// Clean up expired entry if present.
	if exp, ok := c.expiresAt[key]; ok && !time.Now().Before(exp) {
		delete(c.data, key)
		delete(c.expiresAt, key)
	}

	// Return existing value.
	if value, exists := c.data[key]; exists {
		return value, nil
	}

	// Create new value.
	value, err := fn()
	if err != nil {
		return nil, err
	}

	// Cache without TTL.
	c.data[key] = value
	delete(c.expiresAt, key)
	return value, nil
}

// Set stores a value by key without expiration.
func (c *Cache) Set(key string, value any) {
	c.Lock()
	defer c.Unlock()

	c.data[key] = value
	delete(c.expiresAt, key)
}

// SetWithTTL stores a value by key with a time-to-live duration.
// If ttl <= 0, the entry is deleted instead.
// Lazy-starts the janitor if needed.
func (c *Cache) SetWithTTL(key string, value any, ttl time.Duration) {
	c.Lock()

	if ttl <= 0 {
		delete(c.data, key)
		delete(c.expiresAt, key)
		c.Unlock()
		return
	}

	c.data[key] = value
	c.expiresAt[key] = time.Now().Add(ttl)
	needJanitor := c.janitorStop == nil
	c.Unlock()

	if needJanitor {
		c.startJanitor(10 * time.Minute)
	}
}

func (c *Cache) Delete(key string) {
	c.Lock()
	defer c.Unlock()

	delete(c.data, key)
	delete(c.expiresAt, key)
}

// Clear removes all entries and stops the janitor if running.
func (c *Cache) Clear() {
	c.Lock()
	c.data = make(map[string]any)
	c.expiresAt = make(map[string]time.Time)
	needStop := c.janitorStop != nil
	c.Unlock()

	if needStop {
		_ = c.stopJanitor()
	}
}

// PurgeExpired removes all expired entries.
// Returns the number of entries removed.
func (c *Cache) PurgeExpired() int {
	c.Lock()
	defer c.Unlock()

	return c.purgeExpiredLocked(time.Now())
}

// startJanitor starts a background goroutine that periodically cleans up expired entries.
// Returns false if a janitor is already running.
func (c *Cache) startJanitor(interval time.Duration) bool {
	if interval <= 0 {
		interval = time.Second
	}

	c.Lock()
	if c.janitorStop != nil {
		c.Unlock()
		return false
	}

	stop := make(chan struct{})
	done := make(chan struct{})
	c.janitorStop = stop
	c.janitorDone = done
	c.Unlock()

	go func() {
		defer close(done)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				c.PurgeExpired()
			case <-stop:
				return
			}
		}
	}()

	return true
}

// stopJanitor stops the background cleanup if running.
// Blocks until the janitor exits.
// Returns false if no janitor was running.
func (c *Cache) stopJanitor() bool {
	return c.stopJanitorWithTimeout(0)
}

// stopJanitorWithTimeout stops the background cleanup with an optional timeout.
// timeout <= 0 means wait indefinitely.
// Returns false if no janitor was running or if timeout elapsed before completion.
func (c *Cache) stopJanitorWithTimeout(timeout time.Duration) bool {
	c.Lock()
	if c.janitorStop == nil {
		c.Unlock()
		return false
	}

	stop := c.janitorStop
	done := c.janitorDone
	c.janitorStop = nil
	c.janitorDone = nil
	c.Unlock()

	close(stop)

	if timeout <= 0 {
		<-done
		return true
	}

	select {
	case <-done:
		return true
	case <-time.After(timeout):
		return false
	}
}

func (c *Cache) purgeExpiredLocked(now time.Time) int {
	removed := 0
	for key, exp := range c.expiresAt {
		if !now.Before(exp) {
			delete(c.data, key)
			delete(c.expiresAt, key)
			removed++
		}
	}
	return removed
}

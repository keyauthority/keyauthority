/*
Copyright 2025 KeyAuthority.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package internal

import (
	"sync"
	"time"
)

type Cache struct {
	sync.Mutex
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
	c.Lock()
	defer c.Unlock()

	if c.isExpiredLocked(key) {
		delete(c.data, key)
		delete(c.expiresAt, key)
		return nil, false
	}

	value, exists := c.data[key]
	return value, exists
}

func (c *Cache) Set(key string, value any) {
	c.Lock()
	defer c.Unlock()

	c.data[key] = value
	delete(c.expiresAt, key) // persistent entry
}

func (c *Cache) SetWithTTL(key string, value any, ttl time.Duration) {
	c.Lock()
	defer c.Unlock()

	if ttl <= 0 {
		delete(c.data, key)
		delete(c.expiresAt, key)
		return
	}

	c.data[key] = value
	c.expiresAt[key] = time.Now().Add(ttl)
}

func (c *Cache) Delete(key string) {
	c.Lock()
	defer c.Unlock()

	delete(c.data, key)
	delete(c.expiresAt, key)
}

func (c *Cache) Clear() {
	c.Lock()
	defer c.Unlock()

	c.data = make(map[string]any)
	c.expiresAt = make(map[string]time.Time)
}

func (c *Cache) PurgeExpired() int {
	c.Lock()
	defer c.Unlock()

	return c.purgeExpiredLocked(time.Now())
}

// StartJanitor starts periodic expiration cleanup.
// Returns false if a janitor is already running.
func (c *Cache) StartJanitor(interval time.Duration) bool {
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

// StopJanitor stops the background cleanup if running.
// Returns false if no janitor was running.
func (c *Cache) StopJanitor() bool {
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
	<-done
	return true
}

func (c *Cache) isExpiredLocked(key string) bool {
	exp, ok := c.expiresAt[key]
	if !ok {
		return false
	}
	return !time.Now().Before(exp)
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

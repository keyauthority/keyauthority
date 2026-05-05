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

import "sync"

type Cache struct {
	sync.Mutex
	data map[string]any
}

func NewCache(data map[string]any) Cache {
	return Cache{
		data: data,
	}
}

func (c *Cache) WithLock(operation func(data any) any) any {
	c.Lock()
	defer c.Unlock()
	return operation(c.data)
}

func (c *Cache) Get(key string) (any, bool) {
	c.Lock()
	defer c.Unlock()
	value, exists := c.data[key]
	return value, exists
}

func (c *Cache) Set(key string, value any) {
	c.Lock()
	defer c.Unlock()
	c.data[key] = value
}

func (c *Cache) Delete(key string) {
	c.Lock()
	defer c.Unlock()
	delete(c.data, key)
}

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

package acme

import (
	"time"
)

func (a *Service) cleanUpExpiredChallenges() {
	a.challengeStore.Lock()
	defer a.challengeStore.Unlock()
	for token, challenge := range a.challengeStore.challenges {
		if time.Now().After(challenge.ExpiresAt) {
			delete(a.challengeStore.challenges, token)
		}
	}
}

func (a *Service) cleanUpExpiredOrders() {
	a.orderStore.Lock()
	defer a.orderStore.Unlock()
	for id, order := range a.orderStore.orders {
		if time.Now().After(order.ExpiresAt) {
			delete(a.orderStore.orders, id)
		}
	}
}

func (a *Service) getOrder(id string) *Order {
	a.orderStore.Lock()
	order := a.orderStore.orders[id]
	a.orderStore.Unlock()
	return order
}

func (a *Service) updateOrder(order *Order, update func(*Order)) {
	a.orderStore.Lock()
	update(order)
	a.orderStore.Unlock()
}

func (a *Service) getChallenge(token string) *Challenge {
	a.challengeStore.Lock()
	challenge := a.challengeStore.challenges[token]
	a.challengeStore.Unlock()
	return challenge
}

func (a *Service) updateChallenge(challenge *Challenge, update func(*Challenge)) {
	a.challengeStore.Lock()
	update(challenge)
	a.challengeStore.Unlock()
}

func (a *Service) updateOrderStatus(order *Order) {
	unverifiedChallenges := len(order.Tokens)
	if order.Status == "pending" {
		for _, token := range order.Tokens {
			if challenge := a.getChallenge(token); challenge != nil {
				switch challenge.Status {
				case "invalid":
					a.updateOrder(order, func(o *Order) {
						o.Status = "invalid"
					})
				case "valid":
					unverifiedChallenges -= 1
					if unverifiedChallenges == 0 {
						a.updateOrder(order, func(o *Order) {
							o.Status = "ready"
							o.VerifiedDomains[challenge.Domain] = true
						})
					}
				}
			}
		}
	}
}

// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package admission

import (
	"context"

	"golang.org/x/sync/semaphore"

	"github.com/cilium/cilium/pkg/lock"
)

// admissionSlots runs at most one admission at a time per Pod UID. Admission
// revokes the endpoint's previous capture before it starts a new one, so two
// concurrent admissions of one endpoint revoke each other's capture; a caller
// waits for the slot instead. The zero value is ready to use.
type admissionSlots struct {
	mu    lock.Mutex
	slots map[string]*admissionSlot
}

type admissionSlot struct {
	sem   *semaphore.Weighted
	users int // callers holding or waiting for the slot
}

// acquire waits, within ctx, for the slot of podUID. It reports whether
// another admission held the slot when the caller arrived. The returned
// release must be called exactly once.
func (s *admissionSlots) acquire(ctx context.Context, podUID string) (release func(), contended bool, err error) {
	s.mu.Lock()
	if s.slots == nil {
		s.slots = make(map[string]*admissionSlot)
	}
	slot := s.slots[podUID]
	if slot == nil {
		slot = &admissionSlot{sem: semaphore.NewWeighted(1)}
		s.slots[podUID] = slot
	}
	slot.users++
	contended = slot.users > 1
	s.mu.Unlock()

	if err := slot.sem.Acquire(ctx, 1); err != nil {
		s.leave(podUID, slot)
		return nil, contended, err
	}
	return func() {
		slot.sem.Release(1)
		s.leave(podUID, slot)
	}, contended, nil
}

func (s *admissionSlots) leave(podUID string, slot *admissionSlot) {
	s.mu.Lock()
	defer s.mu.Unlock()
	slot.users--
	if slot.users == 0 {
		delete(s.slots, podUID)
	}
}

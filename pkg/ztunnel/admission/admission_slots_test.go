// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package admission

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/time"
)

// users reports how many callers hold or wait for podUID's slot.
func (s *admissionSlots) users(podUID string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	if slot := s.slots[podUID]; slot != nil {
		return slot.users
	}
	return 0
}

func (s *admissionSlots) size() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.slots)
}

// One holder per Pod UID; other Pod UIDs are independent; a waiter gets the
// slot when the holder releases it and learns that it was contended.
func TestAdmissionSlotsExcludePerPodUID(t *testing.T) {
	var slots admissionSlots
	release, contended, err := slots.acquire(t.Context(), "pod-a")
	require.NoError(t, err)
	require.False(t, contended)

	other, contended, err := slots.acquire(t.Context(), "pod-b")
	require.NoError(t, err)
	require.False(t, contended, "another Pod UID never waits")
	other()

	acquired := make(chan bool, 1)
	go func() {
		next, contended, err := slots.acquire(context.Background(), "pod-a")
		if err == nil {
			next()
		}
		acquired <- err == nil && contended
	}()
	require.Eventually(t, func() bool { return slots.users("pod-a") == 2 }, 5*time.Second, time.Millisecond)
	select {
	case <-acquired:
		t.Fatal("a second caller acquired a held slot")
	case <-time.After(20 * time.Millisecond):
	}
	release()
	require.True(t, <-acquired, "the waiter acquires the released slot and reports contention")
	require.Zero(t, slots.size(), "released slots are forgotten")
}

// A caller that gives up while waiting does not take the slot and leaves no
// entry behind once the holder is done.
func TestAdmissionSlotWaiterCancellation(t *testing.T) {
	var slots admissionSlots
	release, _, err := slots.acquire(t.Context(), "pod-a")
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Millisecond)
	defer cancel()
	_, contended, err := slots.acquire(ctx, "pod-a")
	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.True(t, contended)
	require.Equal(t, 1, slots.users("pod-a"), "the cancelled waiter left")
	release()
	require.Zero(t, slots.size())
}

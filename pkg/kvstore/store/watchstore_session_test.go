// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/kvstore"
)

type sessionRecorder struct {
	events     chan string
	onListDone func()
	onEnd      func(context.Context)
}

func (r *sessionRecorder) Begin(context.Context) { r.events <- "begin" }
func (r *sessionRecorder) ListDone(context.Context) {
	if r.onListDone != nil {
		r.onListDone()
	}
	r.events <- "list-done"
}
func (r *sessionRecorder) Invalid(key string, err error) {
	r.events <- "invalid:" + key + ":" + err.Error()
}
func (r *sessionRecorder) End(ctx context.Context) {
	if r.onEnd != nil {
		r.onEnd(ctx)
	}
	r.events <- "end"
}
func (r *sessionRecorder) OnUpdate(k Key)      { r.events <- "update:" + k.GetKeyName() }
func (r *sessionRecorder) OnDelete(k NamedKey) { r.events <- "delete:" + k.GetKeyName() }
func (r *sessionRecorder) expect(t *testing.T, expected string) {
	t.Helper()
	select {
	case actual := <-r.events:
		require.Equal(t, expected, actual)
	case <-time.After(timeout):
		t.Fatalf("missing watch event %q", expected)
	}
}

type rejectingSessionKey struct{ KVPair }

func (k *rejectingSessionKey) Unmarshal(key string, data []byte) error {
	if string(data) == "invalid" {
		return errors.New("invalid test record")
	}
	return k.KVPair.Unmarshal(key, data)
}

func TestWatchSessionRepeatsAndOrdersStaleDeletion(t *testing.T) {
	f, _ := GetFactory(t)
	rec := &sessionRecorder{events: make(chan string, 32)}
	legacyCalls := 0
	var s WatchStore
	rec.onListDone = func() {
		require.True(t, s.Synced(), "ListDone must observe the published snapshot")
		require.Equal(t, uint64(1), s.NumEntries())
	}
	s = f.NewWatchStore("remote-b", KVPairCreator, rec,
		RWSWithSessionObserver(rec),
		RWSWithOnSyncCallback(func(context.Context) { legacyCalls++; rec.events <- "legacy-sync" }))
	rwsRun(s, "source", func() {
		for _, e := range []string{"begin", "update:old", "list-done", "legacy-sync"} {
			rec.expect(t, e)
		}
	}, NewFakeLWBackend(t, "source/", []kvstore.KeyValueEvent{
		{Typ: kvstore.EventTypeCreate, Key: "old", Value: []byte("value")},
		{Typ: kvstore.EventTypeListDone},
	}))
	rec.expect(t, "end")
	require.False(t, s.Synced())
	rwsRun(s, "source", func() {
		for _, e := range []string{"begin", "update:new", "delete:old", "list-done"} {
			rec.expect(t, e)
		}
	}, NewFakeLWBackend(t, "source/", []kvstore.KeyValueEvent{
		{Typ: kvstore.EventTypeCreate, Key: "new", Value: []byte("value")},
		{Typ: kvstore.EventTypeListDone},
	}))
	rec.expect(t, "end")
	require.Equal(t, 1, legacyCalls, "legacy callbacks must remain one-shot")
	require.False(t, s.Synced())
	require.Empty(t, rec.events)
}

func TestWatchSessionInvalidRecordAndFreshRecovery(t *testing.T) {
	f, _ := GetFactory(t)
	rec := &sessionRecorder{events: make(chan string, 32)}
	s := f.NewWatchStore("remote-b", func() Key { return &rejectingSessionKey{} }, rec, RWSWithSessionObserver(rec))
	rwsRun(s, "source", func() {
		for _, e := range []string{"begin", "update:pod", "list-done", "invalid:pod:invalid test record", "update:pod", "delete:pod"} {
			rec.expect(t, e)
		}
	}, NewFakeLWBackend(t, "source/", []kvstore.KeyValueEvent{
		{Typ: kvstore.EventTypeCreate, Key: "pod", Value: []byte("valid")},
		{Typ: kvstore.EventTypeListDone},
		{Typ: kvstore.EventTypeModify, Key: "pod", Value: []byte("invalid")},
		{Typ: kvstore.EventTypeModify, Key: "pod", Value: []byte("corrected")},
		{Typ: kvstore.EventTypeDelete, Key: "pod"},
	}))
	rec.expect(t, "end")
	// A corrected update must not masquerade as another complete snapshot. Only
	// a new watch supplies the Begin/ListDone pair needed for strict recovery.
	rwsRun(s, "source", func() {
		for _, e := range []string{"begin", "update:pod", "list-done"} {
			rec.expect(t, e)
		}
	}, NewFakeLWBackend(t, "source/", []kvstore.KeyValueEvent{
		{Typ: kvstore.EventTypeCreate, Key: "pod", Value: []byte("corrected")},
		{Typ: kvstore.EventTypeListDone},
	}))
	rec.expect(t, "end")
	require.Empty(t, rec.events)
}

func TestWatchSessionInvalidInitialListStillNotifiesFailure(t *testing.T) {
	f, _ := GetFactory(t)
	rec := &sessionRecorder{events: make(chan string, 32)}
	s := f.NewWatchStore("remote-b", func() Key { return &rejectingSessionKey{} }, rec, RWSWithSessionObserver(rec))
	rwsRun(s, "source", func() {
		for _, e := range []string{"begin", "invalid:pod:invalid test record", "list-done"} {
			rec.expect(t, e)
		}
	}, NewFakeLWBackend(t, "source/", []kvstore.KeyValueEvent{
		{Typ: kvstore.EventTypeCreate, Key: "pod", Value: []byte("invalid")},
		{Typ: kvstore.EventTypeListDone},
	}))
	rec.expect(t, "end")
	require.Zero(t, s.NumEntries())
	require.Empty(t, rec.events)
}

type closedSessionBackend struct{}

func (closedSessionBackend) ListAndWatch(context.Context, string, ...kvstore.ListAndWatchOption) kvstore.EventChan {
	ch := make(chan kvstore.KeyValueEvent)
	close(ch)
	return ch
}

func TestWatchSessionEndsBeforeInitialList(t *testing.T) {
	for _, naturalClose := range []bool{false, true} {
		t.Run(map[bool]string{false: "cancelled", true: "backend-closed"}[naturalClose], func(t *testing.T) {
			f, _ := GetFactory(t)
			rec := &sessionRecorder{events: make(chan string, 32)}
			ended := make(chan error, 1)
			rec.onEnd = func(ctx context.Context) { ended <- ctx.Err() }
			s := f.NewWatchStore("remote-b", KVPairCreator, rec, RWSWithSessionObserver(rec))
			if naturalClose {
				s.Watch(context.Background(), closedSessionBackend{}, "source")
			} else {
				rwsRun(s, "source", func() { rec.expect(t, "begin") }, NewFakeLWBackend(t, "source/", nil))
			}
			if naturalClose {
				rec.expect(t, "begin")
			}
			rec.expect(t, "end")
			if naturalClose {
				require.NoError(t, <-ended)
			} else {
				require.ErrorIs(t, <-ended, context.Canceled)
			}
			require.False(t, s.Synced())
			require.Empty(t, rec.events, "incomplete list must not emit ListDone")
		})
	}
}

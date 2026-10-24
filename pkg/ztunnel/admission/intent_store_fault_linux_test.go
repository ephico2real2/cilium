// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package admission

import (
	"errors"
	"os"
	"testing"
)

// injectIntentIOFault overrides one real persistence boundary for a deterministic failure.
// s.ops.syncFile func(*os.File) error
// s.ops.rename func(oldName,newName string) error // captures held directory fd
// s.ops.syncDir func() error
// Constructor uses real IO before the seam is modified; each test injects one
// failing boundary into PersistRequired, not into setup or test assertions.
func injectIntentIOFault(s *IntentStore, boundary string, injected error) func() {
	switch boundary {
	case "write":
		saved := s.ops.writeFile
		s.ops.writeFile = func(*os.File, []byte) error { return injected }
		return func() { s.ops.writeFile = saved }
	case "file-sync":
		saved := s.ops.syncFile
		s.ops.syncFile = func(*os.File) error { return injected }
		return func() { s.ops.syncFile = saved }
	case "rename":
		saved := s.ops.rename
		s.ops.rename = func(string, string) error { return injected }
		return func() { s.ops.rename = saved }
	case "directory-sync":
		saved := s.ops.syncDir
		s.ops.syncDir = func() error { return injected }
		return func() { s.ops.syncDir = saved }
	default:
		panic("unsupported test IO boundary")
	}
}

func TestIntentFailureBeforeRenameDoesNotReportCommitted(t *testing.T) {
	for _, boundary := range []string{"write", "file-sync", "rename"} {
		t.Run(boundary, func(t *testing.T) {
			s, base := openTestIntentStore(t)
			old := persistTestIntent(t, s, testRequiredIdentity())
			next := testRequiredIdentity()
			next.PodUID = "second-pod"
			next.ContainerID = "second-container"
			injected := errors.New("injected " + boundary)
			undo := injectIntentIOFault(s, boundary, injected)
			if _, err := s.PersistRequired(next); !errors.Is(err, injected) {
				t.Fatalf("fault not returned to admission: %v", err)
			}
			undo()
			records, err := s.List()
			if err != nil || len(records) != 1 || records[0] != old {
				t.Fatalf("uncommitted write mutated durable state: %v %v", records, err)
			}
			s.Close()
			reopened, err := OpenIntentStore(base)
			if err != nil {
				t.Fatal(err)
			}
			defer reopened.Close()
			records, err = reopened.List()
			if err != nil || len(records) != 1 || records[0] != old {
				t.Fatalf("restart accepted failed commit: %v %v", records, err)
			}
			// Corrected retry is real recovery, not accepting an old failed attempt.
			if _, err := reopened.PersistRequired(next); err != nil {
				t.Fatal(err)
			}
			records, err = reopened.List()
			if err != nil || len(records) != 2 {
				t.Fatalf("retry did not recover: %v %v", records, err)
			}
		})
	}
}

func TestIntentDirectorySyncFailureIsIndeterminateAndPoisonsOwner(t *testing.T) {
	s, base := openTestIntentStore(t)
	injected := errors.New("injected post-rename directory fsync")
	undo := injectIntentIOFault(s, "directory-sync", injected)
	if _, err := s.PersistRequired(testRequiredIdentity()); !errors.Is(err, injected) {
		t.Fatalf("indeterminate commit reported success: %v", err)
	}
	undo() // Restoring IO does NOT clear the admission latch.
	if _, err := s.PersistRequired(testRequiredIdentity()); err == nil {
		t.Fatal("same owner retried indeterminate persistence as success")
	}
	if _, err := s.List(); err == nil {
		t.Fatal("poisoned owner supplied trusted recovery state")
	}
	s.Close()
	reopened, err := OpenIntentStore(base)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	records, err := reopened.List()
	if err != nil {
		t.Fatal(err)
	}
	// A normal process close/reopen is not simulated power loss; Rename happened,
	// so this local test expects the file. Real crash testing separately allows
	// either old or new complete state, never partial or Ready/ACK state.
	if len(records) != 1 || records[0].RequiredIdentity != testRequiredIdentity() {
		t.Fatalf("post-rename intent lost: %v", records)
	}
}

func TestIntentFileSyncFailurePreservesOriginalWhenRetryingSamePod(t *testing.T) {
	s, _ := openTestIntentStore(t)
	old := persistTestIntent(t, s, testRequiredIdentity())
	// A persisted exact sandbox is read-only/idempotent; a new injected write
	// error must not silently mint a new incarnation or rewrite the record.
	injected := errors.New("writes disabled")
	undo := injectIntentIOFault(s, "file-sync", injected)
	defer undo()
	got, err := s.PersistRequired(testRequiredIdentity())
	if err != nil || got != old {
		t.Fatalf("exact retry mutated durable incarnation: %v %v", got, err)
	}
}

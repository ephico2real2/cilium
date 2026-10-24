// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package admission

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func testRequiredIdentity() RequiredIdentity {
	return RequiredIdentity{ClusterID: 17, NodeName: "node-a", Namespace: "orders", NamespaceUID: "namespace-incarnation-a", PodName: "api", PodUID: "pod-incarnation-a", ServiceAccount: "api", EndpointID: 42, ContainerID: "cri-sandbox-a", NetnsPath: "/var/run/netns/sandbox-a", NetnsDevice: 4, NetnsInode: 12345, NetnsCookie: 98765}
}
func openTestIntentStore(t *testing.T) (*IntentStore, string) {
	t.Helper()
	base := t.TempDir()
	s, err := OpenIntentStore(base)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s, base
}
func persistTestIntent(t *testing.T, s *IntentStore, i RequiredIdentity) RequiredIntent {
	t.Helper()
	r, err := s.PersistRequired(i)
	if err != nil {
		t.Fatal(err)
	}
	return r
}
func intentFiles(t *testing.T, base string) []string {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(base, "ztunnel-required"))
	if err != nil {
		t.Fatal(err)
	}
	var paths []string
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".json") {
			paths = append(paths, filepath.Join(base, "ztunnel-required", e.Name()))
		}
	}
	return paths
}
func singleIntentFile(t *testing.T, base string) string {
	t.Helper()
	p := intentFiles(t, base)
	if len(p) != 1 {
		t.Fatalf("want one intent file, have %v", p)
	}
	return p[0]
}

func TestIntentPersistIsIdempotentAndSurvivesReopen(t *testing.T) {
	s, base := openTestIntentStore(t)
	identity := testRequiredIdentity()
	want := persistTestIntent(t, s, identity)
	again := persistTestIntent(t, s, identity)
	if again != want {
		t.Fatalf("same sandbox got different durable token: %v != %v", again, want)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenIntentStore(base)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	records, err := reopened.List()
	if err != nil || len(records) != 1 || records[0] != want {
		t.Fatalf("recovery=%v err=%v", records, err)
	}
	if got := persistTestIntent(t, reopened, identity); got != want {
		t.Fatalf("restart changed durable intent: %v", got)
	}
}

func TestIntentContainsOnlyIntentAndSandboxBinding(t *testing.T) {
	s, base := openTestIntentStore(t)
	persistTestIntent(t, s, testRequiredIdentity())
	raw, err := os.ReadFile(singleIntentFile(t, base))
	if err != nil {
		t.Fatal(err)
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(raw, &object); err != nil {
		t.Fatal(err)
	}
	allowed := map[string]bool{}
	for _, key := range []string{"schemaVersion", "clusterID", "nodeName", "namespace", "namespaceUID", "podName", "podUID", "serviceAccount", "endpointID", "containerID", "netnsPath", "netnsDevice", "netnsInode", "netnsCookie", "incarnation"} {
		allowed[key] = true
	}
	if len(object) != len(allowed) {
		t.Fatalf("serialized contract changed: %s", raw)
	}
	for key := range object {
		if !allowed[key] {
			t.Fatalf("unexpected persisted evidence field %q: %s", key, raw)
		}
	}
	// This strict allowlist excludes old/new aliases for ALL capture, readiness,
	// certificate, ZDS/ADS generation/ACK and policy evidence, including epoch.
}

func TestIntentSamePodCannotInheritChangedSandbox(t *testing.T) {
	mutations := map[string]func(*RequiredIdentity){
		"endpoint":        func(i *RequiredIdentity) { i.EndpointID++ },
		"container":       func(i *RequiredIdentity) { i.ContainerID = "cri-sandbox-b" },
		"netns-path":      func(i *RequiredIdentity) { i.NetnsPath += "-b" },
		"netns-device":    func(i *RequiredIdentity) { i.NetnsDevice++ },
		"netns-inode":     func(i *RequiredIdentity) { i.NetnsInode++ },
		"netns-cookie":    func(i *RequiredIdentity) { i.NetnsCookie++ },
		"service-account": func(i *RequiredIdentity) { i.ServiceAccount = "other" },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			s, _ := openTestIntentStore(t)
			original := testRequiredIdentity()
			old := persistTestIntent(t, s, original)
			next := original
			mutate(&next)
			if _, err := s.PersistRequired(next); err == nil {
				t.Fatal("sandbox replacement inherited Required intent")
			}
			records, err := s.List()
			if err != nil || len(records) != 1 || records[0] != old {
				t.Fatalf("replacement damaged old intent: %v err=%v", records, err)
			}
		})
	}
}

func TestIntentNameReuseCreatesIndependentRequiredRecords(t *testing.T) {
	s, _ := openTestIntentStore(t)
	a := testRequiredIdentity()
	old := persistTestIntent(t, s, a)
	b := a
	b.NamespaceUID = "namespace-incarnation-b"
	b.PodUID = "pod-incarnation-b"
	b.ContainerID = "cri-b"
	b.NetnsInode++
	b.NetnsCookie++
	fresh := persistTestIntent(t, s, b)
	if fresh.Incarnation == old.Incarnation {
		t.Fatal("new namespace/Pod reused durable incarnation")
	}
	records, err := s.List()
	if err != nil || len(records) != 2 {
		t.Fatalf("lost retained old Required intent: %v %v", records, err)
	}
	// Same names are not authoritative. Recovery must retain/fence old record
	// and validate both immutable UIDs before considering the fresh one.
}

func TestIntentInvalidIdentityNeverWrites(t *testing.T) {
	mutations := map[string]func(*RequiredIdentity){
		"missing-namespace-uid":   func(i *RequiredIdentity) { i.NamespaceUID = "" },
		"missing-pod-uid":         func(i *RequiredIdentity) { i.PodUID = "" },
		"missing-node":            func(i *RequiredIdentity) { i.NodeName = "" },
		"missing-service-account": func(i *RequiredIdentity) { i.ServiceAccount = "" },
		"missing-container":       func(i *RequiredIdentity) { i.ContainerID = "" },
		"zero-endpoint":           func(i *RequiredIdentity) { i.EndpointID = 0 },
		"zero-inode":              func(i *RequiredIdentity) { i.NetnsInode = 0 },
		"zero-cookie":             func(i *RequiredIdentity) { i.NetnsCookie = 0 },
		"relative-netns":          func(i *RequiredIdentity) { i.NetnsPath = "relative/path" },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			s, base := openTestIntentStore(t)
			i := testRequiredIdentity()
			mutate(&i)
			if _, err := s.PersistRequired(i); err == nil {
				t.Fatal("invalid identity accepted")
			}
			if p := intentFiles(t, base); len(p) != 0 {
				t.Fatalf("invalid intent written: %v", p)
			}
		})
	}
}

func TestIntentConcurrentIdempotentWriters(t *testing.T) {
	s, base := openTestIntentStore(t)
	const count = 32
	records := make(chan RequiredIntent, count)
	failures := make(chan error, count)
	var writers sync.WaitGroup
	for range count {
		writers.Go(func() {
			r, err := s.PersistRequired(testRequiredIdentity())
			if err != nil {
				failures <- err
			} else {
				records <- r
			}
		})
	}
	writers.Wait()
	close(records)
	close(failures)
	for err := range failures {
		t.Error(err)
	}
	var want RequiredIntent
	for r := range records {
		if want.Incarnation == "" {
			want = r
		}
		if r != want {
			t.Errorf("concurrent writes minted different intents")
		}
	}
	if len(intentFiles(t, base)) != 1 {
		t.Fatal("concurrent writes created duplicate durable records")
	}
}

func TestIntentExclusiveOwnerAndClosedState(t *testing.T) {
	s, base := openTestIntentStore(t)
	second, err := OpenIntentStore(base)
	if err == nil {
		second.Close()
		t.Fatal("two active owners acquired journal")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close not idempotent: %v", err)
	}
	if _, err := s.List(); err == nil {
		t.Fatal("closed store listed intents")
	}
	if _, err := s.PersistRequired(testRequiredIdentity()); err == nil {
		t.Fatal("closed store wrote intent")
	}
	next, err := OpenIntentStore(base)
	if err != nil {
		t.Fatal(err)
	}
	next.Close()
}

func TestIntentCorruptAndUnsupportedRecordsBlockRecovery(t *testing.T) {
	cases := map[string]func([]byte) []byte{
		"truncated":     func(raw []byte) []byte { return raw[:len(raw)/2] },
		"trailing-json": func(raw []byte) []byte { return append(raw, []byte(" {}")...) },
		"unknown-ack-field": func(raw []byte) []byte {
			var m map[string]any
			json.Unmarshal(raw, &m)
			m["zdsAcked"] = true
			b, _ := json.Marshal(m)
			return b
		},
		"schema": func(raw []byte) []byte {
			var m map[string]any
			json.Unmarshal(raw, &m)
			m["schemaVersion"] = 2
			b, _ := json.Marshal(m)
			return b
		},
		"invalid-incarnation": func(raw []byte) []byte {
			var m map[string]any
			json.Unmarshal(raw, &m)
			m["incarnation"] = "not-an-incarnation"
			b, _ := json.Marshal(m)
			return b
		},
	}
	for name, damage := range cases {
		t.Run(name, func(t *testing.T) {
			s, base := openTestIntentStore(t)
			persistTestIntent(t, s, testRequiredIdentity())
			p := singleIntentFile(t, base)
			raw, err := os.ReadFile(p)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(p, damage(raw), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := s.List(); err == nil {
				t.Fatal("corrupt record became empty or trusted state")
			}
			if _, err := s.PersistRequired(testRequiredIdentity()); err == nil {
				t.Fatal("corrupt Required record overwritten")
			}
		})
	}
}

func TestIntentUnsafeRecordFilesAreRejected(t *testing.T) {
	for _, kind := range []string{"symlink", "hardlink", "world-readable"} {
		t.Run(kind, func(t *testing.T) {
			s, base := openTestIntentStore(t)
			persistTestIntent(t, s, testRequiredIdentity())
			p := singleIntentFile(t, base)
			switch kind {
			case "symlink":
				external := filepath.Join(t.TempDir(), "outside.json")
				raw, err := os.ReadFile(p)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(external, raw, 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.Remove(p); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(external, p); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := os.Link(p, filepath.Join(t.TempDir(), "alias.json")); err != nil {
					t.Fatal(err)
				}
			case "world-readable":
				if err := os.Chmod(p, 0644); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := s.List(); err == nil {
				t.Fatal("unsafe record was accepted")
			}
			if _, err := s.PersistRequired(testRequiredIdentity()); err == nil {
				t.Fatal("unsafe record reused")
			}
		})
	}
}

func TestIntentJournalDirectoryMustBePrivateAndNotSymlink(t *testing.T) {
	for _, kind := range []string{"symlink", "world-writable"} {
		t.Run(kind, func(t *testing.T) {
			base := t.TempDir()
			p := filepath.Join(base, "ztunnel-required")
			if kind == "symlink" {
				if err := os.Symlink(t.TempDir(), p); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := os.Mkdir(p, 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(p, 0777); err != nil {
					t.Fatal(err)
				}
			}
			store, err := OpenIntentStore(base)
			if err == nil {
				store.Close()
				t.Fatal("unsafe journal directory accepted")
			}
		})
	}
}

func TestIntentHeldDirectoryCannotBeRedirectedByPathReplacement(t *testing.T) {
	s, base := openTestIntentStore(t)
	persistTestIntent(t, s, testRequiredIdentity())
	path := filepath.Join(base, "ztunnel-required")
	held := filepath.Join(base, "old-journal")
	if err := os.Rename(path, held); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	fresh := testRequiredIdentity()
	fresh.PodUID = "new-pod"
	fresh.ContainerID = "new-container"
	fresh.NetnsCookie++
	fresh.NetnsInode++
	if _, err := s.PersistRequired(fresh); err == nil {
		t.Fatal("a replaced journal path did not invalidate its owner")
	}
	if _, err := s.List(); err == nil {
		t.Fatal("invalidated owner returned a trusted recovery snapshot")
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("write escaped held journal into replacement: %v", entries)
	}
}

func TestIntentCrashBeforeRenameDoesNotAdoptTemporaryRecord(t *testing.T) {
	s, base := openTestIntentStore(t)
	old := persistTestIntent(t, s, testRequiredIdentity())
	p := singleIntentFile(t, base)
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	// A complete-looking leftover is still uncommitted; it cannot become a
	// second Required record merely because a previous process crashed.
	if err := os.WriteFile(filepath.Join(base, "ztunnel-required", ".intent-crashed"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	s.Close()
	next, err := OpenIntentStore(base)
	if err != nil {
		t.Fatal(err)
	}
	defer next.Close()
	records, err := next.List()
	if err != nil || len(records) != 1 || records[0] != old {
		t.Fatalf("temporary file was promoted or valid intent lost: %v %v", records, err)
	}
}

func TestIntentFilenameBindingAndSizeBound(t *testing.T) {
	for _, kind := range []string{"renamed-record", "oversized-record"} {
		t.Run(kind, func(t *testing.T) {
			s, base := openTestIntentStore(t)
			persistTestIntent(t, s, testRequiredIdentity())
			p := singleIntentFile(t, base)
			switch kind {
			case "renamed-record":
				if err := os.Rename(p, filepath.Join(filepath.Dir(p), strings.Repeat("0", 64)+".json")); err != nil {
					t.Fatal(err)
				}
			case "oversized-record":
				if err := os.WriteFile(p, []byte(strings.Repeat(" ", 128*1024)), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := s.List(); err == nil {
				t.Fatal("unbound or oversized recovery record accepted")
			}
		})
	}
}

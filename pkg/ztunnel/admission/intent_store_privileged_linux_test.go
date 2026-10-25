// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package admission

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/cilium/cilium/pkg/testutils"
)

// A live sandbox with the recorded cookie is not gone; the same path with a
// different cookie (a namespace recreated at that path) is.
func TestPrivilegedIntentRecordedSandboxGoneComparesNetnsCookie(t *testing.T) {
	testutils.PrivilegedTest(t)
	s, _ := openTestIntentStore(t)
	live, err := pinSandbox("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	cookie := live.cookie
	live.ns.Close()
	alive := RequiredIntent{BootID: s.bootID, RequiredIdentity: RequiredIdentity{NetnsPath: "/proc/self/ns/net", NetnsCookie: cookie}}
	if gone, err := s.recordedSandboxGone(alive); err != nil || gone {
		t.Fatalf("a live recorded sandbox was treated as gone: gone=%v err=%v", gone, err)
	}
	replaced := alive
	replaced.NetnsCookie = cookie + 1
	if gone, err := s.recordedSandboxGone(replaced); err != nil || !gone {
		t.Fatalf("a namespace with another cookie was not proven to replace the record: gone=%v err=%v", gone, err)
	}
}

func TestPrivilegedIntentForeignOwnershipIsRejected(t *testing.T) {
	testutils.PrivilegedTest(t)
	// Run the qualifying suite in the existing ROOT Podman builder with
	// PRIVILEGED_TESTS=1. A skip is not evidence for this acceptance condition.
	if os.Geteuid() != 0 {
		t.Fatal("foreign-owner test requires root in disposable builder")
	}
	const foreignUID = 65534
	for _, which := range []string{"journal-directory", "record-file", "owner-file"} {
		t.Run(which, func(t *testing.T) {
			s, base := openTestIntentStore(t)
			persistTestIntent(t, s, testRequiredIdentity())
			switch which {
			case "journal-directory":
				s.Close()
				p := filepath.Join(base, "ztunnel-required")
				if err := os.Chown(p, foreignUID, -1); err != nil {
					t.Fatal(err)
				}
				defer os.Chown(p, 0, -1)
				next, err := OpenIntentStore(base)
				if err == nil {
					next.Close()
					t.Fatal("foreign-owned directory accepted")
				}
			case "record-file":
				p := singleIntentFile(t, base)
				if err := os.Chown(p, foreignUID, -1); err != nil {
					t.Fatal(err)
				}
				defer os.Chown(p, 0, -1)
				if _, err := s.List(); err == nil {
					t.Fatal("foreign-owned Required intent accepted")
				}
				if _, err := s.PersistRequired(testRequiredIdentity()); err == nil {
					t.Fatal("foreign-owned intent reused")
				}
			case "owner-file":
				s.Close()
				p := filepath.Join(base, "ztunnel-required", ".owner")
				if err := os.Chown(p, foreignUID, -1); err != nil {
					t.Fatal(err)
				}
				defer os.Chown(p, 0, -1)
				next, err := OpenIntentStore(base)
				if err == nil {
					next.Close()
					t.Fatal("foreign-owned owner lock accepted")
				}
			}
		})
	}
}

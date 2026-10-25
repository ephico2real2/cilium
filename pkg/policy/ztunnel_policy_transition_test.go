// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium
package policy

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	policyTypes "github.com/cilium/cilium/pkg/policy/types"
)

func TestNativePolicyGuardCannotConsumePendingChangesBeforeDrain(t *testing.T) {
	key := EgressKey().WithIdentity(1<<16 | 900).WithTCPPort(8080)
	p := ztunnelTestPolicy(t, map[Key]MapStateEntry{key: policyTypes.AllowEntry()})
	// Actual native incremental queue; not a copied wire or synthetic proof bit.
	p.policyMapChanges.synced = []mapChange{{Add: false, Key: key}}
	require.True(t, p.HasPendingZtunnelMapChanges())
	before := p.Len()
	blocked := errors.New("drain incomplete")
	calls := 0
	closeSnapshot, _, err := p.ConsumeMapChangesGuarded(func() error { calls++; return blocked })
	require.ErrorIs(t, err, blocked)
	require.Nil(t, closeSnapshot)
	require.Equal(t, 1, calls)
	require.Equal(t, before, p.Len())
	require.Len(t, p.policyMapChanges.synced, 1)
	require.True(t, p.HasPendingZtunnelMapChanges())
	closeSnapshot, changes, err := p.ConsumeMapChangesGuarded(func() error { calls++; return nil })
	require.NoError(t, err)
	defer closeSnapshot()
	require.Equal(t, 2, calls)
	require.NotEmpty(t, changes.Deletes)
	require.False(t, p.HasPendingZtunnelMapChanges())
	_, exists := p.Get(key)
	require.False(t, exists)
}
func TestNativePolicyGuardAlsoFencesUnSyncedChanges(t *testing.T) {
	p := ztunnelTestPolicy(t, nil)
	p.policyMapChanges.changes = []mapChange{{}}
	_, _, err := p.ConsumeMapChangesGuarded(func() error { return errors.New("closed") })
	require.ErrorContains(t, err, "closed")
	require.Len(t, p.policyMapChanges.changes, 1)
}
func TestNativePolicyGuardPreservesUnchangedLegacyPath(t *testing.T) {
	p := ztunnelTestPolicy(t, nil)
	calls := 0
	closer, _, err := p.ConsumeMapChangesGuarded(func() error { calls++; return errors.New("must not run") })
	require.NoError(t, err)
	defer closer()
	require.Zero(t, calls)
	closer, _ = p.ConsumeMapChanges()
	closer()
}

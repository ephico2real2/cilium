// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policymap

import (
	"log/slog"
	"os"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/policy/trafficdirection"
	policyTypes "github.com/cilium/cilium/pkg/policy/types"
	"github.com/cilium/cilium/pkg/testutils"
	"github.com/cilium/cilium/pkg/u8proto"
)

const (
	testMapSize = 1024
)

func createStatsMapForTest(maxStatsEntries int) (*StatsMap, error) {
	m, _ := newStatsMap(maxStatsEntries, slog.Default())
	return m, m.OpenOrCreate()
}

func setupPolicyMapPrivilegedTestSuite(tb testing.TB) PolicyMap {
	testutils.PrivilegedTest(tb)

	logger := hivetest.Logger(tb)
	bpf.CheckOrMountFS(logger, "")

	if err := rlimit.RemoveMemlock(); err != nil {
		tb.Fatal(err)
	}

	stats, err := createStatsMapForTest(testMapSize)
	require.NoError(tb, err)
	require.NotNil(tb, stats)

	testMap, err := newPolicyMap(logger, 0, testMapSize, stats)
	require.NoError(tb, err)
	require.NotNil(tb, testMap)

	_ = os.RemoveAll(bpf.LocalMapPath(logger, MapName, 0))
	err = testMap.CreateUnpinned()
	require.NoError(tb, err)

	tb.Cleanup(func() {
		err := testMap.DeleteAll()
		require.NoError(tb, err)
	})

	return testMap
}

func TestPrivilegedPolicyMapDumpToSlice(t *testing.T) {
	testMap := setupPolicyMapPrivilegedTestSuite(t)

	fooKey := newKey(1, 1, 1, 1, SinglePortPrefixLen)
	entry := newAllowEntry(fooKey, 42, 0)
	err := testMap.Update(&fooKey, &entry)
	require.NoError(t, err)

	dump, err := testMap.DumpToSlice()
	require.NoError(t, err)
	require.Len(t, dump, 1)

	require.Equal(t, fooKey, dump[0].Key)

	require.Equal(t, policyTypes.Precedence(42), dump[0].PolicyEntry.Precedence)

	// Special case: allow-all entry
	barKey := newKey(0, 0, 0, 0, 0)
	barEntry := newAllowEntry(barKey, 0, 0)
	err = testMap.Update(&barKey, &barEntry)
	require.NoError(t, err)

	dump, err = testMap.DumpToSlice()
	require.NoError(t, err)
	require.Len(t, dump, 2)
}

func TestPrivilegedPolicyMapKernelIDReturnsLiveKernelID(t *testing.T) {
	testMap := setupPolicyMapPrivilegedTestSuite(t)
	got, err := testMap.KernelMapID()
	require.NoError(t, err)
	require.NotZero(t, got)

	concrete, ok := testMap.(*policyMap)
	require.True(t, ok)
	fd, err := unix.Dup(concrete.FD())
	require.NoError(t, err)
	mapFromFD, err := ebpf.NewMapFromFD(fd)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, mapFromFD.Close()) })
	info, err := mapFromFD.Info()
	require.NoError(t, err)
	want, ok := info.ID()
	require.True(t, ok)
	require.Equal(t, uint32(want), got)
}

func TestPrivilegedDeleteNonexistentKey(t *testing.T) {
	testMap := setupPolicyMapPrivilegedTestSuite(t)
	key := newKey(trafficdirection.Ingress, 27, u8proto.TCP, 80, SinglePortPrefixLen)
	err := testMap.DeleteKey(key)
	require.Error(t, err)
	var errno unix.Errno
	require.ErrorAs(t, err, &errno)
	require.Equal(t, unix.ENOENT, errno)
}

func TestPrivilegedDenyPolicyMapDumpToSlice(t *testing.T) {
	testMap := setupPolicyMapPrivilegedTestSuite(t)

	fooKey := newKey(1, 1, 1, 1, SinglePortPrefixLen)
	fooEntry := newDenyEntry(fooKey, 321)
	err := testMap.Update(&fooKey, &fooEntry)
	require.NoError(t, err)

	dump, err := testMap.DumpToSlice()
	require.NoError(t, err)
	require.Len(t, dump, 1)

	require.Equal(t, fooKey, dump[0].Key)
	require.Equal(t, fooEntry, dump[0].PolicyEntry)

	// Special case: deny-all entry
	barKey := newKey(0, 0, 0, 0, 0)
	barEntry := newDenyEntry(barKey, 0)
	err = testMap.Update(&barKey, &barEntry)
	require.NoError(t, err)

	dump, err = testMap.DumpToSlice()
	require.NoError(t, err)
	require.Len(t, dump, 2)
}

// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package resolver

import (
	"fmt"
	"strconv"

	"github.com/cilium/cilium/pkg/bpf"
	datapathmaps "github.com/cilium/cilium/pkg/datapath/maps"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/maps/registry"
)

const (
	// MapName is the pinned datapath map of approved DNS resolver identities
	// (cilium_ztunnel_dns_resolvers in bpf/lib/ztunnel_admission.h).
	MapName = datapathmaps.CiliumZtunnelDnsResolvers

	// approved is ZTUNNEL_DNS_RESOLVER_APPROVED; the datapath accepts no other value.
	approved = resolverValue(1)
)

// resolverKey is a security identity. Must match the map's __u32 key.
type resolverKey uint32

func (k *resolverKey) String() string  { return strconv.FormatUint(uint64(*k), 10) }
func (k *resolverKey) New() bpf.MapKey { return new(resolverKey) }

// resolverValue must match the map's __u8 value.
type resolverValue uint8

func (v *resolverValue) String() string    { return strconv.FormatUint(uint64(*v), 10) }
func (v *resolverValue) New() bpf.MapValue { return new(resolverValue) }

// resolverMap is the approved set as the datapath sees it.
type resolverMap interface {
	// List returns every identity in the map; true when its value approves
	// it (any other value approves nothing in the datapath).
	List() (map[identity.NumericIdentity]bool, error)
	Approve(identity.NumericIdentity) error
	Withdraw(identity.NumericIdentity) error
	Close() error
}

type pinnedMap struct {
	m *bpf.Map
}

// openMap opens or creates the pinned map with the datapath's compile-time
// spec, so the loader and the agent always share one map.
func openMap(reg *registry.MapRegistry) (resolverMap, error) {
	var key resolverKey
	var value resolverValue
	m, err := bpf.NewMapFromRegistry(reg, MapName, &key, &value)
	if err != nil {
		return nil, fmt.Errorf("%s spec: %w", MapName, err)
	}
	if err := m.OpenOrCreate(); err != nil {
		return nil, fmt.Errorf("open or create %s: %w", MapName, err)
	}
	return &pinnedMap{m: m}, nil
}

func (p *pinnedMap) List() (map[identity.NumericIdentity]bool, error) {
	ids := make(map[identity.NumericIdentity]bool)
	err := p.m.DumpWithCallback(func(k bpf.MapKey, v bpf.MapValue) {
		ids[identity.NumericIdentity(*k.(*resolverKey))] = *v.(*resolverValue) == approved
	})
	if err != nil {
		return nil, fmt.Errorf("dump %s: %w", MapName, err)
	}
	return ids, nil
}

func (p *pinnedMap) Approve(id identity.NumericIdentity) error {
	key, value := resolverKey(id.Uint32()), approved
	return p.m.Update(&key, &value)
}

func (p *pinnedMap) Withdraw(id identity.NumericIdentity) error {
	key := resolverKey(id.Uint32())
	return p.m.Delete(&key)
}

func (p *pinnedMap) Close() error { return p.m.Close() }

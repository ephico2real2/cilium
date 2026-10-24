// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package admission

import (
	"fmt"

	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/netns"
)

func validateNetworkNamespace(path string) error {
	ns, err := netns.OpenPinned(path)
	if err != nil {
		return err
	}
	defer ns.Close()
	kind, err := unix.IoctlRetInt(ns.FD(), unix.NS_GET_NSTYPE)
	if err != nil {
		return fmt.Errorf("checking namespace type: %w", err)
	}
	if kind != unix.CLONE_NEWNET {
		return fmt.Errorf("namespace type %d is not network", kind)
	}
	return nil
}

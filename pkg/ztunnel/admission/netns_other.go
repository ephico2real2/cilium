// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !linux

package admission

import "errors"

func validateNetworkNamespace(string) error {
	return errors.New("ztunnel network namespace admission requires Linux")
}

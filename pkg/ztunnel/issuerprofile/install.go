// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package issuerprofile

// ValidateInstall checks administrator-supplied bindings before an ADS probe
// starts. It does not read the API, persist floors, or activate a provider.
func ValidateInstall(e Install) error { return e.validate() }

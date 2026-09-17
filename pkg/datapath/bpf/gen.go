// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Package bpf provides Go skeletons containing BPF programs.
package bpf

//go:generate go tool bpfgen SockTerm ../../../bpf/bpf_sock_term.c
//go:generate go tool bpfgen Probes ../../../bpf/bpf_probes.c

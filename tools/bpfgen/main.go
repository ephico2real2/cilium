// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

var (
	ciliumRoot   string
	objCacheRoot string
)

func main() {
	flag.StringVar(&ciliumRoot, "cilium-root", os.Getenv("BPFGEN_CILIUM_ROOT"), "Absolute path to Cilium root directory")
	flag.StringVar(&objCacheRoot, "obj-cache-root", os.Getenv("BPFGEN_OBJ_CACHE_ROOT"), "Absolute path to object file cache root directory")
	flag.Parse()

	if err := run(flag.Args()); err != nil {
		fmt.Fprintf(os.Stderr, "bpfgen: %v\n", err)
		os.Exit(1)
	}
}

func run(bpf2goArgs []string) error {
	cwd, err := os.Getwd()
	if err != nil {
		return err
	}

	tmpDir, err := os.MkdirTemp("", "bpfgen-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmpDir)

	args := append([]string{"tool", "github.com/cilium/ebpf/cmd/bpf2go", "-output-dir", tmpDir}, bpf2goArgs...)
	cmd := exec.Command("go", args...)
	cmd.Env = append(cmd.Env, os.Environ()...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return err
	}

	entries, err := os.ReadDir(tmpDir)
	if err != nil {
		return err
	}

	for _, entry := range entries {
		data, err := os.ReadFile(filepath.Join(tmpDir, entry.Name()))
		if err != nil {
			return err
		}

		dstPath := filepath.Join(cwd, entry.Name())
		if err := os.WriteFile(dstPath, data, 0644); err != nil {
			return err
		}

		if filepath.Ext(entry.Name()) == ".o" && objCacheRoot != "" {
			relPath, err := filepath.Rel(ciliumRoot, dstPath)
			if err != nil {
				return err
			}
			cacheDst := filepath.Join(objCacheRoot, relPath)
			if err := os.MkdirAll(filepath.Dir(cacheDst), 0755); err != nil {
				return err
			}
			if err := os.WriteFile(cacheDst, data, 0644); err != nil {
				return err
			}
		}
	}

	return nil
}

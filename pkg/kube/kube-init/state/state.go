// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package state provides marker-file primitives and well-known path
// constants shared across the kube-init packages.
//
// "Markers" are idempotent on-disk files that record one-shot
// initialization outcomes (e.g. a particular component is installed)
// so kube-init can pick up where it left off across daemon restarts
// without re-doing work. Marker paths are chosen by the package that
// owns the corresponding initialization step; this package does not
// hold a registry of them.
//
// This package is deliberately small. It owns nothing higher-level
// than file existence + atomic file writes. Component-specific marker
// path constants and the FSM/orchestration logic live in the packages
// that introduce them.
package state

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// ContainerdSocket is the path to the CRI socket of the user containerd
// the kube linuxkit container runs. k3s is configured to use this
// containerd as its kubelet runtime endpoint, so direct tools (ctr,
// crictl) and kubelet share a single content store and namespace.
const ContainerdSocket = "/run/containerd-user/containerd.sock"

// K3sKubeconfig is the path to the cluster admin kubeconfig that k3s
// writes after the API server is reachable. Consumers should invoke
// kubectlx.Run / Cmd (which inject this via KUBECONFIG) rather than
// referencing this path directly.
const K3sKubeconfig = "/etc/rancher/k3s/k3s.yaml"

// Marker is a typed filesystem path that identifies a kube-init
// progress marker. Using a named string type instead of a bare
// `string` makes "this is a marker path, not any old filesystem path"
// obvious at every call site, and lets go vet flag accidental mixing
// with plain `string` values from elsewhere. Untyped string literals
// still convert implicitly so component packages can define
// `const SomeFlag Marker = "/var/lib/something"` without ceremony.
type Marker string

// IsMarked reports whether the given marker file is present.
//
// Returns (true, nil) when the marker exists, (false, nil) when it
// does not, and (false, err) for any other os.Stat failure (e.g. EIO
// on a wedged filesystem, EACCES on a permission regression). Real
// stat errors are intentionally NOT collapsed into "not present" —
// silently re-running supposedly-completed init steps because /persist
// is wedged is a serious anti-pattern; callers should treat the error
// path as a hard failure rather than a missing marker.
func IsMarked(m Marker) (bool, error) {
	_, err := os.Stat(string(m))
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, os.ErrNotExist):
		return false, nil
	default:
		return false, fmt.Errorf("stat marker %s: %w", m, err)
	}
}

// Mark writes the marker file with the conventional content "1" using
// AtomicWriteFile so concurrent readers never observe a partial body.
// Readers should still test marker presence with IsMarked rather than
// reading the body; the content is incidental.
//
// Mark is idempotent: re-marking an already-marked path overwrites
// with the same value, leaving the marker present.
func Mark(m Marker) error {
	if err := AtomicWriteFile(string(m), []byte("1"), 0644); err != nil {
		return fmt.Errorf("mark %s: %w", m, err)
	}
	return nil
}

// Unmark removes the marker file. Returns nil if the marker does not
// exist (idempotent).
func Unmark(m Marker) error {
	err := os.Remove(string(m))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("unmark %s: %w", m, err)
	}
	return nil
}

// AtomicWriteFile writes data to a temporary file in the same directory
// as path and then renames it into place, so concurrent readers never
// observe a partially-written file. The parent directory is created
// if it does not already exist.
//
// Durability semantics: the temp file is fsync'd before close and the
// parent directory is fsync'd after rename. After this function
// returns, the new content is durable across power loss; on crash
// during the call, the target path either contains the old content
// or the new content, never partial new content.
func AtomicWriteFile(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("mkdir %s: %w", dir, err)
	}

	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return fmt.Errorf("create temp file in %s: %w", dir, err)
	}
	tmpName := tmp.Name()

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return fmt.Errorf("write temp file %s: %w", tmpName, err)
	}
	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return fmt.Errorf("chmod temp file %s: %w", tmpName, err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return fmt.Errorf("sync temp file %s: %w", tmpName, err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("close temp file %s: %w", tmpName, err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("rename %s -> %s: %w", tmpName, path, err)
	}

	// Fsync the parent directory so the rename is durable. Without
	// this, the file's new name can still be lost on power loss even
	// though its bytes are safely on disk. If we can't open the
	// directory (EACCES / EMFILE / etc.) we surface that as an error
	// rather than silently skip the sync — callers expect this
	// function to report any failure that compromises the durability
	// contract.
	d, derr := os.Open(dir)
	if derr != nil {
		return fmt.Errorf("open parent dir %s for sync: %w", dir, derr)
	}
	syncErr := d.Sync()
	closeErr := d.Close()
	if syncErr != nil {
		return fmt.Errorf("sync parent dir %s: %w", dir, syncErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close parent dir %s: %w", dir, closeErr)
	}
	return nil
}

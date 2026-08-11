// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package k3s

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"time"
)

// SharedBinaryPath is where the kube role publishes its k3s binary for
// the witness container to use, and where the witness looks for it.
//
// The witness cannot simply read the kube role's copy in place. On ext4
// that copy lives under /persist/vault/kube, which both containers see,
// but on ZFS the kube role mounts the etcd-storage zvol at its own
// /var/lib, and that mount exists only in its mount namespace.
//
// Inside the vault rather than plain /persist. Everything k3s and its
// runtime exec sits under /var/lib: the k3s binary and its kubectl/ctr/
// crictl links, and the self-extracted containerd, containerd-shim and
// runc under rancher/k3s/data. That is vault-encrypted storage in both
// layouts, the vault directory itself on ext4 and a zvol keyed by the
// vault on ZFS. Publishing to plain /persist would put the one binary
// two root processes exec on unencrypted storage, which is worth
// tampering with and is weaker than the copy it was made from.
//
// Both roles reach this only after their prereqs have waited for the
// vault to unseal, so the encryption costs no extra ordering.
var SharedBinaryPath = "/persist/vault/k3s-shared/k3s"

// sharedPollInterval between checks while the witness waits for the
// kube role to publish the binary.
var sharedPollInterval = 5 * time.Second

// PublishSharedBinary copies the installed k3s binary to
// SharedBinaryPath for the witness container. No-op when the published
// copy is already the same size, which is enough to catch a version
// change: k3s releases differ in size, and a same-size different build
// is not a case worth an expensive hash on every boot.
//
// Called by the kube role only. The witness never writes here.
func PublishSharedBinary() error {
	src, err := os.Stat(K3sBinaryPath)
	if err != nil {
		return fmt.Errorf("stat %s: %w", K3sBinaryPath, err)
	}
	if dst, err := os.Stat(SharedBinaryPath); err == nil && dst.Size() == src.Size() {
		return nil
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("stat %s: %w", SharedBinaryPath, err)
	}
	if err := os.MkdirAll(filepath.Dir(SharedBinaryPath), 0755); err != nil {
		return fmt.Errorf("create shared bin dir: %w", err)
	}
	// Stage under a temp name and rename into place, so the witness
	// never sees a half-published binary and tries to exec it.
	//
	// A hard link costs no space and is what happens on ext4, where the
	// kube role's /var/lib is a bind of /persist/vault/kube and so the
	// same filesystem as this. It is safe against an in-place k3s
	// upgrade because update installs through a rename, which replaces
	// the directory entry and leaves this link on the old inode until
	// the next publish. On ZFS the two are separate filesystems, the
	// link fails with EXDEV, and a copy is the only option.
	tmp := SharedBinaryPath + ".tmp"
	_ = os.Remove(tmp)
	how := "linked"
	if err := os.Link(K3sBinaryPath, tmp); err != nil {
		how = "copied"
		if err := copyFile(K3sBinaryPath, tmp); err != nil {
			return err
		}
	}
	if err := os.Rename(tmp, SharedBinaryPath); err != nil {
		return fmt.Errorf("rename %s: %w", tmp, err)
	}
	log.Printf("%s k3s binary for the witness to %s", how, SharedBinaryPath)
	return nil
}

// WaitSharedBinary blocks until the kube role has published the k3s
// binary, then links it into this container's own bin dir so the rest
// of the install path proceeds unchanged.
//
// Called by the witness role only. The wait is expected on a first
// boot: the kube role downloads k3s before publishing it.
func WaitSharedBinary(ctx context.Context) error {
	logged := false
	for {
		if _, err := os.Stat(SharedBinaryPath); err == nil {
			break
		} else if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("stat %s: %w", SharedBinaryPath, err)
		}
		if !logged {
			log.Printf("waiting for the kube container to publish k3s at %s",
				SharedBinaryPath)
			logged = true
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("waiting for %s: %w", SharedBinaryPath, ctx.Err())
		case <-time.After(sharedPollInterval):
		}
	}
	if err := os.MkdirAll(filepath.Dir(K3sBinaryPath), 0755); err != nil {
		return fmt.Errorf("create bin dir: %w", err)
	}
	if err := ensureSymlink(SharedBinaryPath, K3sBinaryPath); err != nil {
		return fmt.Errorf("link %s -> %s: %w", K3sBinaryPath, SharedBinaryPath, err)
	}
	return nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("open %s: %w", src, err)
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
	if err != nil {
		return fmt.Errorf("create %s: %w", dst, err)
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return fmt.Errorf("copy %s -> %s: %w", src, dst, err)
	}
	if err := out.Sync(); err != nil {
		out.Close()
		return fmt.Errorf("sync %s: %w", dst, err)
	}
	return out.Close()
}

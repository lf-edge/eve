// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package k3s

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/lf-edge/eve/pkg/kube/kube-init/state"
)

// K3sVersion pins the k3s release this build expects. On a mismatch
// EnsureInstalled tears down the install marker and re-runs the
// self-extract flow, so a controller-driven k3s upgrade triggers
// the install path automatically on the next boot.
const K3sVersion = "v1.34.2+k3s1"

// Subpaths and binary names produced by `k3s check-config`'s
// self-extraction.
const (
	// k3sDataCurrentBin is the directory `k3s check-config`
	// self-extracts shim/runc/etc. into. `current` is a symlink k3s
	// maintains internally.
	k3sDataCurrentBin = "/var/lib/rancher/k3s/data/current/bin"

	containerdShimName = "containerd-shim-runc-v2"
	runcName           = "runc"
	multusName         = "multus"
)

// loadBearingBinaries are the symlinks under /usr/bin that downstream
// code invokes directly. A failure to recreate any of them turns a
// reboot of the kube container into a non-functional node, so
// symlinkAllBinaries treats failures on these names as fatal rather
// than warning-only.
var loadBearingBinaries = map[string]struct{}{
	"k3s":     {},
	"kubectl": {},
	"ctr":     {},
	"crictl":  {},
}

// EnsureInstalled makes sure the k3s binary is unpacked and every
// runtime symlink kube-init relies on is in place. Idempotent and
// safe to call on every boot.
//
// The function rebuilds the ephemeral /usr/bin symlinks
// unconditionally before consulting the install marker, because the
// kube linuxkit container's /usr is recreated from a read-only image
// layer on every container restart while /var/lib is bind-mounted
// onto persistent storage. Without the unconditional rebuild a
// restart with a healthy /var/lib loses /usr/bin/k3s and every
// downstream exec fails.
//
// After a successful self-extract we rebuild a SECOND time so the
// freshly-extracted shim/runc/multus links pick up the new data dir
// (the first rebuild ran before extraction had populated it).
func EnsureInstalled(ctx context.Context) error {
	if _, err := os.Stat(K3sBinaryPath); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("k3s binary missing at %s", K3sBinaryPath)
		}
		return fmt.Errorf("stat %s: %w", K3sBinaryPath, err)
	}

	if err := rebuildRuntimeSymlinks(); err != nil {
		return fmt.Errorf("rebuild runtime symlinks: %w", err)
	}

	marked, err := state.IsMarked(state.K3sInstalledUnpacked)
	if err != nil {
		return fmt.Errorf("check install marker %s: %w",
			state.K3sInstalledUnpacked, err)
	}
	if marked {
		ver, verErr := GetInstalledVersion()
		switch {
		case verErr == nil && ver == K3sVersion:
			log.Printf("k3s %s already installed", ver)
			return nil
		case verErr != nil:
			log.Printf("read installed version failed (%v); re-installing", verErr)
		default:
			log.Printf("version mismatch installed=%s want=%s; re-installing",
				ver, K3sVersion)
		}
		if err := state.Unmark(state.K3sInstalledUnpacked); err != nil {
			return fmt.Errorf("unmark stale install %s: %w",
				state.K3sInstalledUnpacked, err)
		}
	}

	// k3s has no public extract subcommand; `check-config` is the
	// cheapest top-level command that drags the embedded payload
	// (containerd, runc, etc.) onto disk. Its exit code is intentionally
	// not propagated: ExitError is expected because check-config flags
	// built-in CONFIG_* options as "missing"; what matters is whether
	// the shim/runc binaries land in k3sDataCurrentBin (verified below).
	// Non-ExitError errors (binary-not-found, ctx cancellation,
	// SIGSEGV) ARE surfaced — those mean the exec never produced a
	// real exit status and we should not pretend extraction happened.
	log.Printf("triggering k3s self-extraction via check-config")
	if err := runK3sCheckConfig(ctx); err != nil {
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) {
			return fmt.Errorf("k3s check-config exec failed: %w", err)
		}
		log.Printf("k3s check-config exited non-zero (expected): %v", err)
	}

	if _, err := os.Stat(filepath.Join(k3sDataCurrentBin, containerdShimName)); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("self-extraction failed: %s missing under %s",
				containerdShimName, k3sDataCurrentBin)
		}
		return fmt.Errorf("stat %s: %w", containerdShimName, err)
	}

	if err := rebuildRuntimeSymlinks(); err != nil {
		return fmt.Errorf("rebuild runtime symlinks after self-extract: %w", err)
	}

	if err := state.Mark(state.K3sInstalledUnpacked); err != nil {
		return fmt.Errorf("mark install: %w", err)
	}
	log.Printf("k3s %s installed and unpacked", K3sVersion)
	return nil
}

// rebuildRuntimeSymlinks recreates every /usr/bin symlink that points
// into a persistent /var/lib path. See the package layout note in
// EnsureInstalled for why this runs on every boot.
//
// Tolerant of a missing k3s data directory (first-boot pre-extract):
// the shim/runc/multus links are skipped and the caller re-invokes
// after check-config completes.
func rebuildRuntimeSymlinks() error {
	return rebuildRuntimeSymlinksAt(k3sBinDir, "/usr/bin", k3sDataCurrentBin)
}

// rebuildRuntimeSymlinksAt is the path-parameterised seam.
func rebuildRuntimeSymlinksAt(binDir, usrBinDir, dataBinDir string) error {
	if err := symlinkAllBinaries(binDir, usrBinDir); err != nil {
		return fmt.Errorf("symlink %s -> %s: %w", binDir, usrBinDir, err)
	}

	// shim/runc are present only after check-config has self-extracted.
	// Skip silently otherwise; the post-extract re-call populates them.
	for _, bin := range []string{containerdShimName, runcName} {
		src := filepath.Join(dataBinDir, bin)
		if _, err := os.Stat(src); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			log.Printf("warning: stat %s: %v", src, err)
			continue
		}
		if err := ensureSymlink(src, filepath.Join(usrBinDir, bin)); err != nil {
			log.Printf("warning: symlink %s: %v", bin, err)
		}
	}

	if err := linkMultusAt(multusLinkSource, dataBinDir); err != nil {
		log.Printf("runtime symlinks: multus link failed: %v", err)
	}
	return nil
}

// GetInstalledVersion runs `k3s --version` and parses the version
// string. Returns an error if no k3s binary is exec'able or if the
// output doesn't carry the expected shape.
func GetInstalledVersion() (string, error) {
	binary, err := selectK3sBinary()
	if err != nil {
		return "", err
	}
	out, err := exec.Command(binary, "--version").CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("k3s --version: %w (output: %s)",
			err, strings.TrimSpace(string(out)))
	}
	// Expected: `k3s version v1.34.2+k3s1 (abc1234)`
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 3 && fields[0] == "k3s" && fields[1] == "version" {
			return fields[2], nil
		}
	}
	return "", fmt.Errorf("could not parse k3s version from: %s",
		strings.TrimSpace(string(out)))
}

// selectK3sBinary picks the first existing k3s binary path. Prefers
// K3sBinaryPath (the unpacked binary) over K3sSymlink so a stale
// symlink during an in-place upgrade does not shadow the new binary.
// When neither path exists the error chains all encountered stat
// failures via errors.Join so the operator can see which path failed
// for what reason.
func selectK3sBinary() (string, error) {
	var joined error
	for _, p := range []string{K3sBinaryPath, K3sSymlink} {
		_, err := os.Stat(p)
		if err == nil {
			return p, nil
		}
		joined = errors.Join(joined, fmt.Errorf("stat %s: %w", p, err))
	}
	return "", fmt.Errorf("k3s binary not found at %s or %s: %w",
		K3sBinaryPath, K3sSymlink, joined)
}

// symlinkAllBinaries symlinks every regular file in srcDir into
// dstDir. Failures on load-bearing names (k3s, kubectl, ctr, crictl)
// are returned; failures on other entries are logged and the loop
// continues so a single broken auxiliary entry does not abort the
// rebuild.
func symlinkAllBinaries(srcDir, dstDir string) error {
	entries, err := os.ReadDir(srcDir)
	if err != nil {
		return fmt.Errorf("read %s: %w", srcDir, err)
	}
	var joined error
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		src := filepath.Join(srcDir, e.Name())
		dst := filepath.Join(dstDir, e.Name())
		if err := ensureSymlink(src, dst); err != nil {
			if _, loadBearing := loadBearingBinaries[e.Name()]; loadBearing {
				joined = errors.Join(joined,
					fmt.Errorf("link load-bearing %s: %w", e.Name(), err))
				continue
			}
			log.Printf("warning: symlink %s -> %s: %v", dst, src, err)
		}
	}
	return joined
}

// linkMultusAt symlinks the host multus binary into the k3s data
// directory.
//
// Skips silently when dataBinDir does not yet exist. Pre-creating
// /var/lib/rancher/k3s/data/current/bin (or any ancestor) before
// check-config has run causes k3s to rotate it to data/previous/ on
// the next start and create a fresh current symlink, polluting the
// filesystem with a misleading "previous install" marker.
func linkMultusAt(src, dataBinDir string) error {
	// Check dataBinDir BEFORE any cleanup, so a "not yet extracted"
	// state never silently removes a stale link without recreating it.
	if _, err := os.Stat(dataBinDir); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("stat %s: %w", dataBinDir, err)
	}

	dst := filepath.Join(dataBinDir, multusName)

	// Decide what's currently at dst — symlink, regular file, or
	// nothing — via Lstat. Readlink would error on a non-symlink,
	// hiding "there's an unexpected regular file in the way".
	info, lstatErr := os.Lstat(dst)
	switch {
	case lstatErr == nil:
		if info.Mode()&os.ModeSymlink != 0 {
			if target, err := os.Readlink(dst); err == nil && target == src {
				return nil
			}
			// Wrong-target symlink; remove and recreate below.
		} else {
			log.Printf("replacing unexpected non-symlink at %s (mode=%v)",
				dst, info.Mode())
		}
		if err := os.Remove(dst); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove existing %s: %w", dst, err)
		}
	case errors.Is(lstatErr, os.ErrNotExist):
		// Nothing at dst — fall through to Symlink.
	default:
		return fmt.Errorf("lstat %s: %w", dst, lstatErr)
	}

	if err := os.Symlink(src, dst); err != nil {
		return fmt.Errorf("symlink %s -> %s: %w", src, dst, err)
	}
	log.Printf("linked multus: %s -> %s", dst, src)
	return nil
}

// ensureSymlink creates or refreshes a symlink at dst pointing at
// src. If a correct symlink is already in place the call is a
// no-op. Any other existing entry (wrong-target symlink, regular
// file, dangling link) is removed and replaced — the replacement of
// a non-symlink is logged so postmortems can see it happened.
func ensureSymlink(src, dst string) error {
	info, lstatErr := os.Lstat(dst)
	switch {
	case lstatErr == nil:
		if info.Mode()&os.ModeSymlink != 0 {
			if target, err := os.Readlink(dst); err == nil && target == src {
				return nil
			}
		} else {
			log.Printf("replacing unexpected non-symlink at %s (mode=%v)",
				dst, info.Mode())
		}
		if err := os.Remove(dst); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove existing %s: %w", dst, err)
		}
	case errors.Is(lstatErr, os.ErrNotExist):
		// Nothing in the way — proceed.
	default:
		return fmt.Errorf("lstat %s: %w", dst, lstatErr)
	}

	if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
		return fmt.Errorf("mkdir for %s: %w", dst, err)
	}
	if err := os.Symlink(src, dst); err != nil {
		return fmt.Errorf("symlink %s -> %s: %w", src, dst, err)
	}
	log.Printf("symlinked %s -> %s", dst, src)
	return nil
}

// runK3sCheckConfig invokes `k3s check-config` to trigger the
// embedded payload's self-extraction. Output is appended to
// installLogPath; lines containing fail/missing/error tokens are
// also surfaced to the daemon log so the most useful breadcrumbs
// are visible without shipping the full output.
//
// Returns the exec error untouched — EnsureInstalled distinguishes
// ExitError (acceptable: check-config commonly exits non-zero from
// kernel-config audit) from other errors (binary missing, ctx
// cancelled, signalled) before treating extraction as successful.
func runK3sCheckConfig(ctx context.Context) error {
	if err := os.MkdirAll(filepath.Dir(installLogPath), 0755); err != nil {
		log.Printf("warning: create install log dir: %v", err)
	}

	var logFile *os.File
	if f, err := os.OpenFile(installLogPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644); err != nil {
		log.Printf("warning: open install log %s: %v", installLogPath, err)
	} else {
		logFile = f
		defer func() {
			if err := logFile.Close(); err != nil {
				log.Printf("warning: close install log %s: %v", installLogPath, err)
			}
		}()
	}

	binary, err := selectK3sBinary()
	if err != nil {
		return err
	}
	out, runErr := exec.CommandContext(ctx, binary, "check-config").CombinedOutput()
	if logFile != nil {
		if _, wErr := logFile.Write(out); wErr != nil {
			log.Printf("warning: write install log: %v", wErr)
		}
	}
	for _, line := range strings.Split(string(out), "\n") {
		lower := strings.ToLower(line)
		if strings.Contains(lower, "fail") ||
			strings.Contains(lower, "missing") ||
			strings.Contains(lower, "error") {
			log.Printf("check-config: %s", strings.TrimSpace(line))
		}
	}
	return runErr
}

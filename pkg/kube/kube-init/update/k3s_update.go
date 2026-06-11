// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package update

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/lf-edge/eve/pkg/kube/kube-init/k3s"
	"github.com/lf-edge/eve/pkg/kube/kube-init/kubeconfig"
)

// k3sGitHubReleasesURL is the base URL for k3s binary releases.
var k3sGitHubReleasesURL = "https://github.com/k3s-io/k3s/releases/download"

// k3sBinDir is the directory the supervisor will exec from. The
// final binary is dropped here atomically by updateK3s.
var k3sBinDir = "/var/lib/k3s/bin"

// k3sZeroVersion is the sentinel "no binary installed yet" version
// k3sGetVersion returns when the binary is missing or unreadable.
// CheckNodeComponents treats this as "nothing to stop" on first
// boot so it does not try to terminate a non-existent supervisor.
const k3sZeroVersion = "v0.0.0+k3s0"

// Stopper abstracts the supervisor's Stop method so CheckNodeComponents
// can terminate k3s before swapping the binary without a hard
// dependency on the *k3s.Supervisor concrete type.
//
// A nil Stopper is accepted only on first boot (when the running
// version equals k3sZeroVersion and there is nothing to stop). On
// every other path CheckNodeComponents requires a non-nil Stopper
// and returns an error otherwise.
type Stopper interface {
	Stop() error
}

// k3sGetVersion runs the installed k3s binary with --version and
// extracts the version field. Returns k3sZeroVersion when the
// binary is absent so the caller can distinguish "fresh device,
// nothing to stop" from "installed but at a known version". Non-
// ErrNotExist stat failures are logged before returning the
// sentinel so a permissions regression leaves a forensic trail.
func k3sGetVersion() string {
	if _, err := os.Stat(k3s.K3sBinaryPath); err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			log.Printf("update: stat %s: %v (treating as not installed)",
				k3s.K3sBinaryPath, err)
		}
		return k3sZeroVersion
	}
	out, err := exec.Command(k3s.K3sBinaryPath, "--version").CombinedOutput()
	if err != nil {
		log.Printf("update: k3s --version failed: %v", err)
		return k3sZeroVersion
	}
	if v := parseK3sVersion(string(out)); v != "" {
		return v
	}
	log.Printf("update: could not parse k3s version from: %s",
		strings.TrimSpace(string(out)))
	return k3sZeroVersion
}

// parseK3sVersion extracts the version field from `k3s --version`
// output of the form:
//
//	k3s version v1.34.2+k3s1 (abc1234)
//	go version goN.NN.N
//
// Returns "" on no match.
func parseK3sVersion(out string) string {
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 3 && fields[0] == "k3s" && fields[1] == "version" {
			return fields[2]
		}
	}
	return ""
}

// getDesiredK3sVersion returns the controller-specified k3sVersion
// from the KubeConfig pubsub subscription, falling back to the
// build's compile-time k3s.K3sVersion when the subscription has
// not delivered yet or carries an empty override.
//
// The KubeConfig subscription is registered at startup
// (main.go -> kubeconfig.Register). Get returns ok=false until the
// first delivery; once delivered, K3sVersion may legitimately be
// empty (controller has explicitly not set an override) — both
// states fall through to the compile-time default.
func getDesiredK3sVersion() string {
	v := kubeconfig.K3sVersion()
	if v == "" {
		return k3s.K3sVersion
	}
	return v
}

// CheckNodeComponents compares the running k3s version against the
// desired version and performs an in-place binary swap when they
// differ. Returns (true, nil) when a swap actually happened so the
// caller knows it must restart the supervisor; (false, nil) when
// the running version already matches; (false, err) on failure.
//
// The supervisor must be stopped before the new binary is dropped
// in: the supervisor will only pick up the new bytes by re-exec'ing
// the path on its next Start, so leaving it running would race the
// next restart against an in-flight upgrade. (Replacing the file
// via rename is safe with respect to the running process — Linux
// keeps the old inode alive via the open fd — so the failure mode
// is "supervisor keeps running the old version forever," not a
// crash.) On first boot there is no supervisor to stop.
func CheckNodeComponents(ctx context.Context, sup Stopper) (bool, error) {
	currentVersion := k3sGetVersion()
	desiredVersion := getDesiredK3sVersion()

	log.Printf("update: k3s version check current=%s desired=%s",
		currentVersion, desiredVersion)

	if currentVersion == desiredVersion {
		return false, nil
	}

	log.Printf("update: k3s upgrade required %s -> %s",
		currentVersion, desiredVersion)
	PublishUpdateStatus("k3s", StatusDownload, "")

	if currentVersion != k3sZeroVersion {
		if sup == nil {
			err := errors.New("k3s upgrade requires a supervisor but none was provided")
			PublishUpdateStatus("k3s", StatusFailed, err.Error())
			return false, err
		}
		log.Printf("update: stopping k3s via supervisor before binary swap")
		if err := sup.Stop(); err != nil {
			PublishUpdateStatus("k3s", StatusFailed, err.Error())
			return false, fmt.Errorf("stop k3s before upgrade: %w", err)
		}
	}

	if err := updateK3s(ctx, desiredVersion); err != nil {
		PublishUpdateStatus("k3s", StatusFailed, err.Error())
		return false, fmt.Errorf("update k3s to %s: %w", desiredVersion, err)
	}

	newVersion := k3sGetVersion()
	if newVersion != desiredVersion {
		errMsg := fmt.Sprintf("version mismatch after update: got %s, want %s",
			newVersion, desiredVersion)
		PublishUpdateStatus("k3s", StatusFailed, errMsg)
		return false, errors.New(errMsg)
	}

	PublishUpdateStatus("k3s", StatusCompleted, "")
	log.Printf("update: k3s updated to %s (verified)", desiredVersion)
	return true, nil
}

// updateK3s downloads the k3s binary directly from GitHub releases,
// verifies its SHA-256 hash, and installs it atomically into
// k3sBinDir. The caller restarts the supervisor after this returns.
func updateK3s(ctx context.Context, dstVersion string) error {
	if err := os.MkdirAll(k3sBinDir, 0755); err != nil {
		return fmt.Errorf("create k3s bin dir %s: %w", k3sBinDir, err)
	}

	// Release URLs URL-encode the '+' in versions like v1.34.2+k3s1.
	versionURLSafe := strings.ReplaceAll(dstVersion, "+", "%2B")
	arch, err := k3sArchSuffix()
	if err != nil {
		return err
	}
	binSuffix := k3sBinarySuffix(arch)

	hashURL := fmt.Sprintf("%s/%s/sha256sum-%s.txt",
		k3sGitHubReleasesURL, versionURLSafe, arch)
	log.Printf("update: downloading hash from %s", hashURL)
	hashFile := filepath.Join(os.TempDir(), "k3s.hash")
	if err := curlDownload(ctx, hashURL, hashFile); err != nil {
		return fmt.Errorf("download k3s hash: %w", err)
	}
	defer os.Remove(hashFile)

	expectedHash, err := parseHashFile(hashFile, "k3s"+binSuffix)
	if err != nil {
		return fmt.Errorf("parse k3s hash file: %w", err)
	}

	binURL := fmt.Sprintf("%s/%s/k3s%s",
		k3sGitHubReleasesURL, versionURLSafe, binSuffix)
	log.Printf("update: downloading k3s binary from %s", binURL)
	tmpBin := filepath.Join(os.TempDir(), "k3s.download")
	if err := curlDownload(ctx, binURL, tmpBin); err != nil {
		return fmt.Errorf("download k3s binary: %w", err)
	}
	defer os.Remove(tmpBin)

	log.Printf("update: verifying binary hash")
	actualHash, err := sha256File(tmpBin)
	if err != nil {
		return fmt.Errorf("hash downloaded k3s: %w", err)
	}
	if actualHash != expectedHash {
		return fmt.Errorf("k3s hash mismatch: expected %s, got %s",
			expectedHash, actualHash)
	}

	dstPath := filepath.Join(k3sBinDir, "k3s")
	if err := installBinaryDurable(tmpBin, dstPath, 0755); err != nil {
		return fmt.Errorf("install k3s binary: %w", err)
	}
	log.Printf("update: installed k3s %s to %s", dstVersion, dstPath)
	return nil
}

// curlDownload fetches url into dst via curl. We shell out rather
// than use net/http so the system trust store, proxy settings, and
// retry behaviour follow the rest of the EVE base OS, which is
// curl-based throughout. The partial download (if any) is cleaned
// up here rather than in the caller — curl -sfL does not unlink on
// failure, so we can't rely on the success path's defer.
func curlDownload(ctx context.Context, url, dst string) error {
	cmd := exec.CommandContext(ctx, "curl", "-sfL", "-o", dst, url)
	out, err := cmd.CombinedOutput()
	if err != nil {
		os.Remove(dst)
		return fmt.Errorf("curl %s: %w (output: %s)",
			url, err, truncateForLog(string(out), 4096))
	}
	return nil
}

// parseHashFile reads a sha256sum-style file and returns the hex
// hash for the entry matching filename. Two-field lines with a
// 64-character hex hash are required; anything else is silently
// skipped (BSD-style "SHA256 (name) = hex" lines and the empty
// trailing line GNU sha256sum emits).
//
// If no valid hash line was seen at all, the error distinguishes a
// corrupted download of the hash file (HTTP-error-as-HTML, partial
// transfer) from a "filename simply not present in this manifest"
// case — operators investigating an upgrade failure care about the
// difference.
func parseHashFile(path, filename string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	validLines := 0
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 || !isHex64(fields[0]) {
			continue
		}
		validLines++
		if fields[1] == filename {
			return fields[0], nil
		}
	}
	if validLines == 0 {
		return "", fmt.Errorf("no valid sha256 entries in %s (possibly a corrupt download)",
			path)
	}
	return "", fmt.Errorf("hash for %q not found in %s", filename, path)
}

// isHex64 reports whether s is a 64-character lowercase or
// uppercase hex string (the shape of a SHA-256 digest).
func isHex64(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		switch {
		case c >= '0' && c <= '9':
		case c >= 'a' && c <= 'f':
		case c >= 'A' && c <= 'F':
		default:
			return false
		}
	}
	return true
}

// sha256File computes the hex-encoded SHA-256 of the file at path.
func sha256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("read %s: %w", path, err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// installBinaryDurable copies src to dst via a sibling temp file
// and rename, fsync'ing both the file body and the parent directory
// so the new binary survives a power loss across the rename
// boundary. The copy is streamed, so the ~70 MB k3s binary does not
// have to fit in a single allocation.
func installBinaryDurable(src, dst string, perm os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("open src %s: %w", src, err)
	}
	defer in.Close()

	dir := filepath.Dir(dst)
	tmp, err := os.CreateTemp(dir, ".k3s-install-*")
	if err != nil {
		return fmt.Errorf("create temp in %s: %w", dir, err)
	}
	tmpName := tmp.Name()
	cleanupTmp := func() { _ = os.Remove(tmpName) }

	if _, err := io.Copy(tmp, in); err != nil {
		tmp.Close()
		cleanupTmp()
		return fmt.Errorf("copy to %s: %w", tmpName, err)
	}
	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		cleanupTmp()
		return fmt.Errorf("chmod %s: %w", tmpName, err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		cleanupTmp()
		return fmt.Errorf("fsync %s: %w", tmpName, err)
	}
	if err := tmp.Close(); err != nil {
		cleanupTmp()
		return fmt.Errorf("close %s: %w", tmpName, err)
	}
	if err := os.Rename(tmpName, dst); err != nil {
		cleanupTmp()
		return fmt.Errorf("rename %s -> %s: %w", tmpName, dst, err)
	}

	// Fsync the directory so the rename itself is durable. Without
	// this, the file's new name can be lost on power loss even
	// though its bytes are on disk.
	d, derr := os.Open(dir)
	if derr != nil {
		return fmt.Errorf("open %s for sync: %w", dir, derr)
	}
	syncErr := d.Sync()
	closeErr := d.Close()
	if syncErr != nil {
		return fmt.Errorf("fsync %s: %w", dir, syncErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close %s: %w", dir, closeErr)
	}
	return nil
}

// k3sArchSuffix returns the architecture token used in the k3s
// release filenames. Only amd64 and arm64 are produced by k3s
// upstream; anything else is a configuration error that must
// surface before the download URL 404s in a less-helpful way.
func k3sArchSuffix() (string, error) {
	switch runtime.GOARCH {
	case "amd64":
		return "amd64", nil
	case "arm64":
		return "arm64", nil
	default:
		return "", fmt.Errorf("unsupported GOARCH %q for k3s upgrade",
			runtime.GOARCH)
	}
}

// k3sBinarySuffix is the suffix on the k3s release binary filename
// for the given arch.
func k3sBinarySuffix(arch string) string {
	if arch == "arm64" {
		return "-arm64"
	}
	return ""
}

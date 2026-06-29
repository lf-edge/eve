// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package components

import (
	"bytes"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
)

// Registration manifest paths. The source lives on /persist (so the
// operator can update it out-of-band); the applied copy lives in
// the k3s server-manifests dir so k3s auto-applies it as an AddOn.
const (
	persistManifestsDir             = "/persist/vault/manifests"
	registrationYamlName            = "registration"
	registrationYamlFileName        = "registration.yaml"
	registrationYamlFilePath        = persistManifestsDir + "/" + registrationYamlFileName
	appliedRegistrationYamlName     = "persist-registration"
	appliedRegistrationYamlFileName = appliedRegistrationYamlName + ".yaml"
	appliedRegistrationYamlFilePath = manifestsDst + appliedRegistrationYamlFileName
)

// RegistrationCheckApply stages the operator-supplied registration
// manifest from /persist into the k3s server-manifests dir if
// present. k3s auto-applies it as an AddOn — no kubectl call here.
//
// Called every health-worker tick (15 s), so the function is silent
// when there is nothing to do: a missing source manifest produces
// no log line at all, and an already-up-to-date applied copy is
// detected by a byte-compare and skipped without logging. The
// success path only logs when the staged content actually changes.
func RegistrationCheckApply() error {
	src, err := os.ReadFile(registrationYamlFilePath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("read %s: %w", registrationYamlFilePath, err)
	}
	if dst, err := os.ReadFile(appliedRegistrationYamlFilePath); err == nil {
		if bytes.Equal(src, dst) {
			return nil
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("read %s: %w", appliedRegistrationYamlFilePath, err)
	}
	if err := copyFile(registrationYamlFilePath, appliedRegistrationYamlFilePath); err != nil {
		return fmt.Errorf("copy registration manifest from %s to %s: %w",
			registrationYamlFilePath, appliedRegistrationYamlFilePath, err)
	}
	log.Printf("copied registration manifest to %s", appliedRegistrationYamlFilePath)
	return nil
}

// RegistrationCleanup removes both source and applied registration
// files. Per-file ENOENT is tolerated; other errors are collected.
func RegistrationCleanup() error {
	var errs []string
	for _, p := range []string{registrationYamlFilePath, appliedRegistrationYamlFilePath} {
		if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
			errs = append(errs, fmt.Sprintf("remove %s: %v", p, err))
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("registration cleanup: %s", strings.Join(errs, "; "))
	}
	log.Printf("registration manifest cleanup complete")
	return nil
}

// RegistrationExists reports whether the applied registration
// manifest is present in the k3s server-manifests dir.
func RegistrationExists() bool {
	_, err := os.Stat(appliedRegistrationYamlFilePath)
	return err == nil
}

// RegistrationConfigExists reports whether the source registration
// manifest is present on /persist.
func RegistrationConfigExists() bool {
	_, err := os.Stat(registrationYamlFilePath)
	return err == nil
}

// RegistrationApplied checks via kubectl whether k3s has applied
// the registration AddOn.
func RegistrationApplied() bool {
	_, err := kubectl("-n", "kube-system", "get", "AddOn/"+appliedRegistrationYamlName)
	return err == nil
}

// LogRegistrationStatus emits a single human-readable line
// describing the current registration state. Called once at
// daemon entry to RUNNING (and on every re-entry to RUNNING) so
// operators have a clear "did the controller register this
// cluster?" signal in the log without having to read the steady-
// state tick output. The matching steady-state tick
// (RegistrationCheckApply) is silent on the no-op path.
//
// Sources checked, in order:
//
//  1. Source manifest under /persist/vault/manifests/. Absent ->
//     "not configured" (the normal case for a single-node device
//     the controller hasn't registered as a cluster member).
//  2. Applied copy in the k3s server-manifests dir.
//  3. Whether k3s has acknowledged the AddOn via kubectl.
//
// kubectl errors at step 3 (e.g. API not yet reachable) are
// downgraded to "AddOn check pending" so this function never
// fails the caller.
func LogRegistrationStatus() {
	if !RegistrationConfigExists() {
		log.Printf("registration: not configured (no manifest at %s)",
			registrationYamlFilePath)
		return
	}
	if !RegistrationExists() {
		log.Printf("registration: source manifest present at %s, staging into k3s manifests dir pending",
			registrationYamlFilePath)
		return
	}
	if !RegistrationApplied() {
		log.Printf("registration: manifest staged at %s, awaiting k3s AddOn apply",
			appliedRegistrationYamlFilePath)
		return
	}
	log.Printf("registration: AddOn %s applied",
		appliedRegistrationYamlName)
}

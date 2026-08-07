// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build k && !faultinjection

package kubeapi

// No-op variant used when the faultinjection build tag is absent (production
// images). The real, file-existence-driven implementation lives in
// faultinjection_volumedelete.go and is compiled in only under FAULT_INJECTION=y.
// Callers invoke these unconditionally; here they always report "no fault", so
// the delete-path fault branches are dead code the compiler drops.

// VolumeDestroyFaultInjected always reports false in production builds.
func VolumeDestroyFaultInjected() bool { return false }

// DeletePVCFaultInjected always reports false in production builds.
func DeletePVCFaultInjected() bool { return false }

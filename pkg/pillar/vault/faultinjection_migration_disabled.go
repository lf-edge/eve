// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build !faultinjection

package vault

import "github.com/lf-edge/eve/pkg/pillar/base"

// No-op variant used when the faultinjection build tag is absent (production
// images). The real wrapper lives in faultinjection_migration.go and is compiled
// in only under FAULT_INJECTION=y; here the storage operations are handed back
// untouched, so nothing in the migration path consults a marker.
func wrapVaultOps(inner zfsVaultOps, _ *base.LogObject) zfsVaultOps { return inner }

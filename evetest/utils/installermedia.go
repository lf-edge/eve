// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package utils

import (
	api "github.com/lf-edge/eve/evetest/grpcapi/go"
)

// InstallerMediaCapability returns the capability a broker advertises when it
// can build a device from a locally built EVE installer image on the given
// medium. The harness checks it before asking for that medium and the broker
// derives what it advertises from the same table, so the two cannot drift
// apart. Returns false for INSTALLER_MEDIA_UNSPECIFIED and unknown values.
func InstallerMediaCapability(media api.InstallerMedia) (api.Capability, bool) {
	switch media {
	case api.InstallerMedia_INSTALLER_MEDIA_RAW:
		return api.Capability_CAPABILITY_LOCAL_INSTALLER_RAW, true
	case api.InstallerMedia_INSTALLER_MEDIA_ISO:
		return api.Capability_CAPABILITY_LOCAL_INSTALLER_ISO, true
	case api.InstallerMedia_INSTALLER_MEDIA_NET:
		return api.Capability_CAPABILITY_LOCAL_INSTALLER_NET, true
	}
	return api.Capability_CAPABILITY_UNSPECIFIED, false
}

// InstallerMediaName returns how error messages and logs name an installer
// medium, matching the `make installer-<medium>` target that builds it.
func InstallerMediaName(media api.InstallerMedia) string {
	switch media {
	case api.InstallerMedia_INSTALLER_MEDIA_RAW:
		return "raw"
	case api.InstallerMedia_INSTALLER_MEDIA_ISO:
		return "ISO"
	case api.InstallerMedia_INSTALLER_MEDIA_NET:
		return "NET"
	}
	return media.String()
}

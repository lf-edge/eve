// Copyright (c) 2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package hypervisor

import (
	"os"
	"path/filepath"

	"github.com/sirupsen/logrus"
)

// getWindowsLicenceACPIPath returns the path to the ACPI tables that contain
// the Windows licence information.
func getWindowsLicenceACPIPath() []string {
	collectedLicences := []string{}
	// check for both MSDM and SLIC tables, SLIC is deprecated but we should
	// look for it in case older versions of Windows are being used.
	windowsLicenceTables := []string{"MSDM", "SLIC"}
	acpiTablePath := "/sys/firmware/acpi/tables"

	for _, table := range windowsLicenceTables {
		sysfsPath := filepath.Join(acpiTablePath, table)
		if _, err := os.Stat(sysfsPath); err != nil {
			logrus.Infof("error while checkin %s table : %v", table, err)
			continue
		}

		collectedLicences = append(collectedLicences, sysfsPath)
	}

	return collectedLicences
}

// Copyright (c) 2020-2022 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package vault

import (
	"fmt"

	libzfs "github.com/bicomsystems/go-libzfs"
	"github.com/lf-edge/eve/pkg/pillar/base"
)

// CheckOperStatus returns nil if for vaultPath properties
// for in ZFS have the following values:
// mounted:yes keystatus:available encryption:aes-256-gcm;
// else return err
func CheckOperStatus(log *base.LogObject, vaultPath string) error {
	dataset, err := libzfs.DatasetOpen(vaultPath)
	if err != nil {
		return err
	}
	defer dataset.Close()

	mounted, err := dataset.GetProperty(libzfs.DatasetPropMounted)
	if err != nil {
		return fmt.Errorf("DatasetExist(%s): Get property PropMounted failed. %s",
			vaultPath, err.Error())
	}

	encryption, err := dataset.GetProperty(libzfs.DatasetPropEncryption)
	if err != nil {
		return fmt.Errorf("DatasetExist(%s): Get property Encryption failed. %s",
			vaultPath, err.Error())

	}

	// This property is not available for a dataset if no options associated
	// with the key were specified during it's creation.
	keyStatus, err := dataset.GetProperty(libzfs.DatasetPropKeyStatus)
	if err != nil {
		return fmt.Errorf("DatasetExist(%s): Get property KeyStatus failed. %s",
			vaultPath, err.Error())

	}

	//Expect mounted:yes keystatus:available encryption:aes-256-gcm
	if mounted.Value != "yes" {
		return fmt.Errorf("DatasetExist(%s): Dataset is not mounted. value: %s",
			vaultPath, mounted.Value)
	}

	if keyStatus.Value != "available" {
		return fmt.Errorf("DatasetExist(%s): Key is not loaded. value: %s",
			vaultPath, keyStatus.Value)
	}

	if encryption.Value != "aes-256-gcm" {
		return fmt.Errorf("DatasetExist(%s): Encryption is not enabled. value: %s",
			vaultPath, encryption.Value)
	}

	return nil
}

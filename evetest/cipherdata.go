// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package evetest

import (
	"bytes"
	"fmt"

	"github.com/lf-edge/eve-api/go/evecommon"
	"github.com/lf-edge/eve/evetest/utils"
)

// encryptCipherData creates a CipherBlock from an EncryptionBlock.
func (th *TestHarness) encryptCipherData(
	devName string, encBlock *evecommon.EncryptionBlock) (*evecommon.CipherBlock, error) {

	th.devicesM.Lock()
	devState, found := th.devices[devName]
	if !found {
		th.devicesM.Unlock()
		return nil, fmt.Errorf("unknown device %q", devName)
	}
	devECDHCert := devState.ecdhCert
	th.devicesM.Unlock()

	ctrlECDHCert, ctrlECDHKey := th.adamClient.GetECDHCertAndKey()
	cryptoConfig, err := utils.NewCryptoConfig(devECDHCert, ctrlECDHCert, ctrlECDHKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create crypto config: %w", err)
	}
	cipherCtx, err := utils.CreateCipherCtx(cryptoConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher context: %w", err)
	}
	cipherCtx, err = th.addCipherCtxToDevice(devName, cipherCtx)
	if err != nil {
		return nil, fmt.Errorf("failed to add cipher context: %w", err)
	}
	return utils.EncryptBlock(encBlock, cryptoConfig, cipherCtx)
}

// addCipherCtxToDevice associates or de-duplicates a cipher context for a device.
func (th *TestHarness) addCipherCtxToDevice(devName string,
	cipherCtx *evecommon.CipherContext) (*evecommon.CipherContext, error) {
	th.devicesM.Lock()
	defer th.devicesM.Unlock()

	devState, found := th.devices[devName]
	if !found {
		th.devicesM.Unlock()
		return nil, fmt.Errorf("unknown device %q", devName)
	}

	if devState.config == nil {
		devState.config = NewEdgeDeviceConfig(devName)
	}

	// Check if we already have cipherCtx with the same certificates.
	for _, existingCtx := range devState.config.GetCipherContexts() {
		sameCipherCtx :=
			bytes.Equal(existingCtx.DeviceCertHash, cipherCtx.DeviceCertHash) &&
				bytes.Equal(existingCtx.ControllerCertHash, cipherCtx.ControllerCertHash)
		if sameCipherCtx {
			return existingCtx, nil
		}
	}

	devState.config.CipherContexts = append(devState.config.CipherContexts, cipherCtx)
	return cipherCtx, nil
}

/*
// reEncryptCipherData re-encrypts all cipher blocks in an EdgeDevConfig using a new signing cert.
func (th *TestHarness) reEncryptCipherData(devName string, edgeDevConfig *eveconfig.EdgeDevConfig,
	newCtrlECDHCert *x509.Certificate) error {

	th.devicesM.Lock()
	devState, found := th.devices[devName]
	if !found {
		th.devicesM.Unlock()
		return nil, fmt.Errorf("unknown device %q", devName)
	}
	devECDHCert := devState.ecdhCert
	th.devicesM.Unlock()

	oldCtrlECDHCert, ctrlECDHKey := th.adamClient.GetECDHCertAndKey()

	oldCfg, err := utils.NewCryptoConfig(devCert, oldCtrlECDHCert, ctrlECDHKey)
	if err != nil {
		return fmt.Errorf("getCommonCryptoConfig (old): %w", err)
	}
	newCfg, err := utils.NewCryptoConfig(devCert, newCtrlECDHCert, ctrlECDHKey)
	if err != nil {
		return fmt.Errorf("getCommonCryptoConfig (new): %w", err)
	}
	cipherCtx, err := utils.CreateCipherCtx(newCfg)
	if err != nil {
		return fmt.Errorf("createCipherCtx: %w", err)
	}
	cipherCtx = addCipherCtxToDevice(devName, cipherCtx)

	for _, cfg := range edgeDevConfig.Apps {
		if err := utils.ReEncryptCipherData(cfg, oldCfg, newCfg, cipherCtx); err != nil {
			return fmt.Errorf("reencrypt app config: %w", err)
		}
	}
	for _, cfg := range edgeDevConfig.Datastores {
		if err := utils.ReEncryptCipherData(cfg, oldCfg, newCfg, cipherCtx); err != nil {
			return fmt.Errorf("reencrypt datastore config: %w", err)
		}
	}
	for _, netCfg := range edgeDevConfig.GetNetworks() {
		if netCfg.Wireless == nil {
			continue
		}
		for _, cell := range netCfg.Wireless.CellularCfg {
			for _, ap := range cell.AccessPoints {
				if err := utils.ReEncryptCipherData(ap, oldCfg, newCfg, cipherCtx); err != nil {
					return fmt.Errorf("reencrypt cellular config: %w", err)
				}
			}
		}
		for _, wifi := range netCfg.Wireless.WifiCfg {
			if err := utils.ReEncryptCipherData(wifi, oldCfg, newCfg, cipherCtx); err != nil {
				return fmt.Errorf("reencrypt wifi config: %w", err)
			}
		}
	}
	return nil
}

*/

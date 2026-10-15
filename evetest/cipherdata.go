// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package evetest

import (
	"bytes"
	"fmt"

	eveconfig "github.com/lf-edge/eve-api/go/config"
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
//
// The context is recorded in the harness-held device config, which is the single
// owner of the cipher-context list: ApplyConfig always republishes the list found
// there, ignoring the one in the config passed to it (see edgedevice.go).
// Contexts are never removed, so cipher blocks tagged with a retired controller
// certificate keep decrypting for as long as the device holds that certificate.
func (th *TestHarness) addCipherCtxToDevice(devName string,
	cipherCtx *evecommon.CipherContext) (*evecommon.CipherContext, error) {
	th.devicesM.Lock()
	defer th.devicesM.Unlock()

	devState, found := th.devices[devName]
	if !found {
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

// cipherBlockSite is a cipher block found in a device configuration, together
// with a description of its owner for error messages.
type cipherBlockSite struct {
	what  string
	block *evecommon.CipherBlock
}

// cipherBlockSites returns every cipher block of a device configuration.
//
// Every site in this package that creates a cipher block must be listed here
// (grep for encryptCipherData) and in clearCipherBlocks. The last two are held
// in fields not named CipherData, which is why this walks the configuration
// explicitly instead of relying on a getter interface.
func cipherBlockSites(config *eveconfig.EdgeDevConfig) []cipherBlockSite {
	var sites []cipherBlockSite
	add := func(what string, block *evecommon.CipherBlock) {
		if block != nil {
			sites = append(sites, cipherBlockSite{what: what, block: block})
		}
	}

	for _, app := range config.GetApps() {
		add("application "+app.GetDisplayname(), app.GetCipherData())
	}
	for _, ds := range config.GetDatastores() {
		add("datastore "+ds.GetId(), ds.GetCipherData())
	}
	for _, netCfg := range config.GetNetworks() {
		wireless := netCfg.GetWireless()
		if wireless == nil {
			continue
		}
		for _, wifi := range wireless.GetWifiCfg() {
			add("WiFi network "+wifi.GetWifiSSID(), wifi.GetCipherData())
		}
		for _, cellular := range wireless.GetCellularCfg() {
			for _, ap := range cellular.GetAccessPoints() {
				add("cellular access point "+ap.GetApn(), ap.GetCipherData())
			}
		}
	}
	for _, scep := range config.GetScepProfiles() {
		add("SCEP profile "+scep.GetProfileName(), scep.GetScepChallengePassword())
	}
	add("cluster join token", config.GetCluster().GetEncryptedClusterToken())
	return sites
}

// clearCipherBlocks removes every cipher block from a device configuration.
//
// The owners are listed here as well as in cipherBlockSites, because a reader
// cannot unset the field it read from. The closing check is what keeps the two
// lists honest: a newly added cipher block that this function forgets would
// otherwise survive a device reset silently, still encrypted against whatever
// certificate the previous test used.
func clearCipherBlocks(config *eveconfig.EdgeDevConfig) error {
	for _, app := range config.GetApps() {
		if app != nil {
			app.CipherData = nil
		}
	}
	for _, ds := range config.GetDatastores() {
		if ds != nil {
			ds.CipherData = nil
		}
	}
	for _, netCfg := range config.GetNetworks() {
		wireless := netCfg.GetWireless()
		if wireless == nil {
			continue
		}
		for _, wifi := range wireless.GetWifiCfg() {
			if wifi != nil {
				wifi.CipherData = nil
			}
		}
		for _, cellular := range wireless.GetCellularCfg() {
			for _, ap := range cellular.GetAccessPoints() {
				if ap != nil {
					ap.CipherData = nil
				}
			}
		}
	}
	for _, scep := range config.GetScepProfiles() {
		if scep != nil {
			scep.ScepChallengePassword = nil
		}
	}
	if config.GetCluster() != nil {
		config.Cluster.EncryptedClusterToken = nil
	}

	if left := cipherBlockSites(config); len(left) > 0 {
		return fmt.Errorf("failed to clear the cipher block of %s; "+
			"clearCipherBlocks must be extended whenever a new cipher block "+
			"is added to the configuration", left[0].what)
	}
	return nil
}

// hasCipherBlocks reports whether a device configuration contains at least one
// cipher block, i.e. whether it has anything to migrate when the controller's
// ECDH certificate is rotated.
func hasCipherBlocks(config *eveconfig.EdgeDevConfig) bool {
	return len(cipherBlockSites(config)) > 0
}

// reEncryptCipherBlocks re-encrypts every cipher block of a device
// configuration from oldCfg to newCfg and re-tags it with cipherCtx.
// Blocks already tagged with cipherCtx are skipped, making the function
// idempotent.
func reEncryptCipherBlocks(config *eveconfig.EdgeDevConfig,
	oldCfg, newCfg *utils.CryptoConfig, cipherCtx *evecommon.CipherContext) error {

	for _, site := range cipherBlockSites(config) {
		if site.block.GetCipherContextId() == cipherCtx.GetContextId() {
			continue
		}
		err := utils.ReEncryptCipherBlock(site.block, oldCfg, newCfg, cipherCtx)
		if err != nil {
			return fmt.Errorf(
				"failed to re-encrypt cipher block of %s: %w", site.what, err)
		}
	}
	return nil
}

// checkCipherBlocksUseCurrentECDHCert reports an error for the first cipher block
// in the configuration that is not encrypted against the controller's current
// ECDH certificate. cipherCtxs is the cipher-context list the configuration will
// be pushed with.
//
// This exists to make one silent regression loud. RotateControllerEncryptCert
// re-encrypts the configuration builders handed to it; a test that keeps a
// builder the rotation never saw will push blocks encrypted against the retired
// certificate on its next ApplyConfig. Nothing fails at that moment - pillar
// keeps a controller certificate alive while a cipher context still references
// it, and evetest never removes contexts - so the regression would only surface
// after a reboot, or not at all in a test that never reboots.
func (th *TestHarness) checkCipherBlocksUseCurrentECDHCert(
	config *eveconfig.EdgeDevConfig, cipherCtxs []*evecommon.CipherContext) error {

	ctrlECDHCert, _ := th.adamClient.GetECDHCertAndKey()
	if ctrlECDHCert == nil {
		return nil
	}
	currentHash := utils.ControllerCertHash(ctrlECDHCert)[:16]

	for _, site := range cipherBlockSites(config) {
		ctxID := site.block.GetCipherContextId()
		var blockCtx *evecommon.CipherContext
		for _, cipherCtx := range cipherCtxs {
			if cipherCtx.GetContextId() == ctxID {
				blockCtx = cipherCtx
				break
			}
		}
		if blockCtx == nil {
			// The context list is owned by the harness-held config, so a block can
			// only name a context missing from it if the block was built outside
			// encryptCipherData or copied from another device's config.
			return fmt.Errorf("cipher block of %s names cipher context %s, which "+
				"is not among the contexts registered for this device",
				site.what, ctxID)
		}
		if !bytes.Equal(blockCtx.GetControllerCertHash(), currentHash) {
			return fmt.Errorf("cipher block of %s uses cipher context %s, which "+
				"references a retired controller ECDH certificate; pass this "+
				"configuration to RotateControllerEncryptCert", site.what, ctxID)
		}
	}
	return nil
}

// Copyright (c) 2022 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package vault

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/lf-edge/eve-api/go/info"
	"github.com/lf-edge/eve/pkg/pillar/base"
	etpm "github.com/lf-edge/eve/pkg/pillar/evetpm"
	"github.com/lf-edge/eve/pkg/pillar/types"
)

const (
	// fsCryptConfFile is where we keep config
	fsCryptConfFile = "/etc/fscrypt.conf"
	// fsCryptPath is the fscrypt binary
	fsCryptPath = "/opt/zededa/bin/fscrypt"

	mountPoint             = types.PersistDir
	defaultVault           = types.SealedDirName
	protectorPrefix        = "TheVaultKey"
	keyDir                 = "/TmpVaultDir2"
	keyFile                = keyDir + "/protector.key"
	oldKeyDir              = "/TmpVaultDir1"
	oldKeyFile             = oldKeyDir + "/protector.key"
	deprecatedCfgVaultName = "Configuration Data Store"
	deprecatedImgVault     = types.PersistDir + "/img"
	deprecatedCfgVault     = types.PersistDir + "/config"
)

var (
	keyctlPath   = "/bin/keyctl"
	keyctlParams = []string{"link", "@u", "@s"}
)

// Ext4Handler handles vault operations with ext4
type Ext4Handler struct {
	log     *base.LogObject
	options HandlerOptions
}

// GetOperationalInfo returns status of encryption and string with information
func (h *Ext4Handler) GetOperationalInfo() (info.DataSecAtRestStatus, string) {
	if !etpm.IsTpmEnabled() {
		// No encryption on platforms without a (working) TPM
		h.log.Trace("Setting status to disabled, TPM is not in use")
		return info.DataSecAtRestStatus_DATASEC_AT_REST_DISABLED,
			"TPM is either absent or not in use"
	}
	_, err := os.Stat(fsCryptConfFile)
	if err == nil {
		if !h.isFscryptEnabled(mountPoint) {
			// fscrypt is setup, but not being used
			h.log.Trace("Setting status to Error")
			return info.DataSecAtRestStatus_DATASEC_AT_REST_ERROR,
				"Fscrypt Encryption is not setup"
		}
		// fscrypt is setup, and being used on /persist
		h.log.Trace("Setting status to Enabled")
		return info.DataSecAtRestStatus_DATASEC_AT_REST_ENABLED,
			"Fscrypt is enabled and active"
	} else {
		return info.DataSecAtRestStatus_DATASEC_AT_REST_ERROR,
			"Fscrypt is not enabled"
	}
}

// SetHandlerOptions adjust handler options
func (h *Ext4Handler) SetHandlerOptions(options HandlerOptions) {
	h.options = options
}

// GetVaultStatuses returns statuses of vault(s)
func (h *Ext4Handler) GetVaultStatuses() []*types.VaultStatus {
	var statuses []*types.VaultStatus
	fscryptStatus, fscryptErr := h.GetOperationalInfo()
	statuses = append(statuses, h.getVaultStatus(types.DefaultVaultName, defaultVault,
		fscryptStatus, fscryptErr))

	// Don't try if it isn't there
	_, err := os.Stat(deprecatedCfgVault)
	if os.IsNotExist(err) {
		return statuses
	}
	statuses = append(statuses, h.getVaultStatus(deprecatedCfgVaultName, deprecatedCfgVault,
		fscryptStatus, fscryptErr))
	return statuses
}

// SetupDefaultVault setups vaults on ext4, using fscrypt
func (h *Ext4Handler) SetupDefaultVault() error {
	if !etpm.IsTpmEnabled() {
		_, err := os.Stat(defaultVault)
		if os.IsNotExist(err) {
			// No TPM or TPM lacks required features
			// Vault is just a plain folder in those cases
			return os.MkdirAll(defaultVault, 755)
		}
		if err == nil && h.isFscryptEnabled(defaultVault) {
			// old versions of EVE created vault on TPM platforms
			// irrespective of their PCR/ECDSA capabilities
			// which is a bug. At the very best, we can just unlock it
			// just to keep the encryption ON. No sealing/attestation support
			// in these cases
			return h.setupVault(defaultVault, true)
		}
		return err
	}

	if err := h.setupVault(defaultVault, false); err != nil {
		return fmt.Errorf("error in setting up vault %s:%v", defaultVault, err)
	}
	// Log the type of key used for unlocking default vault
	h.log.Noticef("default vault unlocked using key type: %s",
		etpm.CompareLegacyandSealedKey().String())
	return nil
}

// RemoveDefaultVault removes vaults from ext4
func (h *Ext4Handler) RemoveDefaultVault() error {
	if err := os.RemoveAll(defaultVault); err != nil {
		return fmt.Errorf("error in clean up vault %s: %w", defaultVault, err)
	}
	return nil
}

// SetupDeprecatedVaults to support some very old releases (< 5.6.2 )
func (h *Ext4Handler) SetupDeprecatedVaults() error {
	if err := h.setupFscryptEnv(); err != nil {
		return fmt.Errorf("error in setting up fscrypt environment: %s",
			err)
	}
	if err := h.setupVault(deprecatedImgVault, true); err != nil {
		return fmt.Errorf("error in setting up vault %s:%v", deprecatedImgVault, err)
	}
	if err := h.setupVault(deprecatedCfgVault, true); err != nil {
		return fmt.Errorf("error in setting up vault %s %v", deprecatedCfgVault, err)
	}
	return nil
}

// UnlockDefaultVault cloudKeyOnlyMode=false, useSealedKey=true
func (h *Ext4Handler) UnlockDefaultVault() error {
	err := h.unlockVault(defaultVault, false, true)
	if err != nil {
		h.log.Errorf("Failed to unlock vault after receiving Controller key, %v", err)
		return err
	}
	return nil
}

func (h *Ext4Handler) getSetupParams() []string {
	return []string{"setup", mountPoint, "--quiet"}
}

func (h *Ext4Handler) getEncryptParams(vaultPath string) []string {
	return []string{"encrypt", vaultPath, "--key=" + keyFile,
		"--source=raw_key", "--name=" + protectorPrefix + filepath.Base(vaultPath),
		"--user=root"}
}

func (h *Ext4Handler) getUnlockParams(vaultPath string) []string {
	return []string{"unlock", vaultPath, "--key=" + keyFile,
		"--user=root"}
}

func (h *Ext4Handler) getStatusParams(vaultPath string) []string {
	args := []string{"status"}
	return append(args, vaultPath)
}

func (h *Ext4Handler) getChangeProtectorParams(protectorID string) []string {
	return []string{"metadata", "change-passphrase", "--key=" + keyFile,
		"--old-key=" + oldKeyFile, "--source=raw_key",
		"--protector=" + mountPoint + ":" + protectorID}
}

func (h *Ext4Handler) getRemoveProtectorParams(protectorID string) []string {
	return []string{"metadata", "destroy", "--protector=" + mountPoint + ":" + protectorID, "--quiet", "--force"}
}

func (h *Ext4Handler) getRemovePolicyParams(policyID string) []string {
	return []string{"metadata", "destroy", "--policy=" + mountPoint + ":" + policyID, "--quiet", "--force"}
}

func (h *Ext4Handler) getProtectorIDByName(vaultPath string) ([][]string, error) {
	stdOut, _, err := execCmd(fsCryptPath, h.getStatusParams(mountPoint)...)
	if err != nil {
		return nil, err
	}
	patternStr := fmt.Sprintf("([[:xdigit:]]+) {2}No {6}raw key protector \"%s\"",
		protectorPrefix+filepath.Base(vaultPath))
	protector := regexp.MustCompile(patternStr)
	return protector.FindAllStringSubmatch(stdOut, -1), nil
}

func (h *Ext4Handler) getPolicyIDByProtectorID(protectID string) ([][]string, error) {
	stdOut, _, err := execCmd(fsCryptPath, h.getStatusParams(mountPoint)...)
	if err != nil {
		return nil, err
	}
	patternStr := fmt.Sprintf("([[:xdigit:]]+) {2}No {6}%s", protectID)
	policy := regexp.MustCompile(patternStr)
	return policy.FindAllStringSubmatch(stdOut, -1), nil
}

func (h *Ext4Handler) removeProtectorIfAny(vaultPath string) error {
	protectorID, err := h.getProtectorIDByName(vaultPath)
	if err == nil && len(protectorID) == 0 {
		// No protector found, nothing to be done.
		return nil
	}
	if err == nil {
		h.log.Functionf("Removing protectorID %s for vaultPath %s", protectorID[0][1], vaultPath)
		args := h.getRemoveProtectorParams(protectorID[0][1])
		if stdOut, stdErr, err := execCmd(fsCryptPath, args...); err != nil {
			h.log.Errorf("Error changing protector key: %v, %v, %v", err, stdOut, stdErr)
			return err
		}
		policyID, err := h.getPolicyIDByProtectorID(protectorID[0][1])
		if err == nil && len(policyID) == 0 {
			// No policy found, nothing to be done.
			return nil
		}
		if err == nil {
			h.log.Functionf("Removing policyID %s for vaultPath %s", policyID[0][1], vaultPath)
			args := h.getRemovePolicyParams(policyID[0][1])
			if stdOut, stdErr, err := execCmd(fsCryptPath, args...); err != nil {
				h.log.Errorf("Error changing policy key: %v, %v, %v", err, stdOut, stdErr)
				return err
			}
		}
	}
	return nil
}

func (h *Ext4Handler) getProtectorID(vaultPath string) ([][]string, error) {
	args := h.getStatusParams(vaultPath)
	stdOut, _, err := execCmd(fsCryptPath, args...)
	if err != nil {
		return nil, err
	}
	protector := regexp.MustCompile(`([[:xdigit:]]+) {2}No {6}raw key protector`)
	return protector.FindAllStringSubmatch(stdOut, -1), nil
}

// changeProtector is used on deprecated vaults. It is used for migrating them
// to TPM based keys, from cloudOnlyKey (which was a bug introduced in the late
// 2019). We still need to keep cloudKeyOnly for some more time, till we migrate
// all the deprecated vaults to TPM based keys, depending on how old the image
// from which we are getting upgraded is.
func (h *Ext4Handler) changeProtector(vaultPath string) error {
	protectorID, err := h.getProtectorID(vaultPath)
	if protectorID != nil {
		// cloudKeyOnlyMode=true, useSealedKey=false
		unstage1, err := stageKey(h.log, true, false, h.options.TpmKeyOnlyMode, oldKeyDir, oldKeyFile)
		if err != nil {
			return err
		}
		defer unstage1()
		// cloudKeyOnlyMode=false, useSealedKey=false
		unstage2, err := stageKey(h.log, false, false, h.options.TpmKeyOnlyMode, keyDir, keyFile)
		if err != nil {
			return err
		}
		defer unstage2()

		// Note on power failure at this point:
		// If there is a power outage after the execCmd call
		// the key would have moved to TPM based key - which is expected
		//
		// If there is a power outage before the execCmd call - the key would
		// not have moved to TPM based key - which will trigger the post-reboot
		// session to try changeProtector again.
		//
		// We expect fscrypt to handle the case where there is a power outage during
		// the execCmd call
		//

		if stdOut, stdErr, err := execCmd(fsCryptPath,
			h.getChangeProtectorParams(protectorID[0][1])...); err != nil {
			h.log.Errorf("Error changing protector key: %v", err)
			h.log.Trace(stdOut)
			h.log.Trace(stdErr)
			return err
		}
		h.log.Functionf("Changed key for protector %s", protectorID[0][1])
	}
	return err
}

// Is fscrypt saying that this folder is encrypted?
func (h *Ext4Handler) isFscryptEnabled(vaultPath string) bool {
	args := h.getStatusParams(vaultPath)
	_, _, err := execCmd(fsCryptPath, args...)
	return err == nil
}

// handleFirstUse sets up mountpoint for the first time use
func (h *Ext4Handler) handleFirstUse() error {
	// setup mountPoint for encryption
	if _, _, err := execCmd(fsCryptPath, h.getSetupParams()...); err != nil {
		return fmt.Errorf("error setting up mountpoint for encryption: %v", err)
	}
	return nil
}

func (h *Ext4Handler) setupFscryptEnv() error {
	// Check if /persist is already setup for encryption
	if !h.isFscryptEnabled(mountPoint) {
		// Not yet setup, set it up for the first use
		return h.handleFirstUse()
	}
	return nil
}

// cloudKeyOnlyMode and useSealedKey are passed to stageKey
func (h *Ext4Handler) unlockVault(vaultPath string, cloudKeyOnlyMode, useSealedKey bool) error {
	unstage, err := stageKey(h.log, cloudKeyOnlyMode, useSealedKey, h.options.TpmKeyOnlyMode, keyDir, keyFile)
	if err != nil {
		return err
	}
	defer unstage()

	// Unlock vault for access
	if _, _, err := execCmd(fsCryptPath, h.getUnlockParams(vaultPath)...); err != nil {
		h.log.Errorf("Error unlocking vault: %v", err)
		return err
	}
	return h.linkKeyrings()
}

// if deprecated is set, only unlock will be attempted, and creation of the vault will be skipped
func (h *Ext4Handler) setupVault(vaultPath string, deprecated bool) error {
	_, err := os.Stat(vaultPath)
	if os.IsNotExist(err) && deprecated {
		h.log.Functionf("vault %s is marked deprecated, so not creating a new vault", vaultPath)
		return nil
	}
	if err != nil && !deprecated {
		// Create vault dir
		if err := os.MkdirAll(vaultPath, 755); err != nil {
			return err
		}
	}
	args := h.getStatusParams(vaultPath)
	if stdOut, stdErr, err := execCmd(fsCryptPath, args...); err != nil {
		h.log.Functionf("%v, %v, %v", stdOut, stdErr, err)
		if !isDirEmpty(h.log, vaultPath) || deprecated {
			// Don't disturb existing installations
			h.log.Functionf("Not disturbing non-empty or deprecated vault(%s), deprecated=%v",
				vaultPath, deprecated)
			return nil
		}
		return h.createVault(vaultPath)
	}
	// Already setup for encryption, go for unlocking
	h.log.Functionf("Unlocking %s", vaultPath)
	// cloudKeyOnlyMode = false, useSealedKey=false if deprecated, true otherwise
	if err := h.unlockVault(vaultPath, false, !deprecated); err != nil {
		if !deprecated {
			// skip any sort of fallback for non-deprecated vaults
			return err
		}
		// XXX: This is to support some very old releases (< 5.6.2 )
		// We unlock them using fallback mode, and then migrate the keys
		// to use TPM based key
		h.log.Noticef("Unlocking using fallback mode: %s", vaultPath)
		// cloudKeyOnlyMode=true, useSealedKey=false,
		// for fallback mode on deprecated vault
		if err := h.unlockVault(vaultPath, true, false); err != nil {
			return err
		}
		h.log.Noticef("Migrating keys to TPM %s", vaultPath)
		return h.changeProtector(vaultPath)
	}
	h.log.Noticef("Successfully unlocked %s", vaultPath)
	return nil
}

func (h *Ext4Handler) getVaultStatus(vaultName string, vaultPath string,
	fscryptStatus info.DataSecAtRestStatus,
	fscryptError string) *types.VaultStatus {
	status := types.VaultStatus{}
	status.Name = vaultName

	if etpm.PCRBankSHA256Enabled() {
		status.PCRStatus = info.PCRStatus_PCR_ENABLED
	} else {
		status.PCRStatus = info.PCRStatus_PCR_DISABLED
	}

	if fscryptStatus != info.DataSecAtRestStatus_DATASEC_AT_REST_ENABLED {
		status.Status = fscryptStatus
		status.SetErrorDescription(types.ErrorDescription{Error: fscryptError})
	} else {
		args := h.getStatusParams(vaultPath)
		if stdOut, stdErr, err := execCmd(fsCryptPath, args...); err != nil {
			h.log.Errorf("Status failed, %v, %v, %v", err, stdOut, stdErr)
			// check further on few things like PCR bank, non-empty dir etc.
			// which are not errors per se, and other agents can use vault
			// folder in those cases
			if !etpm.PCRBankSHA256Enabled() {
				status.Status = info.DataSecAtRestStatus_DATASEC_AT_REST_DISABLED
				status.SetErrorDescription(types.ErrorDescription{Error: "No PCR-SHA256 bank available"})
			} else if !isDirEmpty(h.log, vaultPath) {
				status.Status = info.DataSecAtRestStatus_DATASEC_AT_REST_DISABLED
				status.SetErrorDescription(types.ErrorDescription{Error: "Directory is not empty"})
			} else {
				status.Status = info.DataSecAtRestStatus_DATASEC_AT_REST_ERROR
				status.SetErrorDescription(types.ErrorDescription{Error: stdOut + stdErr})
			}
		} else {
			sealedKeyType := etpm.CompareLegacyandSealedKey()
			switch sealedKeyType {
			case etpm.SealedKeyTypeReused, etpm.SealedKeyTypeNew:
				status.ClearError()
			default:
				status.SetErrorDescription(types.ErrorDescription{Error: sealedKeyType.String()})
			}
			if strings.Contains(stdOut, "Unlocked: Yes") {
				status.Status = info.DataSecAtRestStatus_DATASEC_AT_REST_ENABLED
			} else {
				status.Status = info.DataSecAtRestStatus_DATASEC_AT_REST_ERROR
				if status.PCRStatus == info.PCRStatus_PCR_ENABLED {
					if pcrs, err := etpm.FindMismatchingPCRs(); err == nil {
						status.MismatchingPCRs = pcrs
					}
				}
				status.SetErrorDescription(types.ErrorDescription{Error: "Vault key unavailable"})
			}
		}
	}
	return &status
}

// createVault expects an empty, existing dir at vaultPath
func (h *Ext4Handler) createVault(vaultPath string) error {
	if !etpm.IsTpmEnabled() || !etpm.PCRBankSHA256Enabled() {
		h.log.Noticef("Ignoring vault create request on no-TPM(%v) or no-PCR (%v) platform",
			!etpm.IsTpmEnabled(), !etpm.PCRBankSHA256Enabled())
		return nil
	}
	if err := h.removeProtectorIfAny(vaultPath); err != nil {
		return err
	}
	if err := etpm.WipeOutStaleSealedKeyIfAny(); err != nil {
		return err
	}
	// We never create deprecated vaults, so -
	// cloudKeyOnlyMode=false, useSealedKey=true
	unstage, err := stageKey(h.log, false, true, h.options.TpmKeyOnlyMode, keyDir, keyFile)
	if err != nil {
		return err
	}
	defer unstage()

	// Encrypt vault, and unlock it for accessing
	if stdout, stderr, err := execCmd(fsCryptPath, h.getEncryptParams(vaultPath)...); err != nil {
		h.log.Errorf("Encryption failed: %v, %s, %s", err, stdout, stderr)
		return err
	}
	return h.linkKeyrings()
}

func (h *Ext4Handler) linkKeyrings() error {
	if _, _, err := execCmd(keyctlPath, keyctlParams...); err != nil {
		return fmt.Errorf("error in linking user keyring %v", err)
	}
	return nil
}

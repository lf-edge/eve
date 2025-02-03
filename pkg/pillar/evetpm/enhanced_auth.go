// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package evetpm

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	tpmea "github.com/lf-edge/eve-tpmea"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/types"
	fileutils "github.com/lf-edge/eve/pkg/pillar/utils/file"
	"os"
	"path/filepath"
)

const TpmPolicyCounterIndex = 0x1500017
const RollbackCounter uint64 = 1

type EnhancedAuthConfig struct {
	AuthDigest    []byte               `json:"authDigest"`
	AuthPublicKey []byte               `json:"authPublicKey"`
	Policy        []EnhancedAuthPolicy `json:"policy"`
}

type EnhancedAuthPolicy struct {
	Policy    []byte                `json:"policy"`
	PolicySig tpmea.PolicySignature `json:"policySig"`
}

// TryToSealDiskKeyWithEnhancedAuth loads the current TPM EA policy and tries
// to seal the vault key using enhanced authorization.
func TryToSealDiskKeyWithEnhancedAuth(log *base.LogObject, key []byte) error {
	policyConfig, err := FindCurrentTpmPolicy(types.TPMPolicyConfigDir)
	if err != nil {
		return fmt.Errorf("failed to find current tpm policy for sealing: %w", err)
	}
	return SealDiskKeyWithEnhancedAuth(log, policyConfig, key)
}

// TryToUnsealDiskKeyWithEnhancedAuth loads the current TPM EA policy and tries
// to unseal the vault key using enhanced authorization.
func TryToUnsealDiskKeyWithEnhancedAuth(log *base.LogObject) ([]byte, error) {
	policyConfig, err := FindCurrentTpmPolicy(types.TPMPolicyConfigDir)
	if err != nil {
		return nil, fmt.Errorf("failed to find current tpm policy for unsealing: %w", err)
	}
	return UnsealDiskKeyWithEnhancedAuth(log, policyConfig)
}

func readEnhancedAuthConfig(configPath string) (*EnhancedAuthConfig, error) {
	cont, err := os.ReadFile(configPath)
	if err != nil {
		return nil, err
	}
	authConfig := &EnhancedAuthConfig{}
	err = json.Unmarshal(cont, authConfig)
	if err != nil {
		return nil, err
	}
	return authConfig, nil
}

func decodePublicKeyFromPEM(publicKeyPem []byte) (any, error) {
	block, _ := pem.Decode(publicKeyPem)
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("decoding pem block failed")
	}
	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing pem public key failed : %w", err)
	}
	return publicKey, nil
}

// SealDiskKeyWithEnhancedAuth seals the vault key into the TPM using
// enhanced authorization (EA). This is different from the legacy sealing,
// with EA we can have mutable TPM policies (e.g. mutable PCR config).
func SealDiskKeyWithEnhancedAuth(log *base.LogObject, configPath string, key []byte) error {
	conf, err := readEnhancedAuthConfig(configPath)
	if err != nil {
		return fmt.Errorf("reading tpm-ea config failed: %w", err)
	}
	// if NV counter already exist and it is initialized, this call just returns
	// the existing NV counter for use without messing with it.
	localCounter, err := tpmea.DefineMonotonicCounter(TpmPolicyCounterIndex)
	if err != nil {
		return fmt.Errorf("defining a monodic counter failed: %w", err)
	}
	// if local counter is greater than EVE's release counter, this is a rollback
	// and we reject this version.
	// TODO : move this to earlier stage, i.e. boot service or on grub even?
	if localCounter > RollbackCounter {
		return fmt.Errorf("local monodic counter greater than EVE's release counter (%d > %d)", localCounter, RollbackCounter)
	}
	// to keep the rollback protection working, sync local counter with the EVE's
	// release counter.
	if localCounter < RollbackCounter {
		for counter := localCounter; counter < RollbackCounter; {
			counter, err = tpmea.IncreaseMonotonicCounter(TpmPolicyCounterIndex)
			if err != nil {
				return fmt.Errorf("failed to sync local rollback protection counter with EVE's release counter : %w ", err)
			}
		}
	}
	// TODO: write  a unit test to make sure tpmutil.Handle remains of type uint32
	err = tpmea.SealSecret(uint32(TpmSealedDiskPrivHdl), conf.AuthDigest, key)
	if err != nil {
		return fmt.Errorf("failed to seal the key : %w", err)
	}

	collectTpmDiagInfo(log)
	return nil
}

// UnsealDiskKeyWithEnhancedAuth unseals the vault key from the TPM using
// the enhanced authorization policy.
func UnsealDiskKeyWithEnhancedAuth(log *base.LogObject, configPath string) ([]byte, error) {
	conf, err := readEnhancedAuthConfig(configPath)
	if err != nil {
		return nil, fmt.Errorf("reading tpm-ea config failed: %w", err)
	}
	publicKey, err := decodePublicKeyFromPEM(conf.AuthPublicKey)
	if err != nil {
		return nil, fmt.Errorf("decoding PEM public key failed : %w", err)
	}
	// iterate over all available policies, proceed if at least one of them
	// successfully unseals the secret from TPM.
	for i, pol := range conf.Policy {
		rbp := tpmea.RBP{
			Counter: TpmPolicyCounterIndex,
			Check:   RollbackCounter}
		key, err := tpmea.UnsealSecret(uint32(TpmSealedDiskPrivHdl),
			publicKey,
			pol.Policy,
			&pol.PolicySig,
			DefaultDiskKeySealingPCRs.PCRs,
			rbp)
		if err != nil {
			log.Warnf("failed to unseal disk key with policy (%d of %d) : %v", i+1, len(conf.Policy), err)
			continue
		}
		log.Noticef("successfully unsealed disk key with policy no. %d", i+1)
		return key, nil
	}
	return nil, fmt.Errorf("all available policies failed to unseal the disk key")
}

// RotateEnhancedAuthPublicKey rotates the public key used for enhanced
// authorization.
func RotateEnhancedAuthPublicKey(log *base.LogObject, currentConfigPath string, keyRotationConfigPath string) error {
	key, err := UnsealDiskKeyWithEnhancedAuth(log, currentConfigPath)
	if err != nil {
		return fmt.Errorf("failed to unseal the disk key during key rotation operation : %w", err)
	}
	// the keyRotationConfigPath has be verified by the caller that signed by the
	// right key.
	err = SealDiskKeyWithEnhancedAuth(log, keyRotationConfigPath, key)
	if err != nil {
		return fmt.Errorf("failed to seal the disk key during key rotation operation : %w", err)
	}
	return nil
}

// SaveEnhancedAuthConfig saves the enhanced authorization config into a file,
// if the config for the same auth digest already exists, it will append the
// new policy to the existing config.
func SaveEnhancedAuthConfig(configDir string, config *EnhancedAuthConfig) error {
	savedConfig, err := findTpmEnhancedAuthPolicy(configDir, config.AuthDigest)
	if err == nil {
		readConfig, err := readEnhancedAuthConfig(savedConfig)
		if err != nil {
			return fmt.Errorf("reading tpm-ea config failed: %w", err)
		}
		readConfig.Policy = append(readConfig.Policy, config.Policy...)
		data, err := json.Marshal(config)
		if err != nil {
			return err
		}
		return fileutils.WriteRename(savedConfig, data)
	}
	data, err := json.Marshal(config)
	if err != nil {
		return err
	}
	configPath := filepath.Join(configDir, fmt.Sprintf("tpm-ea-%x.json", config.AuthDigest))
	return fileutils.WriteRename(configPath, data)
}

// findTpmEnhancedAuthPolicy finds the enhanced authorization policy config
// file that matches the given auth digest. If no matching policy found, it
// returns an error. If there are multiple matching policies, it returns the
// first one.
func findTpmEnhancedAuthPolicy(configDir string, policyDigest []byte) (string, error) {
	files, err := os.ReadDir(configDir)
	if err != nil {
		return "", err
	}
	for _, f := range files {
		configPath := filepath.Join(configDir, f.Name())
		conf, err := readEnhancedAuthConfig(configPath)
		if err != nil {
			return "", fmt.Errorf("reading tpm-ea config failed: %w", err)
		}
		if bytes.Equal(policyDigest, conf.AuthDigest) {
			return configPath, nil
		}
	}
	return "", fmt.Errorf("failed to find a matching policy")
}

// FindCurrentTpmPolicy finds the current TPM policy config file that matches
// the current TPM policy auth digest of the sealed key. If no matching policy
// found, it returns an error. If there are multiple matching policies,
// it returns the first one.
func FindCurrentTpmPolicy(configDir string) (string, error) {
	policyDigest, err := tpmea.ReadNVAuthDigest(uint32(TpmSealedDiskPrivHdl))
	if err != nil {
		return "", fmt.Errorf("failed to read the policy digest : %w", err)
	}
	return findTpmEnhancedAuthPolicy(configDir, policyDigest)
}

func collectTpmDiagInfo(log *base.LogObject) {
	// save a snapshot of current PCR values
	if err := saveDiskKeySealingPCRs(); err != nil {
		log.Warnf("saving snapshot of sealing PCRs failed: %s", err)
	}

	// In order to not lose the ability to diff and diagnose the issue,
	// first backup the previous pair of logs (if any). This is needed because
	// once the failing devices get connected to the controller to fetch the
	// backup key, we end up here again and it'll override the MeasurementLogSealSuccess
	// file content with current tpm measurement logs (which is same as the
	// content of MeasurementLogSealFail).
	if err := backupCopiedMeasurementLogs(); err != nil {
		log.Warnf("copying previous snapshot of TPM event log failed: %s", err)
	}

	// fresh start, remove old copies of measurement logs.
	removeCopiedMeasurementLogs()

	// save a copy of the current measurement log, this is also called
	// if unseal fails to have copy when we fail to unlock the vault.
	if err := copyMeasurementLog(measurementLogSealSuccess); err != nil {
		log.Warnf("copying current TPM measurement log failed: %s", err)
	}
}

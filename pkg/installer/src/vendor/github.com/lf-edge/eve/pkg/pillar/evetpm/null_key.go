// Copyright (c) 2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0
package evetpm

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"

	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
	"github.com/lf-edge/eve/pkg/pillar/base"
)

// kernelNullKeyExists checks if the kernel supports the NULL primary key
// validation, it is only supported if CONFIG_TCG_TPM2_HMAC is enabled,
// this is enabled by default on >= 6.10. On TPM devices that don't support
// AES-128-CFB enabling HMAC config can lead to a failure in the TPM device
// initialization[0] and in some other cases has caused TPM performance
// degradation[1]. Proceed with caution enabling it enabling it in eve-kernel.
//
// [0] https://wiki.archlinux.org/title/Trusted_Platform_Module#A_TPM_error_(714)_occurred_attempting_to_create_NULL_primary
// [1] https://www.spinics.net/lists/kernel/msg5805612.html
func kernelNullKeyExists() ([]byte, error) {
	nullNamePath := "/sys/class/tpm/tpm0/null_name"
	// Check if it exists
	name, err := os.ReadFile(nullNamePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read null_name file: %v", err)
	}
	decoded, err := hex.DecodeString(string(bytes.TrimSpace(name)))
	if err != nil {
		return nil, fmt.Errorf("failed to decode null_name: %v", err)
	}
	return decoded, nil
}

// ValidateKernelNullPrimary creates a NULL primary key with the same parameters
// as the kernel and compares the generated name with the kernel's null_name.
// Since the NULL primary key is created with no uniqueness parameters, if no
// TPM reset attack has occurred (and null seed hasn't changed) the name
// should match the kernel's null_name. To further prove that this is not a
// stale reply, it certifies the NULL primary key using the AK and random
// nonce. The nonce should come from a 3rd-party verifier
// in a real attestation scenario.
func ValidateKernelNullPrimary(log *base.LogObject) error {
	kernelNullName, err := kernelNullKeyExists()
	if err != nil {
		if log != nil {
			log.Warnf("failed to read null_name file, possibly kernel does not support it, skipping validation: %v", err)
		}
		return nil
	}

	rw, err := tpm2.OpenTPM(TpmDevicePath)
	if err != nil {
		return err
	}
	defer rw.Close()

	nullPrimaryHandle, _, err := tpm2.CreatePrimary(
		rw,
		tpm2.HandleNull,     // NULL hierarchy
		tpm2.PCRSelection{}, // No PCR selection
		"",                  // Empty auth
		"",                  // Empty sensitive data
		NullKeyTemplate,     // Null key template
	)
	if err != nil {
		return fmt.Errorf("failed to create null primary key: %v", err)
	}

	// Get the null key name, this should match the kernel one
	name, err := getNullKeyName(rw, nullPrimaryHandle)
	if err != nil {
		return fmt.Errorf("failed to read null primary key name: %v", err)
	}

	// Compare the generated name with the kernel's null_name, since
	// the null key primary is created with no uniqueness parameters, if no TPM
	// reset attack has occurred (and null seed hasn't changed) the name should
	// match the kernel's null_name.
	if !bytes.Equal(name, kernelNullName) {
		return fmt.Errorf("generated null key name does not match kernel's null_name")
	}

	// Generate random qualifying data (nonce) and certify the null key
	// to make sure this was not a stale reply. In general this part is
	// most useful for proving the TPM state (state being no reset attack
	// occurred after kernel booted) to a 3rd-party verifier and the
	// qualifyingData should come from the verifier.
	qualifyingData := make([]byte, 32)
	if _, err := rand.Read(qualifyingData); err != nil {
		return fmt.Errorf("failed to generate qualifyingData: %v", err)
	}
	attest, tpmSig, err := tpm2.Certify(rw, EmptyPassword, EmptyPassword, nullPrimaryHandle, TpmAIKHdl, qualifyingData)
	if err != nil {
		return fmt.Errorf("failed to certify null primary key: %v", err)
	}
	cryptoSig, err := tpm2.DecodeSignature(bytes.NewBuffer(tpmSig))
	if err != nil {
		return fmt.Errorf("failed to decode certification signature: %v", err)
	}

	// Get AK public key to verify the certificate
	tpmPubKey, _, _, err := tpm2.ReadPublic(rw, TpmAIKHdl)
	if err != nil {
		return fmt.Errorf("failed to read AK public key: %v", err)
	}
	cryptoPubkey, err := tpmPubKey.Key()
	if err != nil {
		return fmt.Errorf("failed to get AK public key: %v", err)
	}

	// Verify the signature
	attestHash := sha256.Sum256(attest)
	if err := rsa.VerifyPKCS1v15(cryptoPubkey.(*rsa.PublicKey), crypto.SHA256, attestHash[:], cryptoSig.RSA.Signature); err != nil {
		return fmt.Errorf("failed to verify certification signature: %v", err)
	}

	// Verify the nonce
	attestData, err := tpm2.DecodeAttestationData(attest)
	if err != nil {
		return fmt.Errorf("failed to decode attestation data: %v", err)
	}
	if !bytes.Equal(attestData.ExtraData, qualifyingData) {
		return fmt.Errorf("attest data nonce doesn't match the expected value : %v", err)
	}

	return nil
}

// getNullKeyName reads the public area of the null primary key and returns its name
func getNullKeyName(rw io.ReadWriter, handle tpmutil.Handle) ([]byte, error) {
	_, name, _, err := tpm2.ReadPublic(rw, handle)
	if err != nil {
		return nil, fmt.Errorf("failed to read null key public info: %v", err)
	}
	return name, nil
}

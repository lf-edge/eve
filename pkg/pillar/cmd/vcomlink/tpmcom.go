// Copyright (c) 2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package vcomlink

import (
	"bytes"
	"fmt"

	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
	etpm "github.com/lf-edge/eve/pkg/pillar/evetpm"
)

var getOwnerCred = func() (string, error) {
	return etpm.ReadOwnerCrdl()
}

// tpmReadNV reads the data stored in the given NV index,
// this could be arbitrary data stored by the user or for example EK certificate.
func tpmReadNV(index tpmutil.Handle) ([]byte, error) {
	rw, err := tpm2.OpenTPM(TpmDevicePath)
	if err != nil {
		return nil, fmt.Errorf("unable to open TPM: %w", err)
	}
	defer rw.Close()

	tpmOwnerPasswd, err := getOwnerCred()
	if err != nil {
		return nil, fmt.Errorf("error while reading TPM owner credential: %w", err)
	}

	data, err := tpm2.NVReadEx(rw, index, index, tpmOwnerPasswd, 0)
	if err != nil {
		return nil, fmt.Errorf("error while reading NV index: %w", err)
	}

	return data, nil
}

// tpmGetPub gets the public key of the key at the given index.
func tpmGetPub(handle tpmutil.Handle) (*tpm2.Public, error) {
	rw, err := tpm2.OpenTPM(TpmDevicePath)
	if err != nil {
		return nil, fmt.Errorf("unable to open TPM: %w", err)
	}
	defer rw.Close()

	pub, _, _, err := tpm2.ReadPublic(rw, handle)
	if err != nil {
		return nil, fmt.Errorf("error while reading EK public: %w", err)
	}

	return &pub, nil
}

// tpmSign signs the data using the key at the given index.
func tpmSign(index tpmutil.Handle, data []byte) (*tpm2.Signature, error) {
	rw, err := tpm2.OpenTPM(TpmDevicePath)
	if err != nil {
		return nil, fmt.Errorf("unable to open TPM: %w", err)
	}
	defer rw.Close()

	tpmOwnerPasswd, err := getOwnerCred()
	if err != nil {
		return nil, fmt.Errorf("error while reading TPM owner credential: %w", err)
	}

	pub, err := tpmGetPub(index)
	if err != nil {
		return nil, fmt.Errorf("error while getting public key: %w", err)
	}

	digest, validation, err := tpm2.Hash(rw, tpm2.AlgSHA256, data, tpm2.HandleOwner)
	if err != nil {
		return nil, fmt.Errorf("error while hashing data: %w", err)
	}

	var scheme *tpm2.SigScheme
	if pub.RSAParameters != nil {
		scheme = &tpm2.SigScheme{
			Alg:  pub.RSAParameters.Sign.Alg,
			Hash: pub.RSAParameters.Sign.Hash,
		}
	} else if pub.ECCParameters != nil {
		scheme = &tpm2.SigScheme{
			Alg:  pub.ECCParameters.Sign.Alg,
			Hash: pub.ECCParameters.Sign.Hash,
		}
	} else {
		return nil, fmt.Errorf("unsupported public key type")
	}

	sig, err := tpm2.Sign(rw, index, tpmOwnerPasswd, digest[:], validation, scheme)
	if err != nil {
		return nil, fmt.Errorf("error while signing data: %w", err)
	}

	return sig, nil
}

// tpmGetActivateCredentialParams gets TPM EK public key, AIK public key and AIK name,
// all are returned in TPM wire format.
func tpmGetActivateCredentialParams(index tpmutil.Handle) ([]byte, []byte, []byte, error) {
	rw, err := tpm2.OpenTPM(TpmDevicePath)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to open TPM: %w", err)
	}
	defer rw.Close()

	ekPub, _, _, err := tpm2.ReadPublic(rw, etpm.TpmEKHdl)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to read EK public: %w", err)
	}

	ekPubByte, err := ekPub.Encode()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to encode EK public: %w", err)
	}

	var aikName tpmutil.U16Bytes
	aikPub, aikName, _, err := tpm2.ReadPublic(rw, index)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to read AIK public: %w", err)
	}

	aikPubByte, err := aikPub.Encode()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to encode AIK public: %w", err)
	}

	aikNameMarshaled := &bytes.Buffer{}
	if err := aikName.TPMMarshal(aikNameMarshaled); err != nil {
		return nil, nil, nil, fmt.Errorf("failed to marshal AIK name: %w", err)
	}

	return ekPubByte, aikPubByte, aikNameMarshaled.Bytes(), nil
}

// tpmActivateCredential activates the credential (decrypting the secret) using EK and AIK.
func tpmActivateCredential(index tpmutil.Handle, cred, secret []byte) ([]byte, error) {
	rw, err := tpm2.OpenTPM(TpmDevicePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open TPM: %w", err)
	}
	defer rw.Close()

	// we need to skip the first 2 bytes of the credBlob and encryptedSecret
	// as it contains the type. so make sure the length is greater than 2.
	if len(cred) < 2 || len(secret) < 2 {
		return nil, fmt.Errorf("invalid credential blob or encrypted secret")
	}

	cred = cred[2:]
	secret = secret[2:]
	recoveredCred, err := tpm2.ActivateCredential(rw,
		index,
		etpm.TpmEKHdl,
		etpm.EmptyPassword,
		etpm.EmptyPassword,
		cred,
		secret)
	if err != nil {
		return nil, fmt.Errorf("failed to activate credential: %w", err)
	}

	return recoveredCred, nil
}

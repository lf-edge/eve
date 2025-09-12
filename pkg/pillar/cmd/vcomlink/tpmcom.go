// Copyright (c) 2025 Zededa, Inc.
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
	if err := meetSecurityPolicy(index); err != nil {
		return nil, err
	}

	rw, err := tpm2.OpenTPM(tpmDevicePath)
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
	rw, err := tpm2.OpenTPM(tpmDevicePath)
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

// tpmSign signs the data using the key at the given index, if
// the given key handles is a restricted key, data should be
// the actual data to be signed, otherwise it should be the digest
// of the data to be signed, hashed according to the key signing scheme.
func tpmSign(index tpmutil.Handle, data []byte) (*tpm2.Signature, error) {
	var digest []byte
	var validation *tpm2.Ticket

	// Check if the index is not one of the restricted handles
	if err := meetSecurityPolicy(index); err != nil {
		return nil, err
	}

	rw, err := tpm2.OpenTPM(tpmDevicePath)
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
	if pub.Attributes&tpm2.FlagSign != tpm2.FlagSign {
		return nil, fmt.Errorf("key is not a signing key")
	}

	// Check if the key is restricted, if so we need to hash the data
	// using TPM because key can only sign data originated from TPM.
	if pub.Attributes&tpm2.FlagRestricted == tpm2.FlagRestricted {
		hashAlgo, err := getHashAlg(pub)
		if err != nil {
			return nil, fmt.Errorf("error while getting hash algorithm: %w", err)
		}
		digest, validation, err = tpm2.Hash(rw, hashAlgo, data, tpm2.HandleOwner)
		if err != nil {
			return nil, fmt.Errorf("error while hashing data: %w", err)
		}
	} else {
		// if this is not a restricted key, we should get the computed digest
		// as an input.
		digest = data
	}

	// if key has no signing scheme defined, we can provide default scheme
	// for RSA and ECC keys, otherwise we return an error. Bear in mind this
	// can still fail, a signing key should have a signing scheme defined when
	// created.
	var scheme *tpm2.SigScheme
	switch pub.Type {
	case tpm2.AlgRSA:
		if pub.RSAParameters == nil || pub.RSAParameters.Sign == nil {
			scheme = &tpm2.SigScheme{Alg: tpm2.AlgRSASSA, Hash: tpm2.AlgSHA256}
		}
	case tpm2.AlgECC:
		if pub.ECCParameters == nil || pub.ECCParameters.Sign == nil {
			scheme = &tpm2.SigScheme{Alg: tpm2.AlgECDSA, Hash: tpm2.AlgSHA256}
		}
	default:
		return nil, fmt.Errorf("signing scheme is not defined for key type %v", pub.Type)
	}
	sig, err := tpm2.Sign(rw, index, tpmOwnerPasswd, digest, validation, scheme)
	if err != nil {
		return nil, fmt.Errorf("error while signing data %w", err)
	}

	return sig, nil
}

// tpmGetActivateCredentialParams gets TPM EK public key, AIK public key and AIK name,
// all are returned in TPM wire format.
func tpmGetActivateCredentialParams(index tpmutil.Handle) ([]byte, []byte, []byte, error) {
	rw, err := tpm2.OpenTPM(tpmDevicePath)
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
	rw, err := tpm2.OpenTPM(tpmDevicePath)
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

// tpmCertifyKeyWithAik certifies the key at the given index using AIK
func tpmCertifyKeyWithAik(index tpmutil.Handle) (*tpm2.Public, []byte, []byte, error) {
	if err := meetSecurityPolicy(index); err != nil {
		return nil, nil, nil, err
	}

	rw, err := tpm2.OpenTPM(tpmDevicePath)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("unable to open TPM: %w", err)
	}
	defer rw.Close()

	tpmOwnerPasswd, err := getOwnerCred()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("error while reading TPM owner credential: %w", err)
	}

	pub, _, _, err := tpm2.ReadPublic(rw, index)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("reading AIK public key failed: %v", err)
	}
	attestation, sig, err := tpm2.Certify(rw, tpmOwnerPasswd, tpmOwnerPasswd, index, etpm.TpmAIKHdl, nil)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("certify failed: %v", err)
	}

	return &pub, attestation, sig, nil
}

// meetSecurityPolicy checks if the requested NV index meets the security policy,
// this is very simple and checks the index regardless of the operation being performed,
// but sufficient for now.
func meetSecurityPolicy(index tpmutil.Handle) error {
	// Generally do not allow reading the TPM disk key handle, specifically TpmDiskKeyHdl
	// since this is a special handle that is used to store plain disk encryption
	// key in specific scenarios and should not be accessed directly by the user.
	if index == etpm.TpmSealedDiskPrivHdl || index == etpm.TpmSealedDiskPubHdl ||
		index == etpm.TpmDiskKeyHdl {
		return fmt.Errorf("reading NV index %x is not allowed", index)
	}

	// Do not allow signing arbitrary data with the quote key or device key,
	// this could lead to impersonating device data to the controller.
	if index == etpm.TpmQuoteKeyHdl || index == etpm.TpmDeviceKeyHdl {
		return fmt.Errorf("using key at %x is not allowed", index)
	}

	return nil
}

func getHashAlg(pub *tpm2.Public) (tpm2.Algorithm, error) {
	switch pub.Type {
	case tpm2.AlgRSA:
		if pub.RSAParameters == nil || pub.RSAParameters.Sign == nil {
			return tpm2.AlgUnknown, fmt.Errorf("RSA key missing signature scheme")
		}
		return pub.RSAParameters.Sign.Hash, nil
	case tpm2.AlgECC:
		if pub.ECCParameters == nil || pub.ECCParameters.Sign == nil {
			return tpm2.AlgUnknown, fmt.Errorf("ECC key missing signature scheme")
		}
		return pub.ECCParameters.Sign.Hash, nil
	default:
		return tpm2.AlgUnknown, fmt.Errorf("unsupported key type: %v", pub.Type)
	}
}

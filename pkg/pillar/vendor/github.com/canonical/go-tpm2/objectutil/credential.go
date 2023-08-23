// Copyright 2021 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package objectutil

import (
	"errors"
	"fmt"
	"io"

	"github.com/canonical/go-tpm2"
	internal_crypt "github.com/canonical/go-tpm2/internal/crypt"
	internal_util "github.com/canonical/go-tpm2/internal/util"
	"github.com/canonical/go-tpm2/mu"
)

// MakeCredential performs the duties of a certificate authority in order to create an activation
// credential. It establishes a seed which is used to protect the activation credential (see
// section 24 - "Credential Protection" of Part 1 of the Trusted Platform Module Library
// specification).
//
// The encrypted and integrity protected credential blob and a secret are returned, and these can
// be supplied to the TPM2_ActivateCredential command on the TPM on which both the private part of
// key and the object associated with objectName are loaded in order to recover the activation
// credential.
func MakeCredential(rand io.Reader, key *tpm2.Public, credential tpm2.Digest, objectName tpm2.Name) (credentialBlob tpm2.IDObject, secret tpm2.EncryptedSecret, err error) {
	if !mu.IsValid(key) {
		return nil, nil, errors.New("key is not valid")
	}
	if !key.IsStorageParent() || !key.IsAsymmetric() {
		return nil, nil, errors.New("key must be an asymmetric storage parent")
	}
	if !key.NameAlg.Available() {
		return nil, nil, errors.New("name algorithm for key is not available")
	}

	credentialBlob, err = mu.MarshalToBytes(credential)
	if err != nil {
		return nil, nil, fmt.Errorf("cannot marshal credential: %w", err)
	}

	secret, seed, err := internal_crypt.SecretEncrypt(rand, key.Public(), key.NameAlg.GetHash(), []byte(tpm2.IdentityKey))
	if err != nil {
		return nil, nil, fmt.Errorf("cannot create encrypted symmetric seed: %w", err)
	}

	credentialBlob, err = internal_util.ProduceOuterWrap(key.NameAlg, &key.AsymDetail().Symmetric, objectName, seed, false, credentialBlob)
	if err != nil {
		return nil, nil, fmt.Errorf("cannot apply outer wrapper: %w", err)
	}

	return credentialBlob, secret, nil
}

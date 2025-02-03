// Copyright 2021 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package util

import (
	"crypto/rand"

	"github.com/canonical/go-tpm2"
	"github.com/canonical/go-tpm2/objectutil"
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
//
// Deprecated: Use [objectutil.MakeCredential].
func MakeCredential(key *tpm2.Public, credential tpm2.Digest, objectName tpm2.Name) (credentialBlob tpm2.IDObjectRaw, secret tpm2.EncryptedSecret, err error) {
	return objectutil.MakeCredential(rand.Reader, key, credential, objectName)
}

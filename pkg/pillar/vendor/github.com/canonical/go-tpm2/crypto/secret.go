// Copyright 2022 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package crypto

import (
	"crypto"
	"crypto/rand"

	internal_crypt "github.com/canonical/go-tpm2/internal/crypt"
)

// SecretDecrypt recovers a seed from the supplied secret structure using the supplied private key.
// It can be used to recover secrets created by the TPM, such as those created by the
// TPM2_Duplicate command.
//
// If priv is a *[rsa.PrivateKey], this will recover the seed by decrypting the supplied secret
// with RSA-OAEP.
//
// If priv is a *[ecdsa.PrivateKey], this uses ECDH to derive the seed using the supplied secret,
// which will contain a serialized ephemeral peer key.
//
// The specified digest algorithm must match the name algorithm of the public area associated with
// the supplied private key.
//
// This will panic if hashAlg is not available.
//
// Deprecated: Use [github.com/canonical/go-tpm2/cryptutil.SecretDecrypt].
func SecretDecrypt(priv crypto.PrivateKey, hashAlg crypto.Hash, label, secret []byte) (seed []byte, err error) {
	return internal_crypt.SecretDecrypt(priv, hashAlg, label, secret)
}

// SecretEncrypt establishes a seed and associated secret value using the supplied public key and
// digest algorithm. The corresponding private key can recover the seed from the returned secret
// value. This is useful for sharing secrets with the TPM via the TPM2_Import,
// TPM2_ActivateCredential and TPM2_StartAuthSession commands.
//
// If public is a *[rsa.PublicKey], this will generate a random seed and then RSA-OAEP encrypt it
// to create the secret.
//
// If public is a *[ecdsa.PublicKey], this uses ECDH to derive a seed value using an an ephemeral
// key. The secret contains the serialized form of the public part of the ephemeral key.
//
// The supplied digest algorithm must match the name algorithm of the public area associated with
// the supplied public key.
//
// This will panic if hashAlg is not available.
//
// Deprecated: Use [github.com/canonical/go-tpm2/cryptutil.SecretEncrypt].
func SecretEncrypt(public crypto.PublicKey, hashAlg crypto.Hash, label []byte) (secret []byte, seed []byte, err error) {
	return internal_crypt.SecretEncrypt(rand.Reader, public, hashAlg, label)
}

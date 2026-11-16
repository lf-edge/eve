// Copyright 2022 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package cryptutil

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"errors"
	"io"

	"github.com/canonical/go-tpm2"
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
func SecretDecrypt(priv crypto.PrivateKey, hashAlg tpm2.HashAlgorithmId, label, secret []byte) (seed []byte, err error) {
	return internal_crypt.SecretDecrypt(priv, hashAlg.GetHash(), label, secret)
}

// SecretEncrypt establishes a seed and associated secret value using the supplied public key. The
// corresponding private key can recover the seed from the returned secret value. This is useful
// for sharing secrets with the TPM via the TPM2_Import, TPM2_ActivateCredential and
// TPM2_StartAuthSession commands.
//
// If public has the type [tpm2.ObjectTypeRSA], this will generate a random seed and then RSA-OAEP
// encrypt it to create the secret.
//
// If public has the type [tpm2.ObjectTypeECC], this uses ECDH to derive a seed value using an an
// ephemeral key. The secret contains the serialized form of the public part of the ephemeral key.
func SecretEncrypt(rand io.Reader, public *tpm2.Public, label []byte) (secret tpm2.EncryptedSecret, seed []byte, err error) {
	if !public.NameAlg.Available() {
		return nil, nil, errors.New("digest algorithm is not available")
	}

	pub := public.Public()
	switch p := pub.(type) {
	case *rsa.PublicKey:
		if public.Params.RSADetail.Scheme.Scheme != tpm2.RSASchemeNull &&
			public.Params.RSADetail.Scheme.Scheme != tpm2.RSASchemeOAEP {
			return nil, nil, errors.New("unsupported RSA scheme")
		}
	case *ecdsa.PublicKey:
		if p.Curve == nil {
			return nil, nil, errors.New("unsupported curve")
		}
	}

	return internal_crypt.SecretEncrypt(rand, pub, public.NameAlg.GetHash(), label)
}

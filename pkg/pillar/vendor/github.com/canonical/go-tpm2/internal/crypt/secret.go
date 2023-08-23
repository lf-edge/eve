// Copyright 2022 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package crypt

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"errors"
	"fmt"
	"io"
	"math/big"

	"github.com/canonical/go-tpm2/mu"
)

type eccPoint struct {
	X []byte
	Y []byte
}

func zeroExtendBytes(x *big.Int, l int) (out []byte) {
	out = make([]byte, l)
	tmp := x.Bytes()
	copy(out[len(out)-len(tmp):], tmp)
	return
}

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
func SecretDecrypt(priv crypto.PrivateKey, hashAlg crypto.Hash, label, secret []byte) (seed []byte, err error) {
	switch p := priv.(type) {
	case *rsa.PrivateKey:
		h := hashAlg.New()
		label0 := make([]byte, len(label)+1)
		copy(label0, label)
		return rsa.DecryptOAEP(h, nil, p, secret, label0)
	case *ecdsa.PrivateKey:
		var ephPoint eccPoint
		if _, err := mu.UnmarshalFromBytes(secret, &ephPoint); err != nil {
			return nil, fmt.Errorf("cannot unmarshal ephemeral point: %w", err)
		}
		ephX := new(big.Int).SetBytes(ephPoint.X)
		ephY := new(big.Int).SetBytes(ephPoint.Y)

		if !p.Curve.IsOnCurve(ephX, ephY) {
			return nil, errors.New("ephemeral point is not on curve")
		}

		sz := p.Curve.Params().BitSize / 8

		mulX, _ := p.Curve.ScalarMult(ephX, ephY, p.D.Bytes())
		return KDFe(hashAlg, zeroExtendBytes(mulX, sz), label,
			ephPoint.X, zeroExtendBytes(p.X, sz), hashAlg.Size()*8), nil
	default:
		return nil, errors.New("unsupported key type")
	}
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
func SecretEncrypt(rand io.Reader, public crypto.PublicKey, hashAlg crypto.Hash, label []byte) (secret []byte, seed []byte, err error) {
	digestSize := hashAlg.Size()

	switch p := public.(type) {
	case *rsa.PublicKey:
		secret := make([]byte, digestSize)
		if _, err := rand.Read(secret); err != nil {
			return nil, nil, fmt.Errorf("cannot read random bytes for secret: %v", err)
		}

		h := hashAlg.New()
		label0 := make([]byte, len(label)+1)
		copy(label0, label)
		encryptedSecret, err := rsa.EncryptOAEP(h, rand, p, secret, label0)
		return encryptedSecret, secret, err
	case *ecdsa.PublicKey:
		if p.Curve == nil {
			return nil, nil, errors.New("no curve")
		}
		if !p.Curve.IsOnCurve(p.X, p.Y) {
			return nil, nil, errors.New("public key is not on curve")
		}

		ephPriv, ephX, ephY, err := elliptic.GenerateKey(p.Curve, rand)
		if err != nil {
			return nil, nil, fmt.Errorf("cannot generate ephemeral ECC key: %v", err)
		}

		sz := p.Curve.Params().BitSize / 8

		encryptedSecret := mu.MustMarshalToBytes(&eccPoint{
			X: zeroExtendBytes(ephX, sz),
			Y: zeroExtendBytes(ephY, sz)})

		mulX, _ := p.Curve.ScalarMult(p.X, p.Y, ephPriv)
		secret := KDFe(hashAlg, zeroExtendBytes(mulX, sz), label, zeroExtendBytes(ephX, sz),
			zeroExtendBytes(p.X, sz), digestSize*8)
		return encryptedSecret, secret, nil
	default:
		return nil, nil, errors.New("unsupported key type")
	}
}

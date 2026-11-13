// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/binary"
	"fmt"

	internal_crypt "github.com/canonical/go-tpm2/internal/crypt"
)

type NewCipherFunc func([]byte) (cipher.Block, error)

var (
	eccCurves = map[ECCCurve]elliptic.Curve{
		ECCCurveNIST_P224: elliptic.P224(),
		ECCCurveNIST_P256: elliptic.P256(),
		ECCCurveNIST_P384: elliptic.P384(),
		ECCCurveNIST_P521: elliptic.P521(),
	}

	symmetricAlgs = map[SymAlgorithmId]NewCipherFunc{
		SymAlgorithmAES: aes.NewCipher,
	}
)

// RegisterCipher allows a go block cipher implementation to be registered for the
// specified algorithm, so binaries don't need to link against every implementation.
func RegisterCipher(alg SymAlgorithmId, fn NewCipherFunc) {
	symmetricAlgs[alg] = fn
}

func cryptComputeCpHash(alg HashAlgorithmId, command CommandCode, handles []Name, parameters []byte) Digest {
	hash := alg.NewHash()

	binary.Write(hash, binary.BigEndian, command)
	for _, name := range handles {
		hash.Write([]byte(name))
	}
	hash.Write(parameters)

	return hash.Sum(nil)
}

func cryptComputeRpHash(hashAlg HashAlgorithmId, responseCode ResponseCode, commandCode CommandCode, rpBytes []byte) []byte {
	hash := hashAlg.NewHash()

	binary.Write(hash, binary.BigEndian, responseCode)
	binary.Write(hash, binary.BigEndian, commandCode)
	hash.Write(rpBytes)

	return hash.Sum(nil)
}

func cryptComputeNonce(nonce []byte) error {
	_, err := rand.Read(nonce)
	return err
}

func cryptSecretEncrypt(public *Public, label []byte) (EncryptedSecret, []byte, error) {
	if !public.NameAlg.Available() {
		return nil, nil, fmt.Errorf("nameAlg %v is not available", public.NameAlg)
	}

	pub := public.Public()
	switch p := pub.(type) {
	case *rsa.PublicKey:
		if public.Params.RSADetail.Scheme.Scheme != RSASchemeNull &&
			public.Params.RSADetail.Scheme.Scheme != RSASchemeOAEP {
			return nil, nil, fmt.Errorf("unsupported RSA scheme: %v", public.Params.RSADetail.Scheme.Scheme)
		}
	case *ecdsa.PublicKey:
		if p.Curve == nil {
			return nil, nil, fmt.Errorf("unsupported curve: %v", public.Params.ECCDetail.CurveID.GoCurve())
		}
	}

	return internal_crypt.SecretEncrypt(rand.Reader, pub, public.NameAlg.GetHash(), label)
}

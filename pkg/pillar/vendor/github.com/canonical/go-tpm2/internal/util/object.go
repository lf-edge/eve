// Copyright 2021 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package util

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"errors"
	"fmt"
	"hash"
	"io/ioutil"

	"github.com/canonical/go-tpm2"
	"github.com/canonical/go-tpm2/crypto"
	"github.com/canonical/go-tpm2/mu"
)

// UnwrapOuter removes an outer wrapper from the supplied sensitive data blob. The
// supplied name is associated with the data.
//
// It checks the integrity HMAC is valid using the specified digest algorithm and
// a key derived from the supplied seed and returns an error if the check fails.
//
// It then decrypts the data blob using the specified symmetric algorithm and a
// key derived from the supplied seed and name.
func UnwrapOuter(hashAlg tpm2.HashAlgorithmId, symmetricAlg *tpm2.SymDefObject, name tpm2.Name, seed []byte, useIV bool, data []byte) ([]byte, error) {
	if !hashAlg.Available() {
		return nil, errors.New("digest algorithm is not available")
	}
	if symmetricAlg == nil || !symmetricAlg.Algorithm.IsValidBlockCipher() {
		return nil, errors.New("symmetric algorithm is not a valid block cipher")
	}

	r := bytes.NewReader(data)

	var integrity []byte
	if _, err := mu.UnmarshalFromReader(r, &integrity); err != nil {
		return nil, fmt.Errorf("cannot unmarshal integrity digest: %w", err)
	}

	data, _ = ioutil.ReadAll(r)

	hmacKey := crypto.KDFa(hashAlg.GetHash(), seed, []byte(tpm2.IntegrityKey), nil, nil, hashAlg.Size()*8)
	h := hmac.New(func() hash.Hash { return hashAlg.NewHash() }, hmacKey)
	h.Write(data)
	h.Write(name)

	if !bytes.Equal(h.Sum(nil), integrity) {
		return nil, errors.New("integrity digest is invalid")
	}

	r = bytes.NewReader(data)

	iv := make([]byte, symmetricAlg.Algorithm.BlockSize())
	if useIV {
		if _, err := mu.UnmarshalFromReader(r, &iv); err != nil {
			return nil, fmt.Errorf("cannot unmarshal IV: %w", err)
		}
		if len(iv) != symmetricAlg.Algorithm.BlockSize() {
			return nil, errors.New("IV has the wrong size")
		}
	}

	data, _ = ioutil.ReadAll(r)

	symKey := crypto.KDFa(hashAlg.GetHash(), seed, []byte(tpm2.StorageKey), name, nil, int(symmetricAlg.KeyBits.Sym))

	if err := crypto.SymmetricDecrypt(symmetricAlg.Algorithm, symKey, iv, data); err != nil {
		return nil, fmt.Errorf("cannot decrypt: %w", err)
	}

	return data, nil
}

// ProduceOuterWrap adds an outer wrapper to the supplied data. The supplied name
// is associated with the data.
//
// It encrypts the data using the specified symmetric algorithm and a key derived
// from the supplied seed and name.
//
// It then prepends an integrity HMAC of the encrypted data and the supplied
// name using the specified digest algorithm and a key derived from the supplied
// seed.
func ProduceOuterWrap(hashAlg tpm2.HashAlgorithmId, symmetricAlg *tpm2.SymDefObject, name tpm2.Name, seed []byte, useIV bool, data []byte) ([]byte, error) {
	if !hashAlg.Available() {
		return nil, errors.New("digest algorithm is not available")
	}
	if symmetricAlg == nil || !symmetricAlg.Algorithm.IsValidBlockCipher() {
		return nil, errors.New("symmetric algorithm is not a valid block cipher")
	}

	iv := make([]byte, symmetricAlg.Algorithm.BlockSize())
	if useIV {
		if _, err := rand.Read(iv); err != nil {
			return nil, fmt.Errorf("cannot generate IV: %w", err)
		}
	}

	symKey := crypto.KDFa(hashAlg.GetHash(), seed, []byte(tpm2.StorageKey), name, nil, int(symmetricAlg.KeyBits.Sym))

	if err := crypto.SymmetricEncrypt(symmetricAlg.Algorithm, symKey, iv, data); err != nil {
		return nil, fmt.Errorf("cannot encrypt: %w", err)
	}

	if useIV {
		data = mu.MustMarshalToBytes(iv, mu.RawBytes(data))
	}

	hmacKey := crypto.KDFa(hashAlg.GetHash(), seed, []byte(tpm2.IntegrityKey), nil, nil, hashAlg.Size()*8)
	h := hmac.New(func() hash.Hash { return hashAlg.NewHash() }, hmacKey)
	h.Write(data)
	h.Write(name)

	integrity := h.Sum(nil)

	return mu.MustMarshalToBytes(integrity, mu.RawBytes(data)), nil
}

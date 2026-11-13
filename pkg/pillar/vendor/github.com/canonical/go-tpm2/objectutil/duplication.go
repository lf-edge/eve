// Copyright 2021 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package objectutil

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"io/ioutil"

	"github.com/canonical/go-tpm2"
	internal_crypt "github.com/canonical/go-tpm2/internal/crypt"
	internal_util "github.com/canonical/go-tpm2/internal/util"
	"github.com/canonical/go-tpm2/mu"
)

func duplicateToSensitive(duplicate tpm2.Private, name tpm2.Name, outerHashAlg tpm2.HashAlgorithmId, outerSymmetricAlg *tpm2.SymDefObject, outerSeed []byte, innerSymmetricAlg *tpm2.SymDefObject, innerSymmetricKey tpm2.Data) (sensitive *tpm2.Sensitive, err error) {
	if len(outerSeed) > 0 {
		// Remove outer wrapper
		duplicate, err = internal_util.UnwrapOuter(outerHashAlg, outerSymmetricAlg, name, outerSeed, false, duplicate)
		if err != nil {
			return nil, fmt.Errorf("cannot unwrap outer wrapper: %w", err)
		}
	}

	if innerSymmetricAlg != nil && innerSymmetricAlg.Algorithm != tpm2.SymObjectAlgorithmNull {
		// Remove inner wrapper
		if name.Algorithm() == tpm2.HashAlgorithmNull {
			return nil, errors.New("invalid name")
		}
		if !name.Algorithm().Available() {
			return nil, errors.New("name algorithm is not available")
		}
		if !innerSymmetricAlg.Algorithm.IsValidBlockCipher() {
			return nil, errors.New("inner symmetric algorithm is not a valid block cipher")
		}

		if err := internal_crypt.SymmetricDecrypt(innerSymmetricAlg.Algorithm, innerSymmetricKey, make([]byte, innerSymmetricAlg.Algorithm.BlockSize()), duplicate); err != nil {
			return nil, fmt.Errorf("cannot decrypt inner wrapper: %w", err)
		}

		r := bytes.NewReader(duplicate)

		var innerIntegrity []byte
		if _, err := mu.UnmarshalFromReader(r, &innerIntegrity); err != nil {
			return nil, fmt.Errorf("cannot unmarshal inner integrity digest: %w", err)
		}

		duplicate, _ = ioutil.ReadAll(r)

		h := name.Algorithm().NewHash()
		h.Write(duplicate)
		h.Write(name)

		if !bytes.Equal(h.Sum(nil), innerIntegrity) {
			return nil, errors.New("inner integrity digest is invalid")
		}
	}

	if _, err := mu.UnmarshalFromBytes(duplicate, mu.Sized(&sensitive)); err != nil {
		return nil, fmt.Errorf("cannot unmarhsal sensitive: %w", err)
	}

	return sensitive, nil
}

// UnwrapDuplicated unwraps the supplied duplication object and returns the corresponding
// sensitive area. The duplication object will normally be created by executing the
// [tpm2.TPMContext.Duplicate] command.
//
// If outerSecret is supplied then it is assumed that the object has an outer duplication wrapper.
// For an object duplicated with [tpm2.TPMContext.Duplicate], outerSecret is the secret structure
// returned by this command. In this case, privKey, outerHashAlg and outerSymmetricAlg must be
// supplied - privKey is the key that recovers the seed used to generate the outer wrapper (the new
// parent when using [tpm2.TPMContext.Duplicate]), outerHashAlg is the algorithm used for integrity
// checking and key derivation (the new parent's name algorithm when using
// [tpm2.TPMContext.Duplicate]) and must not be [tpm2.HashAlgorithmNull], and outerSymmetricAlg
// defines the symmetric algorithm for the outer wrapper (the new parent's symmetric algorithm when
// using [tpm2.TPMContext.Duplicate]) and must not be [tpm2.SymObjectAlgorithmNull]).
//
// If innerSymmetricAlg is supplied and the Algorithm field is not [tpm2.SymObjectAlgorithmNull],
// then it is assumed that the object has an inner duplication wrapper. In this case, the symmetric
// key for the inner wrapper must be supplied using the innerSymmetricKey argument.
func UnwrapDuplicated(duplicate tpm2.Private, public *tpm2.Public, privKey crypto.PrivateKey, outerHashAlg tpm2.HashAlgorithmId, outerSymmetricAlg *tpm2.SymDefObject, outerSecret tpm2.EncryptedSecret, innerSymmetricKey tpm2.Data, innerSymmetricAlg *tpm2.SymDefObject) (*tpm2.Sensitive, error) {
	var seed []byte
	if len(outerSecret) > 0 {
		if privKey == nil {
			return nil, errors.New("parent private key is required for outer wrapper")
		}
		if outerHashAlg != tpm2.HashAlgorithmNull && !outerHashAlg.Available() {
			return nil, fmt.Errorf("digest algorithm %v is not available", outerHashAlg)
		}

		var err error
		seed, err = internal_crypt.SecretDecrypt(privKey, outerHashAlg.GetHash(), []byte(tpm2.DuplicateString), outerSecret)
		if err != nil {
			return nil, fmt.Errorf("cannot decrypt symmetric seed: %w", err)
		}
	}

	name, err := public.ComputeName()
	if err != nil {
		return nil, fmt.Errorf("cannot compute name: %w", err)
	}

	sensitive, err := duplicateToSensitive(duplicate, name, outerHashAlg, outerSymmetricAlg, seed, innerSymmetricAlg, innerSymmetricKey)
	if err != nil {
		return nil, fmt.Errorf("cannot convert duplicate to sensitive: %w", err)
	}

	return sensitive, nil
}

func sensitiveToDuplicate(sensitive *tpm2.Sensitive, name tpm2.Name, outerHashAlg tpm2.HashAlgorithmId, outerSymmetricAlg *tpm2.SymDefObject, outerSeed []byte, innerSymmetricAlg *tpm2.SymDefObject, innerSymmetricKey tpm2.Data) (innerSymmetricKeyOut tpm2.Data, duplicate tpm2.Private, err error) {
	applyInnerWrapper := false
	if innerSymmetricAlg != nil && innerSymmetricAlg.Algorithm != tpm2.SymObjectAlgorithmNull {
		applyInnerWrapper = true
	}

	applyOuterWrapper := false
	if len(outerSeed) > 0 {
		applyOuterWrapper = true
	}

	duplicate, err = mu.MarshalToBytes(mu.Sized(sensitive))
	if err != nil {
		return nil, nil, fmt.Errorf("cannot marshal sensitive: %w", err)
	}

	if applyInnerWrapper {
		if name.Algorithm() == tpm2.HashAlgorithmNull {
			return nil, nil, errors.New("invalid name")
		}
		if !name.Algorithm().Available() {
			return nil, nil, errors.New("name algorithm is not available")
		}
		if !innerSymmetricAlg.Algorithm.IsValidBlockCipher() {
			return nil, nil, errors.New("inner symmetric algorithm is not a valid block cipher")
		}

		// Apply inner wrapper
		h := name.Algorithm().NewHash()
		h.Write(duplicate)
		h.Write(name)

		innerIntegrity := h.Sum(nil)

		duplicate = mu.MustMarshalToBytes(innerIntegrity, mu.RawBytes(duplicate))

		if len(innerSymmetricKey) == 0 {
			innerSymmetricKeyOut = make([]byte, innerSymmetricAlg.KeyBits.Sym/8)
			if _, err := rand.Read(innerSymmetricKeyOut); err != nil {
				return nil, nil, fmt.Errorf("cannot obtain symmetric key for inner wrapper: %w", err)
			}
			innerSymmetricKey = innerSymmetricKeyOut
		} else if len(innerSymmetricKey) != int(innerSymmetricAlg.KeyBits.Sym/8) {
			return nil, nil, errors.New("the supplied symmetric key for inner wrapper has the wrong length")
		}

		if err := internal_crypt.SymmetricEncrypt(innerSymmetricAlg.Algorithm, innerSymmetricKey, make([]byte, innerSymmetricAlg.Algorithm.BlockSize()), duplicate); err != nil {
			return nil, nil, fmt.Errorf("cannot apply inner wrapper: %w", err)
		}
	}

	if applyOuterWrapper {
		// Apply outer wrapper
		duplicate, err = internal_util.ProduceOuterWrap(outerHashAlg, outerSymmetricAlg, name, outerSeed, false, duplicate)
		if err != nil {
			return nil, nil, fmt.Errorf("cannot apply outer wrapper: %w", err)
		}
	}

	return innerSymmetricKeyOut, duplicate, nil
}

// CreateImportable creates a duplication object that can be imported in to a TPM with the
// [tpm2.TPMContext.Import] command from the supplied sensitive area.
//
// If parentPublic is supplied, an outer duplication wrapper will be applied to the duplication
// object. The parentPublic argument should correspond to the public area of the storage key to
// which the duplication object will be imported. A secret structure will be returned as
// [tpm2.EncryptedSecret] which can be used by the private part of parentPublic in order to
// recover the seed used to generate the outer wrapper.
//
// If innerSymmetricAlg is supplied and the Algorithm field is not [tpm2.SymObjectAlgorithmNull],
// this function will apply an inner duplication wrapper to the duplication object. If
// innerSymmetricKey is supplied, it will be used as the symmetric key for the inner wrapper. It
// must have a size appropriate for the selected symmetric algorithm. If innerSymmetricKey is not
// supplied, a symmetric key will be created and returned as [tpm2.Data].
func CreateImportable(rand io.Reader, sensitive *tpm2.Sensitive, public, parentPublic *tpm2.Public, innerSymmetricKey tpm2.Data, innerSymmetricAlg *tpm2.SymDefObject) (innerSymmetricKeyOut tpm2.Data, duplicate tpm2.Private, outerSecret tpm2.EncryptedSecret, err error) {
	if public.Attrs&(tpm2.AttrFixedTPM|tpm2.AttrFixedParent) != 0 {
		return nil, nil, nil, errors.New("object must be a duplication root")
	}

	if public.Attrs&tpm2.AttrEncryptedDuplication != 0 {
		if innerSymmetricAlg == nil || innerSymmetricAlg.Algorithm == tpm2.SymObjectAlgorithmNull {
			return nil, nil, nil, errors.New("inner symmetric algorithm must be supplied for an object with AttrEncryptedDuplication")
		}
		if parentPublic == nil {
			return nil, nil, nil, errors.New("parent object must be supplied for an object with AttrEncryptedDuplication")
		}
	}

	name, err := public.ComputeName()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("cannot compute name: %w", err)
	}

	var seed []byte
	var outerHashAlg tpm2.HashAlgorithmId
	var outerSymmetricAlg *tpm2.SymDefObject
	if parentPublic != nil {
		if !mu.IsValid(parentPublic) {
			return nil, nil, nil, errors.New("parent object is invalid")
		}
		if parentPublic.NameAlg != tpm2.HashAlgorithmNull && !parentPublic.NameAlg.Available() {
			return nil, nil, nil, fmt.Errorf("digest algorithm %v is not available", parentPublic.NameAlg)
		}
		if !parentPublic.IsStorageParent() || !parentPublic.IsAsymmetric() {
			return nil, nil, nil, errors.New("parent object must be an asymmetric storage key")
		}

		outerHashAlg = parentPublic.NameAlg
		outerSymmetricAlg = &parentPublic.AsymDetail().Symmetric

		outerSecret, seed, err = internal_crypt.SecretEncrypt(rand, parentPublic.Public(), parentPublic.NameAlg.GetHash(), []byte(tpm2.DuplicateString))
		if err != nil {
			return nil, nil, nil, fmt.Errorf("cannot create encrypted outer symmetric seed: %w", err)
		}
	}

	innerSymmetricKeyOut, duplicate, err = sensitiveToDuplicate(sensitive, name, outerHashAlg, outerSymmetricAlg, seed, innerSymmetricAlg, innerSymmetricKey)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("cannot convert sensitive to duplicate: %w", err)
	}

	return innerSymmetricKeyOut, duplicate, outerSecret, nil
}

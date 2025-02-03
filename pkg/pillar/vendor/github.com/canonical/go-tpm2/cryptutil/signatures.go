// Copyright 2021 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package cryptutil

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"math/big"

	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"

	"github.com/canonical/go-tpm2"
)

var _ crypto.Signer = HMACKey(nil)

// HMACKey can be used to sign and verify signatures using the [Sign] and [VerifySignature] APIs.
type HMACKey []byte

// Public implements [crypto.Signer.Public].
func (k HMACKey) Public() crypto.PublicKey {
	return k
}

// Sign implements [crypto.Signer.Sign].
func (k HMACKey) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	h := hmac.New(opts.HashFunc().New, k)
	h.Write(digest)
	return h.Sum(nil), nil
}

func digestFromSignerOpts(opts crypto.SignerOpts) (tpm2.HashAlgorithmId, error) {
	switch opts.HashFunc() {
	case crypto.SHA1:
		return tpm2.HashAlgorithmSHA1, nil
	case crypto.SHA256:
		return tpm2.HashAlgorithmSHA256, nil
	case crypto.SHA384:
		return tpm2.HashAlgorithmSHA384, nil
	case crypto.SHA512:
		return tpm2.HashAlgorithmSHA512, nil
	case crypto.SHA3_256:
		return tpm2.HashAlgorithmSHA3_256, nil
	case crypto.SHA3_384:
		return tpm2.HashAlgorithmSHA3_384, nil
	case crypto.SHA3_512:
		return tpm2.HashAlgorithmSHA3_512, nil
	default:
		return tpm2.HashAlgorithmNull, fmt.Errorf("unsupported digest algorithm %v", opts.HashFunc())
	}
}

// Sign creates a signature of the supplied digest using the supplied signer and options.
// Note that only RSA-SSA, RSA-PSS, ECDSA and HMAC signatures can be created. The returned
// signature can be verified on a TPM using the associated public key.
//
// This may panic if the requested digest algorithm is not available.
func Sign(rand io.Reader, signer crypto.Signer, digest []byte, opts crypto.SignerOpts) (*tpm2.Signature, error) {
	hashAlg, err := digestFromSignerOpts(opts)
	if err != nil {
		return nil, err
	}

	// Check we have a supported signer type that we can create a tpm2.Signature for
	// before the actual signing.
	switch k := signer.Public().(type) {
	case *rsa.PublicKey:
		_ = k
	case *ecdsa.PublicKey:
		_ = k
	case HMACKey:
		_ = k
	default:
		return nil, errors.New("unsupported key type")
	}

	sig, err := signer.Sign(rand, digest, opts)
	if err != nil {
		return nil, err
	}

	switch k := signer.Public().(type) {
	case *rsa.PublicKey:
		_ = k
		if _, pss := opts.(*rsa.PSSOptions); pss {
			return &tpm2.Signature{
				SigAlg: tpm2.SigSchemeAlgRSAPSS,
				Signature: &tpm2.SignatureU{
					RSAPSS: &tpm2.SignatureRSAPSS{
						Hash: hashAlg,
						Sig:  sig}}}, nil
		}
		return &tpm2.Signature{
			SigAlg: tpm2.SigSchemeAlgRSASSA,
			Signature: &tpm2.SignatureU{
				RSASSA: &tpm2.SignatureRSASSA{
					Hash: hashAlg,
					Sig:  sig}}}, nil
	case *ecdsa.PublicKey:
		_ = k
		r, s := new(big.Int), new(big.Int)
		var inner cryptobyte.String

		input := cryptobyte.String(sig)
		if !input.ReadASN1(&inner, asn1.SEQUENCE) ||
			!input.Empty() ||
			!inner.ReadASN1Integer(r) ||
			!inner.ReadASN1Integer(s) ||
			!inner.Empty() {
			return nil, errors.New("invalid ASN.1 signature")
		}
		return &tpm2.Signature{
			SigAlg: tpm2.SigSchemeAlgECDSA,
			Signature: &tpm2.SignatureU{
				ECDSA: &tpm2.SignatureECDSA{
					Hash:       hashAlg,
					SignatureR: r.Bytes(),
					SignatureS: s.Bytes()}}}, nil
	case HMACKey:
		_ = k
		d := tpm2.MakeTaggedHash(hashAlg, sig)
		return &tpm2.Signature{
			SigAlg:    tpm2.SigSchemeAlgHMAC,
			Signature: &tpm2.SignatureU{HMAC: &d}}, nil
	default:
		panic("not reached")
	}
}

// VerifySignature verifies a signature created by a TPM using the supplied public key. Note that
// only RSA-SSA, RSA-PSS, ECDSA and HMAC signatures are supported.
func VerifySignature(key crypto.PublicKey, digest []byte, signature *tpm2.Signature) (ok bool, err error) {
	if !signature.SigAlg.IsValid() {
		return false, errors.New("invalid signature algorithm")
	}
	hashAlg := signature.HashAlg()

	// We don't use IsValid here because we want to know if the algorithm has a corresponding
	// go algorithm ID to avoid a panic later on. SM3 is valid but is not represented in go.
	if hashAlg.GetHash() == crypto.Hash(0) {
		return false, errors.New("invalid digest algorithm")
	}

	switch k := key.(type) {
	case *rsa.PublicKey:
		switch signature.SigAlg {
		case tpm2.SigSchemeAlgRSASSA:
			if err := rsa.VerifyPKCS1v15(k, hashAlg.GetHash(), digest, signature.Signature.RSASSA.Sig); err != nil {
				if err == rsa.ErrVerification {
					return false, nil
				}
				return false, err
			}
			return true, nil
		case tpm2.SigSchemeAlgRSAPSS:
			if !hashAlg.Available() {
				return false, errors.New("digest algorithm is not available")
			}
			options := rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash}
			if err := rsa.VerifyPSS(k, hashAlg.GetHash(), digest, signature.Signature.RSAPSS.Sig, &options); err != nil {
				if err == rsa.ErrVerification {
					return false, nil
				}
				return false, err
			}
			return true, nil
		default:
			return false, errors.New("unsupported RSA signature algorithm")
		}
	case *ecdsa.PublicKey:
		switch signature.SigAlg {
		case tpm2.SigSchemeAlgECDSA:
			ok = ecdsa.Verify(k, digest, new(big.Int).SetBytes(signature.Signature.ECDSA.SignatureR),
				new(big.Int).SetBytes(signature.Signature.ECDSA.SignatureS))
			return ok, nil
		default:
			return false, errors.New("unsupported ECC signature algorithm")
		}
	case HMACKey:
		switch signature.SigAlg {
		case tpm2.SigSchemeAlgHMAC:
			if !hashAlg.Available() {
				return false, errors.New("digest algorithm is not available")
			}
			test, err := Sign(nil, k, digest, hashAlg.GetHash())
			if err != nil {
				return false, err
			}
			return subtle.ConstantTimeCompare(signature.Signature.HMAC.Digest(), test.Signature.HMAC.Digest()) == 1, nil
		default:
			return false, errors.New("unsupported keyed hash signature algorithm")
		}
	default:
		return false, errors.New("invalid public key type")
	}
}

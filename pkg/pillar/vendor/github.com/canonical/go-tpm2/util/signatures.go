// Copyright 2021 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package util

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/canonical/go-tpm2"
	"github.com/canonical/go-tpm2/cryptutil"
	"github.com/canonical/go-tpm2/mu"
)

// Sign creates a signature of the supplied digest using the supplied private key and signature
// scheme. Note that only RSA-SSA, RSA-PSS, ECDSA and HMAC signatures can be created. The
// returned signature can be verified on a TPM using the associated public key.
//
// In order to create a HMAC, the supplied private key should be a byte slice containing the HMAC
// key.
//
// Deprecated: Use [cryptutil.Sign] instead.
func Sign(key crypto.PrivateKey, scheme *tpm2.SigScheme, digest []byte) (*tpm2.Signature, error) {
	var signer crypto.Signer
	var opts crypto.SignerOpts = scheme.AnyDetails().HashAlg.GetHash()

	switch k := key.(type) {
	case *rsa.PrivateKey:
		switch scheme.Scheme {
		case tpm2.SigSchemeAlgRSASSA:
			signer = k
		case tpm2.SigSchemeAlgRSAPSS:
			signer = k
			opts = &rsa.PSSOptions{
				SaltLength: rsa.PSSSaltLengthEqualsHash,
				Hash:       scheme.Details.RSAPSS.HashAlg.GetHash()}
		default:
			return nil, errors.New("unsupported RSA signature scheme")
		}
	case *ecdsa.PrivateKey:
		switch scheme.Scheme {
		case tpm2.SigSchemeAlgECDSA:
			signer = k
		default:
			return nil, errors.New("unsupported ECC signature scheme")
		}
	case []byte:
		switch scheme.Scheme {
		case tpm2.SigSchemeAlgHMAC:
			signer = cryptutil.HMACKey(k)
		default:
			return nil, errors.New("unsupported keyed hash scheme")
		}
	default:
		return nil, errors.New("unsupported private key type")
	}

	return cryptutil.Sign(rand.Reader, signer, digest, opts)
}

// VerifySignature verifies a signature created by a TPM using the supplied public key. Note that
// only RSA-SSA, RSA-PSS, ECDSA and HMAC signatures are supported.
//
// In order to verify a HMAC signature, the supplied public key should be a byte slice containing
// the HMAC key.
//
// Deprecated: Use [cryptutil.Verify] instead.
func VerifySignature(key crypto.PublicKey, digest []byte, signature *tpm2.Signature) (ok bool, err error) {
	switch k := key.(type) {
	case []byte:
		key = cryptutil.HMACKey(k)
	default:
		// pass as is
	}
	return cryptutil.VerifySignature(key, digest, signature)
}

// SignPolicyAuthorization creates a signed authorization using the supplied key and signature
// scheme. The signed authorization can be used in a TPM2_PolicySigned assertion using the
// [tpm2.TPMContext.PolicySigned] function. The authorizing party can apply contraints on how the
// session that includes this authorization can be used.
//
// If nonceTPM is supplied, then the signed authorization can only be used for the session
// associated with the supplied nonce.
//
// If expiration is non-zero, then the signed authorization is only valid for the specified number
// of seconds from when nonceTPM was generated.
//
// If cpHash is supplied, then the signed authorization is only valid for use in a command with the
// associated command code and set of command parameters. The command parameter digest can be
// computed using [ComputeCpHash].
//
// Deprecated: Use [policyutil.SignPolicyAuthorization].
func SignPolicyAuthorization(key crypto.PrivateKey, scheme *tpm2.SigScheme, nonceTPM tpm2.Nonce, cpHashA tpm2.Digest, policyRef tpm2.Nonce, expiration int32) (*tpm2.Signature, error) {
	hashAlg := scheme.AnyDetails().HashAlg
	if !hashAlg.Available() {
		return nil, errors.New("digest algorithm is not available")
	}

	h := hashAlg.NewHash()
	h.Write(nonceTPM)
	binary.Write(h, binary.BigEndian, expiration)
	h.Write(cpHashA)
	h.Write(policyRef)

	return Sign(key, scheme, h.Sum(nil))
}

// ComputePolicyAuthorizeDigest computes a digest to sign from the supplied authorization policy
// digest and policy reference. The resulting digest can be signed to authorize the supplied policy
// with the TPM2_PolicyAuthorize assertion, using the [tpm2.TPMContext.PolicyAuthorize] function.
func ComputePolicyAuthorizeDigest(alg tpm2.HashAlgorithmId, approvedPolicy tpm2.Digest, policyRef tpm2.Nonce) (tpm2.Digest, error) {
	if !alg.Available() {
		return nil, errors.New("digest algorithm is not available")
	}

	h := alg.NewHash()
	h.Write(approvedPolicy)
	h.Write(policyRef)
	return h.Sum(nil), nil
}

// PolicyAuthorize authorizes an authorization policy digest with the supplied key and signature
// scheme. The resulting digest and signature can be verified by the TPM in order to produce a
// ticket that can then be supplied to a TPM2_PolicyAuthorize assertion, using the
// [tpm2.TPMContext.VerifySignature] and [tpm2.TPMContext.PolicyAuthorize] functions.
//
// The digest algorithm used for the signature must match the name algorithm in the public area
// associated with the supplied private key.
func PolicyAuthorize(key crypto.PrivateKey, scheme *tpm2.SigScheme, approvedPolicy tpm2.Digest, policyRef tpm2.Nonce) (tpm2.Digest, *tpm2.Signature, error) {
	hashAlg := scheme.AnyDetails().HashAlg
	if !hashAlg.Available() {
		return nil, nil, errors.New("digest algorithm is not available")
	}

	digest, _ := ComputePolicyAuthorizeDigest(hashAlg, approvedPolicy, policyRef)
	sig, err := Sign(key, scheme, digest)
	if err != nil {
		return nil, nil, err
	}

	return digest, sig, nil
}

// VerifyAttestationSignature verifies the signature for the supplied attestation structure as
// generated by one of the TPM's attestation commands. Note that only RSA-SSA, RSA-PSS, ECDSA and
// HMAC signatures are supported.
//
// In order to verify a HMAC signature, the supplied public key should be a byte slice containing
// the HMAC key.
func VerifyAttestationSignature(key crypto.PublicKey, attest *tpm2.Attest, signature *tpm2.Signature) (ok bool, err error) {
	if !signature.SigAlg.IsValid() {
		return false, errors.New("invalid signature algorithm")
	}
	hashAlg := signature.HashAlg()
	if !hashAlg.Available() {
		return false, errors.New("digest algorithm is not available")
	}

	h := hashAlg.NewHash()
	if _, err := mu.MarshalToWriter(h, attest); err != nil {
		return false, fmt.Errorf("cannot marshal attestation structure: %w", err)
	}

	return VerifySignature(key, h.Sum(nil), signature)
}

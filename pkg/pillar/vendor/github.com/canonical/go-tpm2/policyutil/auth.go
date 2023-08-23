// Copyright 2023 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package policyutil

import (
	"crypto"
	"errors"
	"fmt"
	"io"

	"github.com/canonical/go-tpm2"
	"github.com/canonical/go-tpm2/cryptutil"
	"github.com/canonical/go-tpm2/mu"
)

// PolicyAuthorization represents a signed authorization for a TPM2_PolicySigned assertion.
type PolicyAuthorization struct {
	AuthName   tpm2.Name       // The name of the auth object associated with the corresponding TPM2_PolicySigned assertion
	PolicyRef  tpm2.Nonce      // The policy ref of the corresponding assertion
	NonceTPM   tpm2.Nonce      // The TPM nonce of the session that this authorization is bound to
	CpHash     tpm2.Digest     // The command parameters that this authorization is bound to
	Expiration int32           // The expiration time of this authorization
	Signature  *tpm2.Signature // The actual signature
}

// NewPolicyAuthorization creates a new authorization that can be used by [Policy.Execute] for a
// TPM2_PolicySigned assertion. The authKey and policyRef arguments bind the authorization to a
// specific assertion in a policy. The sessionAlg argument indicates that session digest algorithm
// that the authorization will be valid for, and must match the session digest algorithm if cpHashA
// is supplied.
//
// The authorizing party chooses the values of the other arguments in order to limit the scope of
// the authorization.
//
// If nonceTPM is supplied, the authorization will be bound to the session with the specified TPM
// nonce. If it is not supplied, the authorization is not bound to a specific session.
//
// If cpHashA is supplied, the authorization will be bound to the corresponding command parameters.
// If it is not supplied, the authorization is not bound to any specific command parameters.
//
// If expiration is not zero, then the absolute value of this specifies an expiration time in
// seconds, after which the authorization will expire. If nonceTPM is also provided, the expiration
// time is measured from the time that nonceTPM was generated. If nonceTPM is not provided, the
// expiration time is measured from the time that this authorization is used in the
// TPM2_PolicySigned assertion.
//
// The expiration field can be used to request a ticket from the TPM by specifying a negative
// value. The ticket can be used to satisfy the corresponding TPM2_PolicySigned assertion in future
// sessions, and its validity period and scope are restricted by the expiration and cpHashA
// arguments. If the authorization is not bound to a specific session, the ticket will expire on
// the next TPM reset if this occurs before the calculated expiration time
func NewPolicyAuthorization(authKey Named, policyRef tpm2.Nonce, sessionAlg tpm2.HashAlgorithmId, nonceTPM tpm2.Nonce, cpHashA CpHash, expiration int32) (*PolicyAuthorization, error) {
	authName := authKey.Name()
	if !authName.IsValid() {
		return nil, errors.New("auth key name is invalid")
	}

	var cpDigest tpm2.Digest
	if cpHashA != nil {
		var err error
		cpDigest, err = cpHashA.Digest(sessionAlg)
		if err != nil {
			return nil, fmt.Errorf("cannot compute cpHash: %w", err)
		}
	}

	return &PolicyAuthorization{
		AuthName:   authName,
		PolicyRef:  policyRef,
		NonceTPM:   nonceTPM,
		CpHash:     cpDigest,
		Expiration: expiration}, nil
}

// Sign signs this authorization using the supplied signer and options. Note that only RSA-SSA,
// RSA-PSS, ECDSA and HMAC signatures can be created. The signer must be the owner of the key
// associated with the AuthName field.
//
// This will panic if the requested digest algorithm is not available.
func (a *PolicyAuthorization) Sign(rand io.Reader, signer crypto.Signer, opts crypto.SignerOpts) error {
	h := opts.HashFunc().New()
	mu.MustMarshalToWriter(h, mu.Raw(a.NonceTPM), a.Expiration, mu.Raw(a.CpHash), mu.Raw(a.PolicyRef))
	sig, err := cryptutil.Sign(rand, signer, h.Sum(nil), opts)
	if err != nil {
		return err
	}
	a.Signature = sig
	return nil
}

// SignPolicyAuthorization creates a signed authorization that can be used in a TPM2_PolicySigned
// assertion by using the [tpm2.TPMContext.PolicySigned] function. Note that only RSA-SSA, RSA-PSS,
// ECDSA and HMAC signatures can be created. The signer must be the owner of the key associated
// with the assertion. The policyRef argument binds the authorization to a specific assertion in a
// policy.
//
// The authorizing party chooses the values of the other arguments in order to limit the scope of
// the authorization.
//
// If nonceTPM is supplied, the authorization will be bound to the session with the specified TPM
// nonce. If it is not supplied, the authorization is not bound to a specific session.
//
// If cpHashA is supplied, the authorization will be bound to the corresponding command parameters.
// If it is not supplied, the authorization is not bound to any specific command parameters.
//
// If expiration is not zero, then the absolute value of this specifies an expiration time in
// seconds, after which the authorization will expire. If nonceTPM is also provided, the expiration
// time is measured from the time that nonceTPM was generated. If nonceTPM is not provided, the
// expiration time is measured from the time that this authorization is used in the
// TPM2_PolicySigned assertion.
//
// The expiration field can be used to request a ticket from the TPM by specifying a negative
// value. The ticket can be used to satisfy the corresponding TPM2_PolicySigned assertion in future
// sessions, and its validity period and scope are restricted by the expiration and cpHashA
// arguments. If the authorization is not bound to a specific session, the ticket will expire on
// the next TPM reset if this occurs before the calculated expiration time
//
// This will panic if the requested digest algorithm is not available.
func SignPolicyAuthorization(rand io.Reader, signer crypto.Signer, nonceTPM tpm2.Nonce, cpHashA tpm2.Digest, policyRef tpm2.Nonce, expiration int32, opts crypto.SignerOpts) (*tpm2.Signature, error) {
	h := opts.HashFunc().New()
	mu.MustMarshalToWriter(h, mu.Raw(nonceTPM), expiration, mu.Raw(cpHashA), mu.Raw(policyRef))
	return cryptutil.Sign(rand, signer, h.Sum(nil), opts)
}

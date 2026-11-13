// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package evetpm

import (
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"io"

	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

// TpmTCGEKHdl is where TCG Provisioning Guidance places a persisted RSA EK.
// EVE never writes it; a key found there is used only if it is a TCG EK.
const TpmTCGEKHdl tpmutil.Handle = 0x81010001

// errEKCertMismatch reports a derived EK that its NV certificate does not
// certify, e.g. a TPM provisioned with a non-default EK template.
var errEKCertMismatch = errors.New("EK certificate does not certify the derived EK")

// tcgEKTemplateECC is template L-2 of the TCG EK Credential Profile (B.3.4);
// DefaultEkTemplate is L-1.
var tcgEKTemplateECC = tpm2.Public{
	Type:       tpm2.AlgECC,
	NameAlg:    tpm2.AlgSHA256,
	Attributes: DefaultEkTemplate.Attributes,
	AuthPolicy: DefaultEkTemplate.AuthPolicy,
	ECCParameters: &tpm2.ECCParams{
		Symmetric: &tpm2.SymScheme{Alg: tpm2.AlgAES, KeyBits: 128, Mode: tpm2.AlgCFB},
		CurveID:   tpm2.CurveNISTP256,
		Point:     tpm2.ECPoint{XRaw: make([]byte, 32), YRaw: make([]byte, 32)},
	},
}

// ReadTCGEK returns the public area of the TPM's endorsement key for alg
// (tpm2.AlgRSA or tpm2.AlgECC): the endorsement-hierarchy primary created
// from the default TCG template, which the vendor's EK certificate certifies.
// EVE's key at TpmEKHdl is an owner-hierarchy key and is not this.
//
// The key is derived as a transient object and flushed; that takes about
// 300 ms on a discrete TPM, so callers should cache the result. If the
// derivation fails, e.g. because endorsement auth is set, a TCG EK persisted
// at TpmTCGEKHdl is used instead. If cert is non-nil, the key must be the
// certificate's.
func ReadTCGEK(rw io.ReadWriter, alg tpm2.Algorithm, cert *x509.Certificate) (tpm2.Public, error) {
	template, err := tcgEKTemplate(alg)
	if err != nil {
		return tpm2.Public{}, err
	}
	h, release, err := loadTCGEK(rw, template)
	if err != nil {
		return tpm2.Public{}, err
	}
	pub, _, _, err := tpm2.ReadPublic(rw, h)
	release()
	if err != nil {
		return tpm2.Public{}, err
	}
	if cert != nil {
		key, err := pub.Key()
		if err != nil {
			return tpm2.Public{}, err
		}
		eq, ok := cert.PublicKey.(interface{ Equal(crypto.PublicKey) bool })
		if !ok || !eq.Equal(key) {
			return tpm2.Public{}, errEKCertMismatch
		}
	}
	return pub, nil
}

// ActivateCredentialWithTCGEK runs TPM2_ActivateCredential for the AIK with
// the TCG EK ek, as returned by ReadTCGEK, and returns the recovered secret.
// credBlob and encSecret are the TPM2B_ID_OBJECT and TPM2B_ENCRYPTED_SECRET
// that TPM2_MakeCredential produced for ek and the AIK's Name.
func ActivateCredentialWithTCGEK(rw io.ReadWriter, ek tpm2.Public, credBlob, encSecret []byte) ([]byte, error) {
	cred, err := unpackTPM2B(credBlob)
	if err != nil {
		return nil, fmt.Errorf("%w: credential blob: %w", ErrCredentialActivation, err)
	}
	secret, err := unpackTPM2B(encSecret)
	if err != nil {
		return nil, fmt.Errorf("%w: encrypted secret: %w", ErrCredentialActivation, err)
	}
	template, err := tcgEKTemplate(ek.Type)
	if err != nil {
		return nil, err
	}
	h, release, err := loadTCGEK(rw, template)
	if err != nil {
		return nil, err
	}
	defer release()
	loaded, _, _, err := tpm2.ReadPublic(rw, h)
	if err != nil {
		return nil, err
	}
	loadedKey, err := loaded.Key()
	if err != nil {
		return nil, err
	}
	ekKey, err := ek.Key()
	if err != nil {
		return nil, err
	}
	if !loadedKey.(interface{ Equal(crypto.PublicKey) bool }).Equal(ekKey) {
		return nil, errors.New("loaded EK differs from the given EK")
	}

	// The TCG EK is adminWithPolicy with PolicySecret(TPM_RH_ENDORSEMENT).
	session, _, err := tpm2.StartAuthSession(rw, tpm2.HandleNull, tpm2.HandleNull,
		make([]byte, 16), nil, tpm2.SessionPolicy, tpm2.AlgNull, tpm2.AlgSHA256)
	if err != nil {
		return nil, fmt.Errorf("starting policy session: %w", err)
	}
	defer tpm2.FlushContext(rw, session) //nolint:errcheck
	pw := tpm2.AuthCommand{Session: tpm2.HandlePasswordSession, Attributes: tpm2.AttrContinueSession}
	if _, _, err := tpm2.PolicySecret(rw, tpm2.HandleEndorsement, pw, session,
		nil, nil, nil, 0); err != nil {
		return nil, fmt.Errorf("PolicySecret: %w", err)
	}
	out, err := tpm2.ActivateCredentialUsingAuth(rw,
		[]tpm2.AuthCommand{pw, {Session: session, Attributes: tpm2.AttrContinueSession}},
		TpmAIKHdl, h, cred, secret)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrCredentialActivation, err)
	}
	return out, nil
}

// ErrCredentialActivation reports a credential the TPM refused to activate,
// e.g. one made for another TPM's EK or another key's Name.
var ErrCredentialActivation = errors.New("TPM2_ActivateCredential failed")

func tcgEKTemplate(alg tpm2.Algorithm) (tpm2.Public, error) {
	switch alg {
	case tpm2.AlgRSA:
		return DefaultEkTemplate, nil
	case tpm2.AlgECC:
		return tcgEKTemplateECC, nil
	}
	return tpm2.Public{}, fmt.Errorf("no TCG EK template for algorithm %v", alg)
}

// loadTCGEK returns a handle to the TCG EK for template and a function that
// releases it: a transient primary in the endorsement hierarchy, or a TCG EK
// persisted at TpmTCGEKHdl if creating the primary fails.
func loadTCGEK(rw io.ReadWriter, template tpm2.Public) (tpmutil.Handle, func(), error) {
	h, _, err := tpm2.CreatePrimary(rw, tpm2.HandleEndorsement, tpm2.PCRSelection{},
		EmptyPassword, EmptyPassword, template)
	if err == nil {
		return h, func() { tpm2.FlushContext(rw, h) }, nil //nolint:errcheck
	}
	persisted, _, _, perr := tpm2.ReadPublic(rw, TpmTCGEKHdl)
	if perr != nil || !persisted.MatchesTemplate(template) {
		return 0, nil, fmt.Errorf("deriving EK: %w", err)
	}
	return TpmTCGEKHdl, func() {}, nil
}

func unpackTPM2B(b []byte) ([]byte, error) {
	if len(b) < 2 || int(b[0])<<8|int(b[1]) != len(b)-2 {
		return nil, errors.New("not a TPM2B: size prefix does not match length")
	}
	return b[2:], nil
}

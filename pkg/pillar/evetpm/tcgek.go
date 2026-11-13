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
	var template tpm2.Public
	switch alg {
	case tpm2.AlgRSA:
		template = DefaultEkTemplate
	case tpm2.AlgECC:
		template = tcgEKTemplateECC
	default:
		return tpm2.Public{}, fmt.Errorf("no TCG EK template for algorithm %v", alg)
	}
	pub, err := deriveEK(rw, template)
	if err != nil {
		persisted, _, _, perr := tpm2.ReadPublic(rw, TpmTCGEKHdl)
		if perr != nil || !persisted.MatchesTemplate(template) {
			return tpm2.Public{}, fmt.Errorf("deriving EK: %w", err)
		}
		pub = persisted
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

func deriveEK(rw io.ReadWriter, template tpm2.Public) (tpm2.Public, error) {
	h, _, err := tpm2.CreatePrimary(rw, tpm2.HandleEndorsement, tpm2.PCRSelection{},
		EmptyPassword, EmptyPassword, template)
	if err != nil {
		return tpm2.Public{}, err
	}
	defer tpm2.FlushContext(rw, h) //nolint:errcheck
	pub, _, _, err := tpm2.ReadPublic(rw, h)
	return pub, err
}

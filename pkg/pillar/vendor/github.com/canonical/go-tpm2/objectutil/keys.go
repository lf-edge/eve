// Copyright 2021 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package objectutil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"errors"
	"io"
	"math/big"

	"github.com/canonical/go-tpm2"
)

func zeroExtendBytes(x *big.Int, l int) (out []byte) {
	out = make([]byte, l)
	tmp := x.Bytes()
	copy(out[len(out)-len(tmp):], tmp)
	return
}

// NewRSAPublicKey returns a public area for the supplied RSA key which can be used to verify
// signatures. The public area can be customized with additional options.
//
// Without any options, the public area will have the following properties:
//   - SHA-256 for the name algorithm - customize with [WithNameAlg].
//   - No RSA scheme - customize with [WithRSAScheme].
//
// The returned public area can be loaded into a TPM with [tpm2.TPMContext.LoadExternal].
func NewRSAPublicKey(key *rsa.PublicKey, options ...PublicTemplateOption) (*tpm2.Public, error) {
	pub := &tpm2.Public{
		Type:    tpm2.ObjectTypeRSA,
		NameAlg: tpm2.HashAlgorithmSHA256,
		Attrs:   tpm2.AttrSign,
		Params: &tpm2.PublicParamsU{
			RSADetail: &tpm2.RSAParams{
				Symmetric: tpm2.SymDefObject{Algorithm: tpm2.SymObjectAlgorithmNull},
				Scheme:    tpm2.RSAScheme{Scheme: tpm2.RSASchemeNull}}}}
	applyPublicTemplateOptions(pub, options...)

	keyBits := uint16(key.N.BitLen())
	switch pub.Params.RSADetail.KeyBits {
	case 0:
		pub.Params.RSADetail.KeyBits = keyBits
	case keyBits:
		// ok
	default:
		return nil, errors.New("invalid RSA key bit length")
	}

	exponent := uint32(key.E)
	switch pub.Params.RSADetail.Exponent {
	case 0:
		pub.Params.RSADetail.Exponent = exponent
	case exponent:
		// ok
	default:
		return nil, errors.New("invalid RSA key exponent")
	}
	if pub.Params.RSADetail.Exponent == tpm2.DefaultRSAExponent {
		pub.Params.RSADetail.Exponent = 0
	}

	pub.Unique = &tpm2.PublicIDU{RSA: key.N.Bytes()}

	return pub, nil
}

// NewECCPublicKey returns a public area for the supplied elliptic key which can be used to verify
// signatures. The public area can be customized with additional options.
//
// Without any options, the public area will have the following properties:
//   - SHA-256 for the name algorithm - customize with [WithNameAlg].
//   - No ECC scheme - customize with [WithECCScheme].
//
// The returned public area can be loaded into a TPM with [tpm2.TPMContext.LoadExternal].
func NewECCPublicKey(key *ecdsa.PublicKey, options ...PublicTemplateOption) (*tpm2.Public, error) {
	var curve tpm2.ECCCurve
	switch key.Curve {
	case elliptic.P224():
		curve = tpm2.ECCCurveNIST_P224
	case elliptic.P256():
		curve = tpm2.ECCCurveNIST_P256
	case elliptic.P384():
		curve = tpm2.ECCCurveNIST_P384
	case elliptic.P521():
		curve = tpm2.ECCCurveNIST_P521
	default:
		return nil, errors.New("unsupported curve")
	}

	pub := &tpm2.Public{
		Type:    tpm2.ObjectTypeECC,
		NameAlg: tpm2.HashAlgorithmSHA256,
		Attrs:   tpm2.AttrSign,
		Params: &tpm2.PublicParamsU{
			ECCDetail: &tpm2.ECCParams{
				Symmetric: tpm2.SymDefObject{Algorithm: tpm2.SymObjectAlgorithmNull},
				Scheme:    tpm2.ECCScheme{Scheme: tpm2.ECCSchemeNull},
				KDF:       tpm2.KDFScheme{Scheme: tpm2.KDFAlgorithmNull}}}}
	applyPublicTemplateOptions(pub, options...)

	switch pub.Params.ECCDetail.CurveID {
	case tpm2.ECCCurve(0):
		pub.Params.ECCDetail.CurveID = curve
	case curve:
		// ok:
	default:
		return nil, errors.New("invalid elliptic curve")
	}

	pub.Unique = &tpm2.PublicIDU{
		ECC: &tpm2.ECCPoint{
			X: zeroExtendBytes(key.X, key.Params().BitSize/8),
			Y: zeroExtendBytes(key.Y, key.Params().BitSize/8)}}

	return pub, nil
}

// NewSealedObject returns a public and sensitive area for a sealed data object containing the
// supplied data and with the specified auth value. The supplied [io.Reader] is used to generate
// the seed parameter for the sensitive area. The public area can be customized with additional
// options.
//
// Without any options, the public area will have the following properties:
//   - SHA-256 for the name algorithm - customize with [WithNameAlg].
//   - Authorization with the object's auth value is permitted for both the user and admin roles -
//     customize with [WithUserAuthMode] and [WithAdminAuthMode].
//   - DA protected - customize with [WithDictionaryAttackProtection] and
//     [WithoutDictionaryAttackProtection].
//
// The returned public and sensitive area can be loaded into a TPM with
// [tpm2.TPMContext.LoadExternal] or imported into a hierarchy by creating an importable object
// with [CreateImportable].
func NewSealedObject(rand io.Reader, data []byte, authValue tpm2.Auth, options ...PublicTemplateOption) (*tpm2.Public, *tpm2.Sensitive, error) {
	pub := &tpm2.Public{
		Type:    tpm2.ObjectTypeKeyedHash,
		NameAlg: tpm2.HashAlgorithmSHA256,
		Attrs:   tpm2.AttrUserWithAuth,
		Params: &tpm2.PublicParamsU{
			KeyedHashDetail: &tpm2.KeyedHashParams{
				Scheme: tpm2.KeyedHashScheme{Scheme: tpm2.KeyedHashSchemeNull}}}}
	applyPublicTemplateOptions(pub, options...)

	if len(authValue) > pub.NameAlg.Size() {
		return nil, nil, errors.New("authValue too large")
	}

	sensitive := &tpm2.Sensitive{
		Type:      tpm2.ObjectTypeKeyedHash,
		AuthValue: make(tpm2.Auth, pub.NameAlg.Size()),
		SeedValue: make(tpm2.Digest, pub.NameAlg.Size()),
		Sensitive: &tpm2.SensitiveCompositeU{Bits: data}}
	copy(sensitive.AuthValue, authValue)

	if _, err := io.ReadFull(rand, sensitive.SeedValue); err != nil {
		return nil, nil, err
	}

	h := pub.NameAlg.NewHash()
	h.Write(sensitive.SeedValue)
	h.Write(sensitive.Sensitive.Bits)
	pub.Unique = &tpm2.PublicIDU{KeyedHash: h.Sum(nil)}

	return pub, sensitive, nil
}

// NewSymmetricKey returns a public and sensitive area for the supplied symmetric key with the
// specified usage and auth value. The supplied [io.Reader] is used to generate the seed parameter
// for the sensitive area. The public area can be customized with additional options.
//
// Without any options, the public area will have the following properties:
//   - SHA-256 for the name algorithm - customize with [WithNameAlg].
//   - Authorization with the object's auth value is permitted for both the user and admin roles -
//     customize with [WithUserAuthMode] and [WithAdminAuthMode].
//   - DA protected - customize with [WithDictionaryAttackProtection] and
//     [WithoutDictionaryAttackProtection].
//   - AES-128-CFB for the symmetric scheme - customize with [WithSymmetricScheme].
//
// The returned public and sensitive area can be loaded into a TPM with
// [tpm2.TPMContext.LoadExternal] or imported into a hierarchy by creating an importable object
// with [CreateImportable].
func NewSymmetricKey(rand io.Reader, usage Usage, key []byte, authValue tpm2.Auth, options ...PublicTemplateOption) (*tpm2.Public, *tpm2.Sensitive, error) {
	if usage == 0 {
		panic("invalid usage")
	}

	attrs := tpm2.AttrUserWithAuth
	if usage&UsageDecrypt != 0 {
		attrs |= tpm2.AttrDecrypt
	}
	if usage&UsageEncrypt != 0 {
		attrs |= tpm2.AttrSign
	}

	pub := &tpm2.Public{
		Type:    tpm2.ObjectTypeSymCipher,
		NameAlg: tpm2.HashAlgorithmSHA256,
		Attrs:   attrs,
		Params: &tpm2.PublicParamsU{
			SymDetail: &tpm2.SymCipherParams{
				Sym: tpm2.SymDefObject{
					Algorithm: tpm2.SymObjectAlgorithmAES,
					KeyBits:   new(tpm2.SymKeyBitsU),
					Mode:      &tpm2.SymModeU{Sym: tpm2.SymModeCFB}}}}}
	applyPublicTemplateOptions(pub, options...)

	symKeyBits := uint16(len(key) * 8)
	switch pub.Params.SymDetail.Sym.KeyBits.Sym {
	case 0:
		pub.Params.SymDetail.Sym.KeyBits.Sym = symKeyBits
	case symKeyBits:
		// ok
	default:
		return nil, nil, errors.New("invalid symmetric key length")
	}

	if len(authValue) > pub.NameAlg.Size() {
		return nil, nil, errors.New("authValue too large")
	}

	sensitive := &tpm2.Sensitive{
		Type:      tpm2.ObjectTypeSymCipher,
		AuthValue: make(tpm2.Auth, pub.NameAlg.Size()),
		SeedValue: make(tpm2.Digest, pub.NameAlg.Size()),
		Sensitive: &tpm2.SensitiveCompositeU{Sym: key}}
	copy(sensitive.AuthValue, authValue)

	if _, err := io.ReadFull(rand, sensitive.SeedValue); err != nil {
		return nil, nil, err
	}

	h := pub.NameAlg.NewHash()
	h.Write(sensitive.SeedValue)
	h.Write(sensitive.Sensitive.Sym)
	pub.Unique = &tpm2.PublicIDU{Sym: h.Sum(nil)}

	return pub, sensitive, nil
}

// NewHMACKey returns a public and sensitive area for the supplied HMAC key with the specified auth
// value. The supplied [io.Reader] is used to generate the seed parameter for the sensitive area.
// The public area can be customized with additional options.
//
// Without any options, the public area will have the following properties:
//   - SHA-256 for the name algorithm - customize with [WithNameAlg].
//   - Authorization with the object's auth value is permitted for both the user and admin roles -
//     customize with [WithUserAuthMode] and [WithAdminAuthMode].
//   - DA protected - customize with [WithDictionaryAttackProtection] and
//     [WithoutDictionaryAttackProtection].
//   - SHA-256 for the HMAC digest algorithm - customize with [WithHMACDigest].
//
// The returned public and sensitive area can be loaded into a TPM with
// [tpm2.TPMContext.LoadExternal] or imported into a hierarchy by creating an importable object
// with [CreateImportable].
func NewHMACKey(rand io.Reader, key []byte, authValue tpm2.Auth, options ...PublicTemplateOption) (*tpm2.Public, *tpm2.Sensitive, error) {
	pub := &tpm2.Public{
		Type:    tpm2.ObjectTypeKeyedHash,
		NameAlg: tpm2.HashAlgorithmSHA256,
		Attrs:   tpm2.AttrUserWithAuth | tpm2.AttrSign,
		Params: &tpm2.PublicParamsU{
			KeyedHashDetail: &tpm2.KeyedHashParams{
				Scheme: tpm2.KeyedHashScheme{
					Scheme: tpm2.KeyedHashSchemeHMAC,
					Details: &tpm2.SchemeKeyedHashU{
						HMAC: &tpm2.SchemeHMAC{HashAlg: tpm2.HashAlgorithmSHA256}}}}}}
	applyPublicTemplateOptions(pub, options...)

	if len(authValue) > pub.NameAlg.Size() {
		return nil, nil, errors.New("authValue too large")
	}

	sensitive := &tpm2.Sensitive{
		Type:      tpm2.ObjectTypeKeyedHash,
		AuthValue: make(tpm2.Auth, pub.NameAlg.Size()),
		SeedValue: make(tpm2.Digest, pub.NameAlg.Size()),
		Sensitive: &tpm2.SensitiveCompositeU{Bits: key}}
	copy(sensitive.AuthValue, authValue)

	if _, err := io.ReadFull(rand, sensitive.SeedValue); err != nil {
		return nil, nil, err
	}

	h := pub.NameAlg.NewHash()
	h.Write(sensitive.SeedValue)
	h.Write(sensitive.Sensitive.Bits)
	pub.Unique = &tpm2.PublicIDU{KeyedHash: h.Sum(nil)}

	return pub, sensitive, nil
}

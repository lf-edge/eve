// Copyright 2021 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

/*
Package templates is deprecated and shouldn't be used - use objectutil instead.
*/
package templates

import (
	"github.com/canonical/go-tpm2"
	"github.com/canonical/go-tpm2/objectutil"
)

type KeyUsage = objectutil.Usage

const (
	KeyUsageSign    = objectutil.UsageSign
	KeyUsageDecrypt = objectutil.UsageDecrypt

	KeyUsageEncrypt = objectutil.UsageEncrypt
)

// NewRSAStorageKey returns a template for a RSA storage parent with the specified
// name algorithm, symmetric cipher, symmetric key size and RSA key size. If nameAlg
// is HashAlgorithmNull, then HashAlgorithmSHA256 is used. If algorithm is
// SymObjectAlgorithmNull, then SymObjectAlgorithmAES is used. If symKeyBits is zero,
// then 128 is used. If asymKeyBits is zero, then 2048 is used.
//
// The template cannot be used to create a key in a duplication group. In order to create
// a key in a duplication group, remove the AttrFixedTPM attribute. In order to create
// a key that is a duplication root, remove both the AttrFixedTPM and AttrFixedParent
// attributes. In this case, an authorization policy that permits duplication must
// be added.
//
// The template has the AttrUserWithAuth set in order to permit authentication for
// the user auth role using the created object's authorization value. In order to
// require authentication for the user auth role using an authorization policy,
// remove the AttrUserWithAuth attribute.
//
// Deprecated: Use [objectutil.NewRSAStorageKeyTemplate].
func NewRSAStorageKey(nameAlg tpm2.HashAlgorithmId, algorithm tpm2.SymObjectAlgorithmId, symKeyBits, asymKeyBits uint16) *tpm2.Public {
	if nameAlg == tpm2.HashAlgorithmNull {
		nameAlg = tpm2.HashAlgorithmSHA256
	}
	if algorithm == tpm2.SymObjectAlgorithmNull {
		algorithm = tpm2.SymObjectAlgorithmAES
	}
	if symKeyBits == 0 {
		symKeyBits = 128
	}
	if asymKeyBits == 0 {
		asymKeyBits = 2048
	}

	return &tpm2.Public{
		Type:    tpm2.ObjectTypeRSA,
		NameAlg: nameAlg,
		Attrs:   tpm2.AttrFixedTPM | tpm2.AttrFixedParent | tpm2.AttrSensitiveDataOrigin | tpm2.AttrUserWithAuth | tpm2.AttrRestricted | tpm2.AttrDecrypt,
		Params: &tpm2.PublicParamsU{
			RSADetail: &tpm2.RSAParams{
				Symmetric: tpm2.SymDefObject{
					Algorithm: algorithm,
					KeyBits:   &tpm2.SymKeyBitsU{Sym: symKeyBits},
					Mode:      &tpm2.SymModeU{Sym: tpm2.SymModeCFB}},
				Scheme:   tpm2.RSAScheme{Scheme: tpm2.RSASchemeNull},
				KeyBits:  asymKeyBits,
				Exponent: 0}}}
}

// NewRSAStorageKeyWithDefaults returns a template for a RSA storage parent with
// SHA256 as the name algorithm, AES-128 as the symmetric cipher and 2048 bits as
// the RSA key size.
//
// The template cannot be used to create a key in a duplication group. In order to create
// a key in a duplication group, remove the AttrFixedTPM attribute. In order to create
// a key that is a duplication root, remove both the AttrFixedTPM and AttrFixedParent
// attributes. In this case, an authorization policy that permits duplication must
// be added.
//
// The template has the AttrUserWithAuth set in order to permit authentication for
// the user auth role using the created object's authorization value. In order to
// require authentication for the user auth role using an authorization policy,
// remove the AttrUserWithAuth attribute.
//
// Deprecated: Use [objectutil.NewRSAStorageKeyTemplate].
func NewRSAStorageKeyWithDefaults() *tpm2.Public {
	return NewRSAStorageKey(tpm2.HashAlgorithmNull, tpm2.SymObjectAlgorithmNull, 0, 0)
}

// NewRestrictedRSASigningKey returns a template for a restricted RSA signing
// key with the specified name algorithm, RSA scheme and RSA key size. If nameAlg
// is HashAlgorithmNull, then HashAlgorithmSHA256 is used. If scheme is nil, then
// RSASSA is used with the digest algorithm set to the same as the name
// algorithm. If keyBits is zero, then 2048 is used.
//
// The template cannot be used to create a key in a duplication group. In order to create
// a key in a duplication group, remove the AttrFixedTPM attribute. In order to create
// a key that is a duplication root, remove both the AttrFixedTPM and AttrFixedParent
// attributes. In this case, an authorization policy that permits duplication must
// be added.
//
// The template has the AttrUserWithAuth set in order to permit authentication for
// the user auth role using the created object's authorization value. In order to
// require authentication for the user auth role using an authorization policy,
// remove the AttrUserWithAuth attribute.
//
// Deprecated: Use [objectutil.NewRSAAttestationKeyTemplate].
func NewRestrictedRSASigningKey(nameAlg tpm2.HashAlgorithmId, scheme *tpm2.RSAScheme, keyBits uint16) *tpm2.Public {
	if nameAlg == tpm2.HashAlgorithmNull {
		nameAlg = tpm2.HashAlgorithmSHA256
	}
	if scheme == nil {
		scheme = &tpm2.RSAScheme{
			Scheme: tpm2.RSASchemeRSASSA,
			Details: &tpm2.AsymSchemeU{
				RSASSA: &tpm2.SigSchemeRSASSA{HashAlg: nameAlg}}}
	}
	if keyBits == 0 {
		keyBits = 2048
	}

	return &tpm2.Public{
		Type:    tpm2.ObjectTypeRSA,
		NameAlg: nameAlg,
		Attrs:   tpm2.AttrFixedTPM | tpm2.AttrFixedParent | tpm2.AttrSensitiveDataOrigin | tpm2.AttrUserWithAuth | tpm2.AttrSign | tpm2.AttrRestricted,
		Params: &tpm2.PublicParamsU{
			RSADetail: &tpm2.RSAParams{
				Symmetric: tpm2.SymDefObject{Algorithm: tpm2.SymObjectAlgorithmNull},
				Scheme:    *scheme,
				KeyBits:   keyBits,
				Exponent:  0}}}
}

// NewRestrictedRSASigningKeyWithDefaults returns a template for a restricted RSA
// signing key with SHA256 as the name algorithm, RSA-SSA with SHA256 as the scheme
// and 2048 bits as the key size.
//
// The template cannot be used to create a key in a duplication group. In order to create
// a key in a duplication group, remove the AttrFixedTPM attribute. In order to create
// a key that is a duplication root, remove both the AttrFixedTPM and AttrFixedParent
// attributes. In this case, an authorization policy that permits duplication must
// be added.
//
// The template has the AttrUserWithAuth set in order to permit authentication for
// the user auth role using the created object's authorization value. In order to
// require authentication for the user auth role using an authorization policy,
// remove the AttrUserWithAuth attribute.
//
// Deprecated: Use [objectutil.NewRSAAttestationKeyTemplate].
func NewRestrictedRSASigningKeyWithDefaults() *tpm2.Public {
	return NewRestrictedRSASigningKey(tpm2.HashAlgorithmNull, nil, 0)
}

// NewRSAKey returns a template for a general purpose RSA key for the specified
// usage, with the specified name algorithm, RSA scheme and RSA key size. If nameAlg
// is HashAlgorithmNull, then HashAlgorithmSHA256 is used. If keyBits is zero, then
// 2048 is used. If no usage is specified, the template will include both sign and
// decrypt attributes.
//
// The template cannot be used to create a key in a duplication group. In order to create
// a key in a duplication group, remove the AttrFixedTPM attribute. In order to create
// a key that is a duplication root, remove both the AttrFixedTPM and AttrFixedParent
// attributes. In this case, an authorization policy that permits duplication must
// be added.
//
// The template has the AttrUserWithAuth set in order to permit authentication for
// the user auth role using the created object's authorization value. In order to
// require authentication for the user auth role using an authorization policy,
// remove the AttrUserWithAuth attribute.
//
// Deprecated: Use [objectutil.NewRSAKeyTemplate].
func NewRSAKey(nameAlg tpm2.HashAlgorithmId, usage KeyUsage, scheme *tpm2.RSAScheme, keyBits uint16) *tpm2.Public {
	attrs := tpm2.AttrFixedTPM | tpm2.AttrFixedParent | tpm2.AttrSensitiveDataOrigin | tpm2.AttrUserWithAuth
	if usage == 0 {
		usage = KeyUsageSign | KeyUsageDecrypt
	}
	if usage&KeyUsageSign != 0 {
		attrs |= tpm2.AttrSign
	}
	if usage&KeyUsageDecrypt != 0 {
		attrs |= tpm2.AttrDecrypt
	}

	if nameAlg == tpm2.HashAlgorithmNull {
		nameAlg = tpm2.HashAlgorithmSHA256
	}
	if scheme == nil {
		scheme = &tpm2.RSAScheme{Scheme: tpm2.RSASchemeNull}
	}
	if keyBits == 0 {
		keyBits = 2048
	}

	return &tpm2.Public{
		Type:    tpm2.ObjectTypeRSA,
		NameAlg: nameAlg,
		Attrs:   attrs,
		Params: &tpm2.PublicParamsU{
			RSADetail: &tpm2.RSAParams{
				Symmetric: tpm2.SymDefObject{Algorithm: tpm2.SymObjectAlgorithmNull},
				Scheme:    *scheme,
				KeyBits:   keyBits,
				Exponent:  0}}}
}

// NewRSAKeyWithDefaults returns a template for a general purpose RSA key for the
// specified usage, with SHA256 as the name algorithm, the scheme unset and 2048 bits
// as the key size. If no usage is specified, the template will include both sign and
// decrypt attributes.
//
// The template cannot be used to create a key in a duplication group. In order to create
// a key in a duplication group, remove the AttrFixedTPM attribute. In order to create
// a key that is a duplication root, remove both the AttrFixedTPM and AttrFixedParent
// attributes. In this case, an authorization policy that permits duplication must
// be added.
//
// The template has the AttrUserWithAuth set in order to permit authentication for
// the user auth role using the created object's authorization value. In order to
// require authentication for the user auth role using an authorization policy,
// remove the AttrUserWithAuth attribute.
//
// Deprecated: Use [objectutil.NewRSAKeyTemplate].
func NewRSAKeyWithDefaults(usage KeyUsage) *tpm2.Public {
	return NewRSAKey(tpm2.HashAlgorithmNull, usage, nil, 0)
}

// NewSealedObject returns a template for a sealed object with the specified name
// algorithm. If nameAlg is HashAlgorithmNull, then HashAlgorithmSHA256 is used.
//
// The template cannot be used to create an object in a duplication group. In order to
// create an object in a duplication group, remove the AttrFixedTPM attribute. In
// order to create an object that can be moved to a new parent, remove both the
// AttrFixedTPM and AttrFixedParent attributes. In this case, an authorization policy
// that permits duplication must be added.
//
// The template has the AttrUserWithAuth set in order to permit authentication for
// the user auth role using the created object's authorization value. In order to
// require authentication for the user auth role using an authorization policy,
// remove the AttrUserWithAuth attribute.
//
// Deprecated: Use [objectutil.NewSealedObjectTemplate].
func NewSealedObject(nameAlg tpm2.HashAlgorithmId) *tpm2.Public {
	if nameAlg == tpm2.HashAlgorithmNull {
		nameAlg = tpm2.HashAlgorithmSHA256
	}
	return &tpm2.Public{
		Type:    tpm2.ObjectTypeKeyedHash,
		NameAlg: nameAlg,
		Attrs:   tpm2.AttrFixedTPM | tpm2.AttrFixedParent | tpm2.AttrUserWithAuth,
		Params: &tpm2.PublicParamsU{
			KeyedHashDetail: &tpm2.KeyedHashParams{
				Scheme: tpm2.KeyedHashScheme{Scheme: tpm2.KeyedHashSchemeNull}}}}
}

// NewECCStorageKey returns a template for a ECC storage parent with the specified
// name algorithm, symmetric cipher, symmetric key size and elliptic curve. If nameAlg
// is HashAlgorithmNull, then HashAlgorithmSHA256 is used. If algorithm is
// SymObjectAlgorithmNull, then SymObjectAlgorithmAES is used. If keyBits is zero,
// then 128 is used.
//
// The template cannot be used to create a key in a duplication group. In order to create
// a key in a duplication group, remove the AttrFixedTPM attribute. In order to create
// a key that is a duplication root, remove both the AttrFixedTPM and AttrFixedParent
// attributes. In this case, an authorization policy that permits duplication must
// be added.
//
// The template has the AttrUserWithAuth set in order to permit authentication for
// the user auth role using the created object's authorization value. In order to
// require authentication for the user auth role using an authorization policy,
// remove the AttrUserWithAuth attribute.
//
// Deprecated: Use [objectutil.NewECCStorageKeyTemplate].
func NewECCStorageKey(nameAlg tpm2.HashAlgorithmId, algorithm tpm2.SymObjectAlgorithmId, keyBits uint16, curve tpm2.ECCCurve) *tpm2.Public {
	if nameAlg == tpm2.HashAlgorithmNull {
		nameAlg = tpm2.HashAlgorithmSHA256
	}
	if algorithm == tpm2.SymObjectAlgorithmNull {
		algorithm = tpm2.SymObjectAlgorithmAES
	}
	if keyBits == 0 {
		keyBits = 128
	}

	return &tpm2.Public{
		Type:    tpm2.ObjectTypeECC,
		NameAlg: nameAlg,
		Attrs:   tpm2.AttrFixedTPM | tpm2.AttrFixedParent | tpm2.AttrSensitiveDataOrigin | tpm2.AttrUserWithAuth | tpm2.AttrRestricted | tpm2.AttrDecrypt,
		Params: &tpm2.PublicParamsU{
			ECCDetail: &tpm2.ECCParams{
				Symmetric: tpm2.SymDefObject{
					Algorithm: algorithm,
					KeyBits:   &tpm2.SymKeyBitsU{Sym: keyBits},
					Mode:      &tpm2.SymModeU{Sym: tpm2.SymModeCFB}},
				Scheme:  tpm2.ECCScheme{Scheme: tpm2.ECCSchemeNull},
				CurveID: curve,
				KDF:     tpm2.KDFScheme{Scheme: tpm2.KDFAlgorithmNull}}}}
}

// NewECCStorageKeyWithDefaults returns a template for a ECC storage parent with
// SHA256 as the name algorithm, AES-128 as the symmetric cipher and the NIST-P256
// curve.
//
// The template cannot be used to create a key in a duplication group. In order to create
// a key in a duplication group, remove the AttrFixedTPM attribute. In order to create
// a key that is a duplication root, remove both the AttrFixedTPM and AttrFixedParent
// attributes. In this case, an authorization policy that permits duplication must
// be added.
//
// The template has the AttrUserWithAuth set in order to permit authentication for
// the user auth role using the created object's authorization value. In order to
// require authentication for the user auth role using an authorization policy,
// remove the AttrUserWithAuth attribute.
//
// Deprecated: Use [objectutil.NewECCStorageKeyTemplate].
func NewECCStorageKeyWithDefaults() *tpm2.Public {
	return NewECCStorageKey(tpm2.HashAlgorithmNull, tpm2.SymObjectAlgorithmNull, 0, tpm2.ECCCurveNIST_P256)
}

// NewRestrictedECCSigningKey returns a template for a restricted ECC signing
// key with the specified name algorithm, ECC scheme and elliptic curve. If nameAlg
// is HashAlgorithmNull, then HashAlgorithmSHA256 is used. If scheme is nil, then
// ECDSA is used with the digest algorithm set to the same as the name algorithm.
//
// The template cannot be used to create a key in a duplication group. In order to create
// a key in a duplication group, remove the AttrFixedTPM attribute. In order to create
// a key that is a duplication root, remove both the AttrFixedTPM and AttrFixedParent
// attributes. In this case, an authorization policy that permits duplication must
// be added.
//
// The template has the AttrUserWithAuth set in order to permit authentication for
// the user auth role using the created object's authorization value. In order to
// require authentication for the user auth role using an authorization policy,
// remove the AttrUserWithAuth attribute.
//
// Deprecated: Use [objectutil.NewECCAttestationKeyTemplate].
func NewRestrictedECCSigningKey(nameAlg tpm2.HashAlgorithmId, scheme *tpm2.ECCScheme, curve tpm2.ECCCurve) *tpm2.Public {
	if nameAlg == tpm2.HashAlgorithmNull {
		nameAlg = tpm2.HashAlgorithmSHA256
	}
	if scheme == nil {
		scheme = &tpm2.ECCScheme{
			Scheme: tpm2.ECCSchemeECDSA,
			Details: &tpm2.AsymSchemeU{
				ECDSA: &tpm2.SigSchemeECDSA{HashAlg: nameAlg}}}
	}
	return &tpm2.Public{
		Type:    tpm2.ObjectTypeECC,
		NameAlg: nameAlg,
		Attrs:   tpm2.AttrFixedTPM | tpm2.AttrFixedParent | tpm2.AttrSensitiveDataOrigin | tpm2.AttrUserWithAuth | tpm2.AttrSign | tpm2.AttrRestricted,
		Params: &tpm2.PublicParamsU{
			ECCDetail: &tpm2.ECCParams{
				Symmetric: tpm2.SymDefObject{Algorithm: tpm2.SymObjectAlgorithmNull},
				Scheme:    *scheme,
				CurveID:   curve,
				KDF:       tpm2.KDFScheme{Scheme: tpm2.KDFAlgorithmNull}}}}
}

// NewRestrictedECCSigningKeyWithDefaults returns a template for a restricted ECC
// signing key with SHA256 as the name algorithm, ECDSA with SHA256 as the scheme and
// NIST-P256 as the curve.
//
// The template cannot be used to create a key in a duplication group. In order to create
// a key in a duplication group, remove the AttrFixedTPM attribute. In order to create
// a key that is a duplication root, remove both the AttrFixedTPM and AttrFixedParent
// attributes. In this case, an authorization policy that permits duplication must
// be added.
//
// The template has the AttrUserWithAuth set in order to permit authentication for
// the user auth role using the created object's authorization value. In order to
// require authentication for the user auth role using an authorization policy,
// remove the AttrUserWithAuth attribute.
//
// Deprecated: Use [objectutil.NewECCAttestationKeyTemplate].
func NewRestrictedECCSigningKeyWithDefaults() *tpm2.Public {
	return NewRestrictedECCSigningKey(tpm2.HashAlgorithmNull, nil, tpm2.ECCCurveNIST_P256)
}

// NewECCKey returns a template for a general purpose ECC key for the specified
// usage, with the specified name algorithm, ECC scheme and elliptic curve. If nameAlg
// is HashAlgorithmNull, then HashAlgorithmSHA256 is used. If no usage is specified,
// the template will include both sign and decrypt attributes.
//
// The template cannot be used to create a key in a duplication group. In order to create
// a key in a duplication group, remove the AttrFixedTPM attribute. In order to create
// a key that is a duplication root, remove both the AttrFixedTPM and AttrFixedParent
// attributes. In this case, an authorization policy that permits duplication must
// be added.
//
// The template has the AttrUserWithAuth set in order to permit authentication for
// the user auth role using the created object's authorization value. In order to
// require authentication for the user auth role using an authorization policy,
// remove the AttrUserWithAuth attribute.
//
// Deprecated: Use [objectutil.NewECCKeyTemplate].
func NewECCKey(nameAlg tpm2.HashAlgorithmId, usage KeyUsage, scheme *tpm2.ECCScheme, curve tpm2.ECCCurve) *tpm2.Public {
	attrs := tpm2.AttrFixedTPM | tpm2.AttrFixedParent | tpm2.AttrSensitiveDataOrigin | tpm2.AttrUserWithAuth
	if usage == 0 {
		usage = KeyUsageSign | KeyUsageDecrypt
	}
	if usage&KeyUsageSign != 0 {
		attrs |= tpm2.AttrSign
	}
	if usage&KeyUsageDecrypt != 0 {
		attrs |= tpm2.AttrDecrypt
	}

	if nameAlg == tpm2.HashAlgorithmNull {
		nameAlg = tpm2.HashAlgorithmSHA256
	}
	if scheme == nil {
		scheme = &tpm2.ECCScheme{Scheme: tpm2.ECCSchemeNull}
	}

	return &tpm2.Public{
		Type:    tpm2.ObjectTypeECC,
		NameAlg: nameAlg,
		Attrs:   attrs,
		Params: &tpm2.PublicParamsU{
			ECCDetail: &tpm2.ECCParams{
				Symmetric: tpm2.SymDefObject{Algorithm: tpm2.SymObjectAlgorithmNull},
				Scheme:    *scheme,
				CurveID:   curve,
				KDF:       tpm2.KDFScheme{Scheme: tpm2.KDFAlgorithmNull}}}}
}

// NewECCKeyWithDefaults returns a template for a general purpose ECC key for the
// specified usage, with SHA256 as the name algorithm, the scheme unset and NIST-P256
// as the curve. If no usage is specified, the template will include both sign and
// decrypt attributes.
//
// The template cannot be used to create a key in a duplication group. In order to create
// a key in a duplication group, remove the AttrFixedTPM attribute. In order to create
// a key that is a duplication root, remove both the AttrFixedTPM and AttrFixedParent
// attributes. In this case, an authorization policy that permits duplication must
// be added.
//
// The template has the AttrUserWithAuth set in order to permit authentication for
// the user auth role using the created object's authorization value. In order to
// require authentication for the user auth role using an authorization policy,
// remove the AttrUserWithAuth attribute.
//
// Deprecated: Use [objectutil.NewECCKeyTemplate].
func NewECCKeyWithDefaults(usage KeyUsage) *tpm2.Public {
	return NewECCKey(tpm2.HashAlgorithmNull, usage, nil, tpm2.ECCCurveNIST_P256)
}

// NewSymmetricStorageKey returns a template for a symmetric storage parent with the
// specified name algorithm, symmetric cipher and symmetric key size. If nameAlg
// is HashAlgorithmNull, then HashAlgorithmSHA256 is used. If algorithm is
// SymObjectAlgorithmNull, then SymObjectAlgorithmAES is used. If keyBits is zero,
// then 128 is used.
//
// The template cannot be used to create a key in a duplication group. In order to create
// a key in a duplication group, remove the AttrFixedTPM attribute. In order to create
// a key that is a duplication root, remove both the AttrFixedTPM and AttrFixedParent
// attributes. In this case, an authorization policy that permits duplication must
// be added.
//
// The template will create a TPM generated key. In order to supply the key, remove
// the AttrSensitiveDataOrigin attribute.
//
// The template has the AttrUserWithAuth set in order to permit authentication for
// the user auth role using the created object's authorization value. In order to
// require authentication for the user auth role using an authorization policy,
// remove the AttrUserWithAuth attribute.
//
// Deprecated: Use [objectutil.NewSymmetricStorageKeyTemplate].
func NewSymmetricStorageKey(nameAlg tpm2.HashAlgorithmId, algorithm tpm2.SymObjectAlgorithmId, keyBits uint16) *tpm2.Public {
	if nameAlg == tpm2.HashAlgorithmNull {
		nameAlg = tpm2.HashAlgorithmSHA256
	}
	if algorithm == tpm2.SymObjectAlgorithmNull {
		algorithm = tpm2.SymObjectAlgorithmAES
	}
	if keyBits == 0 {
		keyBits = 128
	}

	return &tpm2.Public{
		Type:    tpm2.ObjectTypeSymCipher,
		NameAlg: nameAlg,
		Attrs:   tpm2.AttrFixedTPM | tpm2.AttrFixedParent | tpm2.AttrSensitiveDataOrigin | tpm2.AttrUserWithAuth | tpm2.AttrRestricted | tpm2.AttrDecrypt,
		Params: &tpm2.PublicParamsU{
			SymDetail: &tpm2.SymCipherParams{
				Sym: tpm2.SymDefObject{
					Algorithm: algorithm,
					KeyBits:   &tpm2.SymKeyBitsU{Sym: keyBits},
					Mode:      &tpm2.SymModeU{Sym: tpm2.SymModeCFB}}}}}
}

// NewSymmetricStorageKeyWithDefaults returns a template for a symmetric storage
// parent with SHA256 as the name algorithm and AES-128 as the symmetric cipher.
//
// The template cannot be used to create a key in a duplication group. In order to create
// a key in a duplication group, remove the AttrFixedTPM attribute. In order to create
// a key that is a duplication root, remove both the AttrFixedTPM and AttrFixedParent
// attributes. In this case, an authorization policy that permits duplication must
// be added.
//
// The template will create a TPM generated key. In order to supply the key, remove
// the AttrSensitiveDataOrigin attribute.
//
// The template has the AttrUserWithAuth set in order to permit authentication for
// the user auth role using the created object's authorization value. In order to
// require authentication for the user auth role using an authorization policy,
// remove the AttrUserWithAuth attribute.
//
// Deprecated: Use [objectutil.NewSymmetricStorageKeyTemplate].
func NewSymmetricStorageKeyWithDefaults() *tpm2.Public {
	return NewSymmetricStorageKey(tpm2.HashAlgorithmNull, tpm2.SymObjectAlgorithmNull, 0)
}

// NewSymmetricKey returns a template for a general purpose symmetric key with
// the specified name algorithm, key usage, symmetic algorithm, symmetric key size
// and symmetric mode. If nameAlg is HashAlgorithmNull, then HashAlgorithmSHA256
// is used. If algorithm is SymObjectAlgorithmNull, then SymObjectAlgorithmAES is
// used. If keyBits is zero, then 128 is used. If no usage is specified, the template
// will include both sign and decrypt attributes.
//
// The template cannot be used to create a key in a duplication group. In order to create
// a key in a duplication group, remove the AttrFixedTPM attribute. In order to create
// a key that is a duplication root, remove both the AttrFixedTPM and AttrFixedParent
// attributes. In this case, an authorization policy that permits duplication must
// be added.
//
// The template will create a TPM generated key. In order to supply the key, remove
// the AttrSensitiveDataOrigin attribute.
//
// The template has the AttrUserWithAuth set in order to permit authentication for
// the user auth role using the created object's authorization value. In order to
// require authentication for the user auth role using an authorization policy,
// remove the AttrUserWithAuth attribute.
//
// Deprecated: Use [objectutil.NewSymmetricKeyTemplate].
func NewSymmetricKey(nameAlg tpm2.HashAlgorithmId, usage KeyUsage, algorithm tpm2.SymObjectAlgorithmId, keyBits uint16, mode tpm2.SymModeId) *tpm2.Public {
	attrs := tpm2.AttrFixedTPM | tpm2.AttrFixedParent | tpm2.AttrSensitiveDataOrigin | tpm2.AttrUserWithAuth
	if usage == 0 {
		usage = KeyUsageEncrypt | KeyUsageDecrypt
	}
	if usage&KeyUsageEncrypt != 0 {
		attrs |= tpm2.AttrSign
	}
	if usage&KeyUsageDecrypt != 0 {
		attrs |= tpm2.AttrDecrypt
	}

	if nameAlg == tpm2.HashAlgorithmNull {
		nameAlg = tpm2.HashAlgorithmSHA256
	}
	if algorithm == tpm2.SymObjectAlgorithmNull {
		algorithm = tpm2.SymObjectAlgorithmAES
	}
	if keyBits == 0 {
		keyBits = 128
	}

	return &tpm2.Public{
		Type:    tpm2.ObjectTypeSymCipher,
		NameAlg: nameAlg,
		Attrs:   attrs,
		Params: &tpm2.PublicParamsU{
			SymDetail: &tpm2.SymCipherParams{
				Sym: tpm2.SymDefObject{
					Algorithm: algorithm,
					KeyBits:   &tpm2.SymKeyBitsU{Sym: keyBits},
					Mode:      &tpm2.SymModeU{Sym: mode}}}}}
}

// NewSymmetricKeyWithDefaults returns a template for a general purpose symmetric
// key for the specified usage with SHA256 as the name algorithm, AES-128 as the
// cipher and CFB as the cipher mode. If no usage is specified, the template will
// include both sign and decrypt attributes.
//
// The template cannot be used to create a key in a duplication group. In order to create
// a key in a duplication group, remove the AttrFixedTPM attribute. In order to create
// a key that is a duplication root, remove both the AttrFixedTPM and AttrFixedParent
// attributes. In this case, an authorization policy that permits duplication must
// be added.
//
// The template will create a TPM generated key. In order to supply the key, remove
// the AttrSensitiveDataOrigin attribute.
//
// The template has the AttrUserWithAuth set in order to permit authentication for
// the user auth role using the created object's authorization value. In order to
// require authentication for the user auth role using an authorization policy,
// remove the AttrUserWithAuth attribute.
//
// Deprecated: Use [objectutil.NewSymmetricKeyTemplate].
func NewSymmetricKeyWithDefaults(usage KeyUsage) *tpm2.Public {
	return NewSymmetricKey(tpm2.HashAlgorithmNull, usage, tpm2.SymObjectAlgorithmNull, 0, tpm2.SymModeCFB)
}

// NewHMACKey returns a template for a HMAC key with the specified name algorithm
// and HMAC digest algorithm. If nameAlg is HashAlgorithmNull, then HashAlgorithmSHA256
// is used. If schemeAlg is HashAlgorithmNull, then nameAlg is used.
//
// The template cannot be used to create a key in a duplication group. In order to create
// a key in a duplication group, remove the AttrFixedTPM attribute. In order to create
// a key that is a duplication root, remove both the AttrFixedTPM and AttrFixedParent
// attributes. In this case, an authorization policy that permits duplication must
// be added.
//
// The template will create a TPM generated key. In order to supply the key, remove
// the AttrSensitiveDataOrigin attribute.
//
// The template has the AttrUserWithAuth set in order to permit authentication for
// the user auth role using the created object's authorization value. In order to
// require authentication for the user auth role using an authorization policy,
// remove the AttrUserWithAuth attribute.
//
// Deprecated: Use [objectutil.NewHMACKeyTemplate].
func NewHMACKey(nameAlg, schemeAlg tpm2.HashAlgorithmId) *tpm2.Public {
	if nameAlg == tpm2.HashAlgorithmNull {
		nameAlg = tpm2.HashAlgorithmSHA256
	}
	if schemeAlg == tpm2.HashAlgorithmNull {
		schemeAlg = nameAlg
	}

	return &tpm2.Public{
		Type:    tpm2.ObjectTypeKeyedHash,
		NameAlg: nameAlg,
		Attrs:   tpm2.AttrFixedTPM | tpm2.AttrFixedParent | tpm2.AttrSensitiveDataOrigin | tpm2.AttrUserWithAuth | tpm2.AttrSign,
		Params: &tpm2.PublicParamsU{
			KeyedHashDetail: &tpm2.KeyedHashParams{
				Scheme: tpm2.KeyedHashScheme{
					Scheme: tpm2.KeyedHashSchemeHMAC,
					Details: &tpm2.SchemeKeyedHashU{
						HMAC: &tpm2.SchemeHMAC{
							HashAlg: schemeAlg}}}}}}
}

// NewHMACKeyWithDefaults returns a template for a HMAC key with SHA256 as the
// name algorithm and the HMAC digest algorithm.
//
// The template cannot be used to create a key in a duplication group. In order to create
// a key in a duplication group, remove the AttrFixedTPM attribute. In order to create
// a key that is a duplication root, remove both the AttrFixedTPM and AttrFixedParent
// attributes. In this case, an authorization policy that permits duplication must
// be added.
//
// The template will create a TPM generated key. In order to supply the key, remove
// the AttrSensitiveDataOrigin attribute.
//
// The template has the AttrUserWithAuth set in order to permit authentication for
// the user auth role using the created object's authorization value. In order to
// require authentication for the user auth role using an authorization policy,
// remove the AttrUserWithAuth attribute.
//
// Deprecated: Use [objectutil.NewHMACKeyTemplate].
func NewHMACKeyWithDefaults() *tpm2.Public {
	return NewHMACKey(tpm2.HashAlgorithmNull, tpm2.HashAlgorithmNull)
}

// NewDerivationParentKey returns a template for derivation parent key with the
// specified name algorithm and KDF digest algorithm. If nameAlg is HashAlgorithmNull,
// then HashAlgorithmSHA256 is used. If schemeAlg is HashAlgorithmNull, then nameAlg
// is used.
//
// The template cannot be used to create a key in a duplication group. In order to create
// a key in a duplication group, remove the AttrFixedTPM attribute. In order to create
// a key that is a duplication root, remove both the AttrFixedTPM and AttrFixedParent
// attributes. In this case, an authorization policy that permits duplication must
// be added.
//
// The template will create a key with a TPM generated seed. In order to supply the
// seed, remove the AttrSensitiveDataOrigin attribute.
//
// The template has the AttrUserWithAuth set in order to permit authentication for
// the user auth role using the created object's authorization value. In order to
// require authentication for the user auth role using an authorization policy,
// remove the AttrUserWithAuth attribute.
//
// Deprecated: Use [objectutil.NewDerivationParentTemplate].
func NewDerivationParentKey(nameAlg, schemeAlg tpm2.HashAlgorithmId) *tpm2.Public {
	if nameAlg == tpm2.HashAlgorithmNull {
		nameAlg = tpm2.HashAlgorithmSHA256
	}
	if schemeAlg == tpm2.HashAlgorithmNull {
		schemeAlg = nameAlg
	}

	return &tpm2.Public{
		Type:    tpm2.ObjectTypeKeyedHash,
		NameAlg: nameAlg,
		Attrs:   tpm2.AttrFixedTPM | tpm2.AttrFixedParent | tpm2.AttrSensitiveDataOrigin | tpm2.AttrUserWithAuth | tpm2.AttrDecrypt | tpm2.AttrRestricted,
		Params: &tpm2.PublicParamsU{
			KeyedHashDetail: &tpm2.KeyedHashParams{
				Scheme: tpm2.KeyedHashScheme{
					Scheme: tpm2.KeyedHashSchemeXOR,
					Details: &tpm2.SchemeKeyedHashU{
						XOR: &tpm2.SchemeXOR{
							HashAlg: schemeAlg,
							KDF:     tpm2.KDFAlgorithmKDF1_SP800_108}}}}}}
}

// NewDerivationParentKeyWithDefaults returns a template for derivation parent key
// with SHA256 as the name algorithm and KDF digest algorithm.
//
// The template cannot be used to create a key in a duplication group. In order to create
// a key in a duplication group, remove the AttrFixedTPM attribute. In order to create
// a key that is a duplication root, remove both the AttrFixedTPM and AttrFixedParent
// attributes. In this case, an authorization policy that permits duplication must
// be added.
//
// The template will create a key with a TPM generated seed. In order to supply the
// seed, remove the AttrSensitiveDataOrigin attribute.
//
// The template has the AttrUserWithAuth set in order to permit authentication for
// the user auth role using the created object's authorization value. In order to
// require authentication for the user auth role using an authorization policy,
// remove the AttrUserWithAuth attribute.
//
// Deprecated: Use [objectutil.NewDerivationParentTemplate].
func NewDerivationParentKeyWithDefaults() *tpm2.Public {
	return NewDerivationParentKey(tpm2.HashAlgorithmNull, tpm2.HashAlgorithmNull)
}

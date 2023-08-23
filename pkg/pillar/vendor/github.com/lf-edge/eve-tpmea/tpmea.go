package tpmea

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"reflect"

	"github.com/canonical/go-tpm2"
	"github.com/canonical/go-tpm2/linux"
	"github.com/canonical/go-tpm2/policyutil"
	"github.com/canonical/go-tpm2/util"
)

const (
	TpmDevicePath = "/dev/tpmrm0"
)

type PCRHashAlgo int

const (
	AlgoSHA1   = PCRHashAlgo(0)
	AlgoSHA256 = PCRHashAlgo(1)
	AlgoSHA384 = PCRHashAlgo(2)
	AlgoSHA512 = PCRHashAlgo(3)
)

type PolicySignature struct {
	RSASignature  []byte
	ECCSignatureR []byte
	ECCSignatureS []byte
}

type PCR struct {
	Index  int
	Digest []byte
}

type PCRS []PCR

type PCRList struct {
	Pcrs PCRS
	Algo PCRHashAlgo
}

type RBP struct {
	Counter uint32
	Check   uint64
}

func getPCRAlgo(algo PCRHashAlgo) tpm2.HashAlgorithmId {
	switch algo {
	case AlgoSHA1:
		return tpm2.HashAlgorithmSHA1
	case AlgoSHA256:
		return tpm2.HashAlgorithmSHA256
	case AlgoSHA384:
		return tpm2.HashAlgorithmSHA384
	case AlgoSHA512:
		return tpm2.HashAlgorithmSHA512
	default:
		return tpm2.HashAlgorithmSHA256
	}
}

func getTpmHandle() (*tpm2.TPMContext, error) {
	tcti, err := linux.OpenDevice(TpmDevicePath)
	if err != nil {
		return nil, err
	}
	return tpm2.NewTPMContext(tcti), nil
}

func zeroExtendBytes(x *big.Int, l int) (out []byte) {
	out = make([]byte, l)
	tmp := x.Bytes()
	copy(out[len(out)-len(tmp):], tmp)
	return
}

func newExternalECCPub(key *ecdsa.PublicKey) tpm2.Public {
	return tpm2.Public{
		Type:    tpm2.ObjectTypeECC,
		NameAlg: tpm2.HashAlgorithmSHA256,
		Attrs:   tpm2.AttrDecrypt | tpm2.AttrSign | tpm2.AttrUserWithAuth,
		Params: &tpm2.PublicParamsU{
			ECCDetail: &tpm2.ECCParams{
				Symmetric: tpm2.SymDefObject{Algorithm: tpm2.SymObjectAlgorithmNull},
				Scheme:    tpm2.ECCScheme{Scheme: tpm2.ECCSchemeNull},
				CurveID:   tpm2.ECCCurveNIST_P256,
				KDF:       tpm2.KDFScheme{Scheme: tpm2.KDFAlgorithmNull}}},
		Unique: &tpm2.PublicIDU{
			ECC: &tpm2.ECCPoint{
				X: zeroExtendBytes(key.X, key.Params().BitSize/8),
				Y: zeroExtendBytes(key.Y, key.Params().BitSize/8)}}}
}

func newExternalRSAPub(key *rsa.PublicKey) tpm2.Public {
	return tpm2.Public{
		Type:    tpm2.ObjectTypeRSA,
		NameAlg: tpm2.HashAlgorithmSHA256,
		Attrs:   tpm2.AttrDecrypt | tpm2.AttrSign | tpm2.AttrUserWithAuth,
		Params: &tpm2.PublicParamsU{
			RSADetail: &tpm2.RSAParams{
				Symmetric: tpm2.SymDefObject{Algorithm: tpm2.SymObjectAlgorithmNull},
				Scheme:    tpm2.RSAScheme{Scheme: tpm2.RSASchemeNull},
				KeyBits:   2048,
				Exponent:  uint32(key.E)}},
		Unique: &tpm2.PublicIDU{RSA: key.N.Bytes()}}
}

func verifyPolicySignature(tpm *tpm2.TPMContext, publicKey crypto.PublicKey, policy []byte, policySig *PolicySignature) (*tpm2.TkVerified, tpm2.ResourceContext, error) {
	var (
		public    tpm2.Public
		signature *tpm2.Signature
	)
	switch p := publicKey.(type) {
	case *rsa.PublicKey:
		public = newExternalRSAPub(p)
		signature = &tpm2.Signature{
			SigAlg: tpm2.SigSchemeAlgRSASSA,
			Signature: &tpm2.SignatureU{
				RSASSA: &tpm2.SignatureRSASSA{
					Hash: tpm2.HashAlgorithmSHA256,
					Sig:  policySig.RSASignature}}}
	case *ecdsa.PublicKey:
		public = newExternalECCPub(p)
		signature = &tpm2.Signature{
			SigAlg: tpm2.SigSchemeAlgECDSA,
			Signature: &tpm2.SignatureU{
				ECDSA: &tpm2.SignatureECDSA{
					Hash:       tpm2.HashAlgorithmSHA256,
					SignatureR: policySig.ECCSignatureR,
					SignatureS: policySig.ECCSignatureS}}}
	default:
		return nil, nil, fmt.Errorf("invalid private key (neither RSA nor ECC)")
	}

	// null-hierarchy won't produce a valid ticket, go with owner
	keyCtx, err := tpm.LoadExternal(nil, &public, tpm2.HandleOwner)
	if err != nil {
		return nil, nil, err
	}

	// approvedPolicy by itself is a digest, but approvedPolicySignature is a
	// signature over digest of approvedPolicy (signature over digest of digest),
	// so compute it first.
	approvedPolicyDigest, err := util.ComputePolicyAuthorizeDigest(tpm2.HashAlgorithmSHA256, policy, nil)
	if err != nil {
		return nil, nil, err
	}

	// check the signature and produce a ticket if it's valid
	ticket, err := tpm.VerifySignature(keyCtx, approvedPolicyDigest, signature)
	if err != nil {
		return nil, nil, err
	}

	return ticket, keyCtx, nil
}

func authorizeObject(tpm *tpm2.TPMContext, publicKey crypto.PublicKey, policy []byte, policySig *PolicySignature, pcrs []int, rbp RBP) (tpm2.SessionContext, error) {
	ticket, keyCtx, err := verifyPolicySignature(tpm, publicKey, policy, policySig)
	if err != nil {
		return nil, err
	}
	defer tpm.FlushContext(keyCtx)

	// start a policy session, a policy session will actually evaluate commands
	// in comparison to trial policy that only computes the final digest whether
	// run-time state match the provided state or not.
	polss, err := tpm.StartAuthSession(nil, nil, tpm2.SessionTypePolicy, nil, tpm2.HashAlgorithmSHA256)
	if err != nil {
		return nil, err
	}

	if rbp != (RBP{}) {
		index, err := tpm.NewResourceContext(tpm2.Handle(rbp.Counter))
		if err != nil {
			return nil, err
		}

		// if rbp is provide, first check the PolicyNV then PolicyPCR, in this
		// case the two policy will from a logical AND (PolicyPCR AND PolicyPCR).
		operandB := make([]byte, 8)
		binary.BigEndian.PutUint64(operandB, rbp.Check)
		err = tpm.PolicyNV(tpm.OwnerHandleContext(), index, polss, operandB, 0, tpm2.OpUnsignedLE, nil)
		if err != nil {
			return nil, err
		}
	}

	pcrSelections := tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: pcrs}}
	err = tpm.PolicyPCR(polss, nil, pcrSelections)
	if err != nil {
		return nil, err
	}

	// authorize policy will check if policies hold at runtime (i.e PCR values
	// match the expected value and counter holds true on the arithmetic op)
	err = tpm.PolicyAuthorize(polss, policy, nil, keyCtx.Name(), ticket)
	if err != nil {
		return nil, err
	}

	return polss, nil
}

// DefineMonotonicCounter will define a monotonic NV counter at the given index,
// function will initialize the counter and returns the its current value.
//
// monotonic counters will retain their value and won't go away even if undefined,
// because of this if the handle already exist and it's attributes matches what
// we need, it will get initialized first if it is uninitialized, and then
// its current value is returned.
func DefineMonotonicCounter(handle uint32) (uint64, error) {
	tpm, err := getTpmHandle()
	if err != nil {
		return 0, err
	}
	defer tpm.Close()

	index, err := tpm.NewResourceContext(tpm2.Handle(handle))
	if err == nil {
		// probably handle already exists, read its attributes.
		nvpub, _, err := tpm.NVReadPublic(index)
		if err != nil {
			return 0, err
		}

		// check if the attributes match what we need, is so, just use the handle.
		attr := tpm2.AttrNVOwnerRead | tpm2.AttrNVOwnerWrite
		if (nvpub.Attrs & attr) != attr {
			return 0, errors.New("a counter at provide handle already exists with mismatched attributes")
		}

		// if it's not initialized, initialize it by increasing it.
		if (nvpub.Attrs & tpm2.AttrNVWritten) != tpm2.AttrNVWritten {
			err = tpm.NVIncrement(tpm.OwnerHandleContext(), index, nil)
			if err != nil {
				return 0, err
			}
		}

		counter, err := tpm.NVReadCounter(tpm.OwnerHandleContext(), index, nil)
		if err != nil {
			return 0, err
		}

		return counter, nil
	}

	// handle doesn't exists, create it with desired attributes.
	nvpub := tpm2.NVPublic{
		Index:   tpm2.Handle(handle),
		NameAlg: tpm2.HashAlgorithmSHA256,
		Attrs:   tpm2.NVTypeCounter.WithAttrs(tpm2.AttrNVOwnerRead | tpm2.AttrNVOwnerWrite),
		Size:    8}
	index, err = tpm.NVDefineSpace(tpm.OwnerHandleContext(), nil, &nvpub, nil)
	if err != nil {
		return 0, err
	}

	// increasing the counter is necessary to initialize it.
	err = tpm.NVIncrement(tpm.OwnerHandleContext(), index, nil)
	if err != nil {
		return 0, err
	}

	return 1, nil
}

// IncreaseMonotonicCounter will increase the value of the monotonic counter at
// provided index, by one and returns the new value.
func IncreaseMonotonicCounter(handle uint32) (uint64, error) {
	tpm, err := getTpmHandle()
	if err != nil {
		return 0, err
	}
	defer tpm.Close()

	index, err := tpm.NewResourceContext(tpm2.Handle(handle))
	if err != nil {
		return 0, err
	}

	err = tpm.NVIncrement(tpm.OwnerHandleContext(), index, nil)
	if err != nil {
		return 0, err
	}

	counter, err := tpm.NVReadCounter(tpm.OwnerHandleContext(), index, nil)
	if err != nil {
		return 0, err
	}

	return counter, nil
}

// SealSecret will write the provide secret to the TPM. The authDigest parameter
// binds the unseal operation with a singed policy that must gold true at run-time.
func SealSecret(handle uint32, authDigest []byte, secret []byte) error {
	if authDigest == nil || secret == nil {
		return fmt.Errorf("invalid parameter(s)")
	}

	tpm, err := getTpmHandle()
	if err != nil {
		return err
	}
	defer tpm.Close()

	// ignore error from NewResourceContext, maybe handle doesn't exist,
	// we catch other errors at NVDefineSpace anyways.
	index, err := tpm.NewResourceContext(tpm2.Handle(handle))
	if err == nil {
		err = tpm.NVUndefineSpace(tpm.OwnerHandleContext(), index, nil)
		if err != nil {
			return err
		}
	}

	nvpub := tpm2.NVPublic{
		Index:      tpm2.Handle(handle),
		NameAlg:    tpm2.HashAlgorithmSHA256,
		Attrs:      tpm2.NVTypeOrdinary.WithAttrs(tpm2.AttrNVPolicyRead | tpm2.AttrNVOwnerWrite | tpm2.AttrNVReadStClear),
		AuthPolicy: authDigest,
		Size:       uint16(len(secret))}
	index, err = tpm.NVDefineSpace(tpm.OwnerHandleContext(), nil, &nvpub, nil)
	if err != nil {
		return err
	}

	return tpm.NVWrite(tpm.OwnerHandleContext(), index, secret, 0, nil)
}

// UnsealSecret will read the secret from the TPM. To read the secret the
// approvedPolicy and approvedPolicySignature must be provided.
// If approvedPolicy is signed with the valid key and provided TPM states
// matches the run-time state of the TPM, the secret is returned.
func UnsealSecret(handle uint32, publicKey crypto.PublicKey, policy []byte, policySig *PolicySignature, pcrs []int, rbp RBP) ([]byte, error) {
	if publicKey == nil || policy == nil || policySig == nil {
		return nil, fmt.Errorf("invalid parameter(s)")
	}

	tpm, err := getTpmHandle()
	if err != nil {
		return nil, err
	}
	defer tpm.Close()

	// if the handle is not valid don't bother authorizing.
	index, err := tpm.NewResourceContext(tpm2.Handle(handle))
	if err != nil {
		return nil, err
	}

	// perform the TPM commands in order, this will work only if policy signature
	// is valid and session digest matches the auth (saved) digest of the object.
	polss, err := authorizeObject(tpm, publicKey, policy, policySig, pcrs, rbp)
	if err != nil {
		return nil, err
	}
	defer tpm.FlushContext(polss)

	// read the public area of NV to find out its size.
	pub, _, err := tpm.NVReadPublic(index)
	if err != nil {
		return nil, err
	}

	return tpm.NVRead(index, index, pub.Size, 0, polss)
}

// ActivateReadLock prevents further reading of the data from provided index,
// this restriction will gets deactivated on next tpm reset or restart.
func ActivateReadLock(handle uint32, publicKey crypto.PublicKey, policy []byte, policySig *PolicySignature, pcrs []int, rbp RBP) error {
	if publicKey == nil || policy == nil || policySig == nil {
		return fmt.Errorf("invalid parameter(s)")
	}

	tpm, err := getTpmHandle()
	if err != nil {
		return err
	}
	defer tpm.Close()

	// don't bother authorizing, if the handle is not valid
	index, err := tpm.NewResourceContext(tpm2.Handle(handle))
	if err != nil {
		return err
	}

	// perform the TPM commands in order, this will work only if policy signature
	// is valid and session digest matches the auth (saved) digest of the object.
	polss, err := authorizeObject(tpm, publicKey, policy, policySig, pcrs, rbp)
	if err != nil {
		return err
	}
	defer tpm.FlushContext(polss)

	return tpm.NVReadLock(index, index, polss)
}

// GenerateAuthDigest will generate a authorization digest based on the provided
// public key. The returned authorizationDigest is the basis for creating mutable
// TPM policies.
//
// It is not necessary to run this function on a real TPM, running it on a
// true-to-spec emulator like swtpm will work.
//
// This function should be called in the server side (attester, Challenger, etc).
func GenerateAuthDigest(publicKey crypto.PublicKey) (authDigest tpm2.Digest, err error) {
	if publicKey == nil {
		return nil, fmt.Errorf("invalid parameter(s)")
	}

	tpm, err := getTpmHandle()
	if err != nil {
		return nil, err
	}
	defer tpm.Close()

	// we generate the auth digest in a trial session, trial session won't
	// evaluate the states of TPM and we can get the final session digest
	// regardless of TPM state.
	triss, err := tpm.StartAuthSession(nil, nil, tpm2.SessionTypeTrial, nil, tpm2.HashAlgorithmSHA256)
	if err != nil {
		return nil, err
	}
	defer tpm.FlushContext(triss)

	var public tpm2.Public
	switch p := publicKey.(type) {
	case *rsa.PublicKey:
		public = newExternalRSAPub(p)
	case *ecdsa.PublicKey:
		public = newExternalECCPub(p)
	default:
		return nil, fmt.Errorf("invalid private key (neither RSA nor ECC)")
	}

	// load the public key into TPM
	keyCtx, err := tpm.LoadExternal(nil, &public, tpm2.HandleNull)
	if err != nil {
		return nil, err
	}
	defer tpm.FlushContext(keyCtx)

	// ask TPM to compute the session digest.
	err = tpm.PolicyAuthorize(triss, nil, nil, keyCtx.Name(), nil)
	if err != nil {
		return nil, err
	}

	// retrieve the session digest.
	return tpm.PolicyGetDigest(triss)
}

// GenerateSignedPolicy will compute the digest of PolicyNV and PolicyPCR and
// signs it using the provided key. It will return the approvedPolicy which
// represent the run-time state that the target TPM should match (i.e PCR values),
// and approvedPolicySignature which is the signature of the approvedPolicy that gets
// validated on the target TPM to match the key which is used to generate
// authorizationDigest from the call to GenerateAuthDigest.
//
// The private key must be belong to the pair that is used with GenerateAuthDigest.
//
// It is not necessary to run this function on a real TPM, running it on a
// true-to-spec emulator like swtpm will work.
//
// This function should be called in the server side (attester, Challenger, etc).
func GenerateSignedPolicy(privateKey crypto.PrivateKey, pcrList PCRList, rbp RBP) (policy []byte, policySig *PolicySignature, err error) {
	if privateKey == nil {
		return nil, nil, fmt.Errorf("invalid parameter(s)")
	}

	tpm, err := getTpmHandle()
	if err != nil {
		return nil, nil, err
	}
	defer tpm.Close()

	// we generate the policy digest in a trial session, because we don't want to
	// evaluate the provided state, we are only interested in the final session
	// digest that is computed as result of executing TPM commands, here the
	// commands are PolicyNV and PolicyPCR.
	triss, err := tpm.StartAuthSession(nil, nil, tpm2.SessionTypeTrial, nil, tpm2.HashAlgorithmSHA256)
	if err != nil {
		return nil, nil, err
	}
	defer tpm.FlushContext(triss)

	if rbp != (RBP{}) {
		index, err := tpm.NewResourceContext(tpm2.Handle(rbp.Counter))
		if err != nil {
			return nil, nil, err
		}

		// PolicyNV : index value <= operandB
		operandB := make([]byte, 8)
		binary.BigEndian.PutUint64(operandB, rbp.Check)
		err = tpm.PolicyNV(tpm.OwnerHandleContext(), index, triss, operandB, 0, tpm2.OpUnsignedLE, nil)
		if err != nil {
			return nil, nil, err
		}
	}

	sel := make([]int, 0)
	digests := make(map[int]tpm2.Digest)
	for _, pcr := range pcrList.Pcrs {
		sel = append(sel, pcr.Index)
		digests[pcr.Index] = pcr.Digest
	}

	pcrHashAlgo := getPCRAlgo(pcrList.Algo)
	pcrSelections := tpm2.PCRSelectionList{{Hash: pcrHashAlgo, Select: sel}}
	pcrValues := tpm2.PCRValues{pcrHashAlgo: digests}
	pcrDigests, err := policyutil.ComputePCRDigest(pcrHashAlgo, pcrSelections, pcrValues)
	if err != nil {
		return nil, nil, err
	}

	// PolicyPCR: runtime PCRs == pcrList
	err = tpm.PolicyPCR(triss, pcrDigests, pcrSelections)
	if err != nil {
		return nil, nil, err
	}

	// get the final session digest from TPM.
	policyDigest, err := tpm.PolicyGetDigest(triss)
	if err != nil {
		return nil, nil, err
	}

	switch p := privateKey.(type) {
	case *rsa.PrivateKey:
		_ = p
		scheme := tpm2.SigScheme{
			Scheme: tpm2.SigSchemeAlgRSASSA,
			Details: &tpm2.SigSchemeU{
				RSASSA: &tpm2.SigSchemeRSASSA{
					HashAlg: tpm2.HashAlgorithmSHA256}}}
		// util.PolicyAuthorize is not executing PolicyAuthorize TPM commands, it
		// just computes digest of policyDigest and signs it with provided key, bad
		// naming on the go-tpm2.
		_, s, err := util.PolicyAuthorize(privateKey, &scheme, policyDigest, nil)
		return policyDigest, &PolicySignature{RSASignature: s.Signature.RSASSA.Sig}, err
	case *ecdsa.PrivateKey:
		_ = p
		scheme := tpm2.SigScheme{
			Scheme: tpm2.SigSchemeAlgECDSA,
			Details: &tpm2.SigSchemeU{
				ECDSA: &tpm2.SigSchemeECDSA{
					HashAlg: tpm2.HashAlgorithmSHA256}}}
		// util.PolicyAuthorize is not executing PolicyAuthorize TPM commands, it
		// just computes digest of policyDigest and signs it with provided key, bad
		// naming on the go-tpm2.
		_, s, err := util.PolicyAuthorize(privateKey, &scheme, policyDigest, nil)
		return policyDigest, &PolicySignature{ECCSignatureR: s.Signature.ECDSA.SignatureR, ECCSignatureS: s.Signature.ECDSA.SignatureS}, err
	default:
		return nil, nil, fmt.Errorf("invalid private key (neither RSA nor ECC)")
	}
}

func hashPublicKey(publicKey crypto.PublicKey) ([]byte, error) {
	message, err := json.Marshal(publicKey)
	if err != nil {
		return nil, err
	}

	sh := crypto.SHA256.New()
	sh.Write(message)
	return sh.Sum(nil), nil
}

// rotateAuthDigestKeyWithKeySigning signs the new auth public key using the old one,
// and generates a new Authorization Digest using the new auth key.
//
// It is not necessary to run this function on a real TPM, running it on a
// true-to-spec emulator like swtpm will work.
//
// This function should be called in the server side  (attester, Challenger, etc).
func rotateAuthDigestKeyWithKeySigning(oldPrivateKey crypto.PrivateKey, newPrivateKey crypto.PrivateKey) (newSignature []byte, newAuthDigest tpm2.Digest, err error) {
	var public tpm2.Public
	var signature []byte
	switch p := oldPrivateKey.(type) {
	case *rsa.PrivateKey:
		newRSAPrivateKey, _ := newPrivateKey.(*rsa.PrivateKey)
		newRSAPublicKeyHash, err := hashPublicKey(newRSAPrivateKey.PublicKey)
		if err != nil {
			return nil, nil, err
		}
		public = newExternalRSAPub(&newRSAPrivateKey.PublicKey)
		signature, err = rsa.SignPKCS1v15(nil, p, crypto.SHA256, newRSAPublicKeyHash)
		if err != nil {
			return nil, nil, err
		}
	case *ecdsa.PrivateKey:
		newECCPrivateKey, _ := newPrivateKey.(*ecdsa.PrivateKey)
		newECCPublicKeyHash, err := hashPublicKey(newECCPrivateKey.PublicKey)
		if err != nil {
			return nil, nil, err
		}
		public = newExternalECCPub(&newECCPrivateKey.PublicKey)
		signature, err = ecdsa.SignASN1(rand.Reader, p, newECCPublicKeyHash)
		if err != nil {
			return nil, nil, err
		}
	}

	tpm, err := getTpmHandle()
	if err != nil {
		return nil, nil, err
	}
	defer tpm.Close()

	keyCtx, err := tpm.LoadExternal(nil, &public, tpm2.HandleNull)
	if err != nil {
		return nil, nil, err
	}
	defer tpm.FlushContext(keyCtx)

	// we generate the auth digest in a trial session, no evaluation in TPM is
	// required, we are only interested in the final session digest
	triss, err := tpm.StartAuthSession(nil, nil, tpm2.SessionTypeTrial, nil, tpm2.HashAlgorithmSHA256)
	if err != nil {
		return nil, nil, err
	}
	defer tpm.FlushContext(triss)

	// ask TPM to compute the session digest.
	err = tpm.PolicyAuthorize(triss, nil, nil, keyCtx.Name(), nil)
	if err != nil {
		return nil, nil, err
	}

	// retrieve it the session digest.
	digest, err := tpm.PolicyGetDigest(triss)
	if err != nil {
		return nil, nil, err
	}

	return signature, digest, nil
}

// RotateAuthDigestWithPolicy will first signs the new auth public key using
// the old one and generates a new Authorization Digest using the new auth key,
// then signs the policy using new key.
//
// It is not necessary to run this function on a real TPM, running it on a
// true-to-spec emulator like swtpm will work.
//
// This function should be called in the server side  (attester, Challenger, etc).
func RotateAuthDigestWithPolicy(oldPrivateKey crypto.PrivateKey, newPrivateKey crypto.PrivateKey, pcrList PCRList, rbp RBP) (newKeySig []byte, newAuthDigest tpm2.Digest, policyNewSig *PolicySignature, err error) {
	if oldPrivateKey == nil || newPrivateKey == nil {
		return nil, nil, nil, fmt.Errorf("invalid parameter(s)")
	}

	if reflect.ValueOf(oldPrivateKey).Kind() != reflect.ValueOf(newPrivateKey).Kind() {
		return nil, nil, nil, fmt.Errorf("both old and new public keys have to be of same type")
	}

	newKeySig, newAuthDigest, err = rotateAuthDigestKeyWithKeySigning(oldPrivateKey, newPrivateKey)
	if err != nil {
		return nil, nil, nil, err
	}

	_, policyNewSig, err = GenerateSignedPolicy(newPrivateKey, pcrList, rbp)
	if err != nil {
		return nil, nil, nil, err
	}

	return newKeySig, newAuthDigest, policyNewSig, nil
}

// VerifyNewAuthDigest verifies that the new key signed by the old key,
// this is needed when the target TPM is doing a Authorization Digest rotation
// using a new key.
func VerifyNewAuthDigest(oldPublicKey crypto.PublicKey, newPublicKey crypto.PublicKey, newKeySig []byte) error {
	if oldPublicKey == nil || newPublicKey == nil || newKeySig == nil {
		return fmt.Errorf("invalid parameter(s)")
	}

	if reflect.ValueOf(oldPublicKey).Kind() != reflect.ValueOf(newPublicKey).Kind() {
		return fmt.Errorf("both old and new public keys have to be of same type")
	}

	newPublicKeyHash, err := hashPublicKey(newPublicKey)
	if err != nil {
		return err
	}

	switch p := oldPublicKey.(type) {
	case *rsa.PublicKey:
		return rsa.VerifyPKCS1v15(p, crypto.SHA256, newPublicKeyHash, newKeySig)
	case *ecdsa.PublicKey:
		ok := ecdsa.VerifyASN1(p, newPublicKeyHash, newKeySig)
		if !ok {
			return fmt.Errorf("invalid new key signature")
		}
		return nil
	default:
		return fmt.Errorf("invalid private key (neither RSA nor ECC)")
	}
}

// SealSecretWithVerifiedAuthDigest will first validates the new key
// by calling VerifyNewAuthDigest, then reseals the secret using the new
// Authorization Digest that is bound to the new key, meaning subsequent unseal
// operations require policies that are signed with the new key.
func SealSecretWithVerifiedAuthDigest(handle uint32, oldPublicKey crypto.PublicKey, newPublicKey crypto.PublicKey, newKeySig []byte, newAuthDigest tpm2.Digest, secret []byte) error {
	if oldPublicKey == nil || newPublicKey == nil || newKeySig == nil || newAuthDigest == nil || secret == nil {
		return fmt.Errorf("invalid parameter(s)")
	}

	err := VerifyNewAuthDigest(oldPublicKey, newPublicKey, newKeySig)
	if err != nil {
		return err
	}

	return SealSecret(handle, newAuthDigest, secret)
}

// ResealTpmSecretWithVerifiedAuthDigest unseals the secret using old key and policies,
// then validation and key resealing using ResealSecretWithNewAuthDigestWithSecret.
// check out ResealSecretWithNewAuthDigestWithSecret for more information.
func ResealTpmSecretWithVerifiedAuthDigest(handle uint32, oldPublicKey crypto.PublicKey, newPublicKey crypto.PublicKey, newKeySig []byte, newAuthDigest tpm2.Digest, policy []byte, policySig *PolicySignature, pcrs []int, rbp RBP) error {
	if oldPublicKey == nil || newPublicKey == nil || newKeySig == nil || newAuthDigest == nil || policy == nil || policySig == nil {
		return fmt.Errorf("invalid parameter(s)")
	}

	secret, err := UnsealSecret(handle, oldPublicKey, policy, policySig, pcrs, rbp)
	if err != nil {
		return err
	}

	return SealSecretWithVerifiedAuthDigest(handle, oldPublicKey, newPublicKey, newKeySig, newAuthDigest, secret)
}

func ReadNVAuthDigest(handle uint32) ([]byte, error) {
	tpm, err := getTpmHandle()
	if err != nil {
		return nil, err
	}
	defer tpm.Close()

	index, err := tpm.NewResourceContext(tpm2.Handle(handle))
	if err != nil {
		return nil, err
	}

	info, _, err := tpm.NVReadPublic(index)
	if err != nil {
		return nil, err
	}

	return info.AuthPolicy, nil
}

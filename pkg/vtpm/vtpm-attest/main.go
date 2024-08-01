package main

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"fmt"
	"log"

	"github.com/google/go-tpm/legacy/tpm2"
	cred "github.com/google/go-tpm/legacy/tpm2/credactivation"
	"github.com/google/go-tpm/tpmutil"
)

// This is a restricted signing key, for vTPM guest usage
var defaultAikTemplate = tpm2.Public{
	Type:    tpm2.AlgRSA,
	NameAlg: tpm2.AlgSHA256,
	Attributes: tpm2.FlagFixedTPM | tpm2.FlagFixedParent |
		tpm2.FlagSensitiveDataOrigin | tpm2.FlagUserWithAuth |
		tpm2.FlagRestricted | tpm2.FlagSign | tpm2.FlagNoDA,
	RSAParameters: &tpm2.RSAParams{
		Sign: &tpm2.SigScheme{
			Alg:  tpm2.AlgRSASSA,
			Hash: tpm2.AlgSHA256,
		},
		KeyBits:    2048,
		ModulusRaw: make([]byte, 256),
	},
}

const TpmAIKHdl tpmutil.Handle = 0x81000003
const TpmEKHdl tpmutil.Handle = 0x81000001
const TpmDevicePath = "/dev/tpmrm0"
const EmptyPassword = ""

var pcrSelection = tpm2.PCRSelection{Hash: tpm2.AlgSHA256, PCRs: []int{7}}

func createKey(keyHandle, ownerHandle tpmutil.Handle, template tpm2.Public, overwrite bool) error {
	rw, err := tpm2.OpenTPM(TpmDevicePath)
	if err != nil {
		return fmt.Errorf("%v", err)
	}
	defer rw.Close()
	if !overwrite {
		//don't overwrite if key already exists, and if the attributes match up
		pub, _, _, err := tpm2.ReadPublic(rw, keyHandle)
		if err == nil && pub.Attributes == template.Attributes {
			fmt.Printf("Attributes match up, not re-creating 0x%X\n", keyHandle)
			return nil
		} else if err == nil {
			//key is present, but attributes not matching
			fmt.Printf("Attribute mismatch, re-creating 0x%X\n", keyHandle)
		} else {
			//key is not present
			fmt.Printf("key is not present, re-creating 0x%X\n", keyHandle)
		}
	}
	handle, pub, err := tpm2.CreatePrimary(rw,
		tpm2.HandleOwner,
		pcrSelection,
		EmptyPassword,
		EmptyPassword,
		template)
	if err != nil {
		return fmt.Errorf("create 0x%x failed: %s, do BIOS reset of TPM", keyHandle, err)
	}
	if err := tpm2.EvictControl(rw, EmptyPassword,
		tpm2.HandleOwner,
		keyHandle,
		keyHandle); err != nil {
		fmt.Printf("EvictControl failed: %v", err)
	}
	if err := tpm2.EvictControl(rw, EmptyPassword,
		tpm2.HandleOwner, handle,
		keyHandle); err != nil {
		return fmt.Errorf("EvictControl failed: %v, do BIOS reset of TPM", err)
	}

	// print pub
	fmt.Printf("Public: %v\n", pub)

	return nil
}

func main() {
	if err := createKey(TpmAIKHdl, tpm2.HandleOwner, defaultAikTemplate, false); err != nil {
		fmt.Printf("Error in creating Attestation key: %v\n", err)
	}

	rw, err := tpm2.OpenTPM(TpmDevicePath)
	if err != nil {
		fmt.Printf("%v\n", err)
		return
	}
	defer rw.Close()

	fmt.Println("///////////////////////////// 1- ON THE EVE SIDE ///////////////////////////////")
	// read HWTPM EK public blob
	ekPub, _, _, err := tpm2.ReadPublic(rw, TpmEKHdl)
	if err != nil {
		fmt.Printf("ReadPublic failed: %s\n", err)
		return
	}

	// read the HWTPM AIK pub blob and name (which is basically digest of the pub blob)
	var aikName tpmutil.U16Bytes
	aikPub, aikName, _, err := tpm2.ReadPublic(rw, TpmAIKHdl)
	if err != nil {
		fmt.Printf("ReadPublic failed: %s\n", err)
		return
	}
	b := &bytes.Buffer{}
	if err := aikName.TPMMarshal(b); err != nil {
		fmt.Printf("marshaling name: %v", err)
	}
	name, err := tpm2.DecodeName(bytes.NewBuffer(b.Bytes()))
	if err != nil {
		fmt.Printf("decoding name: %v\n", err)
		return
	}
	fmt.Printf("EK Public: %v\n", ekPub)
	fmt.Printf("AIK Public: %v\n", aikPub)
	fmt.Printf("AIK Name: %v\n", name)

	fmt.Println("///////////////////////////// 2- ON THE ATTESTOR SIDE ///////////////////////////////")
	// we get the HWTPM EK public blob, HWTPM AIK public blob and HWTPM AIK name from EVE
	// make sure calcultaed digest matches the digest in the HWTPM AIK name
	fmt.Printf("AIK Name: %v\n", name)
	h, err := name.Digest.Alg.Hash()
	if err != nil {
		log.Fatalf("failed to get name hash: %v", err)
	}
	p, _ := aikPub.Encode()
	aikPubHash := h.New()
	aikPubHash.Write(p)
	aikPubDigest := aikPubHash.Sum(nil)
	if !bytes.Equal(name.Digest.Value, aikPubDigest) {
		log.Fatalf("name was not for AIK public blob")
	}
	fmt.Printf("AIK Name matches AIK public blob\n")

	// now that digest is valid, make sure HWTPM AIK is restricted-in-tpm signing key
	if (aikPub.Attributes & tpm2.FlagFixedTPM) == 0 {
		fmt.Printf("AIK can be exported.\n")
	}
	if ((aikPub.Attributes & tpm2.FlagRestricted) == 0) ||
		((aikPub.Attributes & tpm2.FlagFixedParent) == 0) ||
		((aikPub.Attributes & tpm2.FlagSensitiveDataOrigin) == 0) {
		fmt.Printf("AIK is not a restricted signing key.\n")
	}
	fmt.Printf("AIK is a restricted signing key.\n")

	// create the credential, meaning bind the HWTPM AIK to HWTPM EK by:
	// 1. Generate a random seed
	// 2. Encrypt the seed with the HWTPM EK
	// 3. put the HWTPM AIK name and seed to a KDF to get the symmetric key
	// 4. Decrypt the nonce with the symmetric key to make the final "credential"
	credential := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf, 0x10}
	symBlockSize := int(ekPub.RSAParameters.Symmetric.KeyBits) / 8
	encKey, _ := ekPub.Key()
	credBlob, encryptedSecret, err := cred.Generate(name.Digest, encKey, symBlockSize, credential)
	if err != nil {
		fmt.Printf("MakeCredential failed: %s", err)
		return
	}
	fmt.Printf("Credential: %v\n", credential)

	fmt.Println("///////////////////////////// 3- ON THE EVE SIDE ///////////////////////////////")
	// activate the credential, meaning:
	// 1. Decrypt the encrypted seed with the HWTPM EK
	// 2. make sure a AIK with the provided name is present in the HWTPM (this a TPM spec guarantee)
	// 3. put the HWTPM AIK name and seed to a KDF to get the symmetric key
	// 4. Decrypt the nonce with the symmetric key to make the final "credential"
	recoveredCred, err := tpm2.ActivateCredential(rw, TpmAIKHdl, TpmEKHdl, EmptyPassword, EmptyPassword, credBlob[2:], encryptedSecret[2:])
	if err != nil {
		fmt.Printf("ActivateCredential failed: %s", err)
		return
	}
	fmt.Printf("Recovered credential: %v\n", recoveredCred)

	// sign the SWTPM EK using the HWTPM AIK
	data := []byte("assume this is SWTPM EK")
	digest, validation, err := tpm2.Hash(rw, tpm2.AlgSHA256, data, tpm2.HandleOwner)
	if err != nil {
		fmt.Printf("Hash failed: %s\n", err)
		return
	}
	sig, err := tpm2.Sign(rw, TpmAIKHdl, EmptyPassword, digest, validation, nil)
	if err != nil {
		fmt.Printf("Sign failed: %s\n", err)
		return
	}
	fmt.Printf("Signature: %v\n", sig)
	// send back the nonce and signature of SWTPM EK to the atte

	fmt.Println("///////////////////////////// 4- ON THE ATTESTOR SIDE ///////////////////////////////")
	// make sure the recovered credential matches the original credential
	if !bytes.Equal(credential, recoveredCred) {
		fmt.Printf("Credential mismatch")
		return
	}
	fmt.Printf("credential\t%v\n", credential)
	fmt.Printf("recoveredCred\t%v\n", recoveredCred)

	// make sure the signature is valid
	// verify the signature using the public key
	// verify the signature, this is not really neccasry
	sinerpub, _ := aikPub.Key()
	sinerpub2 := sinerpub.(*rsa.PublicKey)
	err = rsa.VerifyPKCS1v15(sinerpub2, crypto.SHA256, digest[:], sig.RSA.Signature)
	if err != nil {
		fmt.Printf("VerifyPKCS1v15 failed: %s\n", err)
		return
	}
	fmt.Printf("Signature verified\n")
}

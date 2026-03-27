// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// enc_seal.go contains modernized seal/unseal operations using the go-tpm v2 API
// with salted HMAC sessions and AES-128-CFB parameter encryption to protect
// sensitive data on the CPU-TPM bus.

package evetpm

import (
	"fmt"

	legacytpm2 "github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/lf-edge/eve/pkg/pillar/base"
)

func openTPM2() (transport.TPMCloser, error) {
	return transport.OpenTPM(TpmDevicePath)
}

func readEKPublic(t transport.TPM) (*tpm2.TPMTPublic, error) {
	rsp, err := (tpm2.ReadPublic{
		ObjectHandle: tpm2.TPMHandle(TpmEKHdl),
	}).Execute(t)
	if err != nil {
		return nil, fmt.Errorf("ReadPublic 0x%X: %w", TpmEKHdl, err)
	}
	pub, err := rsp.OutPublic.Contents()
	if err != nil {
		return nil, fmt.Errorf("EK public contents: %w", err)
	}
	return pub, nil
}

func readSRKName(t transport.TPM) (tpm2.TPM2BName, error) {
	rsp, err := (tpm2.ReadPublic{
		ObjectHandle: tpm2.TPMHandle(TpmSRKHdl),
	}).Execute(t)
	if err != nil {
		return tpm2.TPM2BName{}, fmt.Errorf("ReadPublic 0x%X: %w", TpmSRKHdl, err)
	}
	return rsp.Name, nil
}

// toTPMLPCRSelection converts a tpm2.PCRSelection to the
// tpm2.TPMLPCRSelection used by the go-tpm v2 API.
func toTPMLPCRSelection(pcrSel legacytpm2.PCRSelection) tpm2.TPMLPCRSelection {
	pcrs := make([]uint, len(pcrSel.PCRs))
	for i, p := range pcrSel.PCRs {
		pcrs[i] = uint(p)
	}
	return tpm2.TPMLPCRSelection{
		PCRSelections: []tpm2.TPMSPCRSelection{
			{
				Hash:      tpm2.TPMAlgSHA256,
				PCRSelect: tpm2.PCClientCompatible.PCRs(pcrs...),
			},
		},
	}
}

// tpmSupportsAES128CFB checks whether the TPM supports AES-128-CFB as a
// symmetric cipher. This is used to determine whether we can use encrypted
// sessions for sealing operations.
func tpmSupportsAES128CFB() bool {
	t, err := openTPM2()
	if err != nil {
		return false
	}
	defer t.Close()

	// Use TestParms to check for AES-128-CFB support
	_, err = (tpm2.TestParms{
		Parameters: tpm2.TPMTPublicParms{
			Type: tpm2.TPMAlgSymCipher,
			Parameters: tpm2.NewTPMUPublicParms(
				tpm2.TPMAlgSymCipher,
				&tpm2.TPMSSymCipherParms{
					Sym: tpm2.TPMTSymDefObject{
						Algorithm: tpm2.TPMAlgAES,
						KeyBits: tpm2.NewTPMUSymKeyBits(
							tpm2.TPMAlgAES,
							tpm2.TPMKeyBits(128),
						),
						Mode: tpm2.NewTPMUSymMode(
							tpm2.TPMAlgAES,
							tpm2.TPMAlgCFB,
						),
					},
				},
			),
		},
	}).Execute(t)

	return err == nil
}

// nvReadAll reads the entire contents of an NV index, using modern tpm2 APIs.
func nvReadAll(t transport.TPM, nvIndex tpm2.TPMHandle) ([]byte, error) {
	rpRsp, err := (tpm2.NVReadPublic{NVIndex: nvIndex}).Execute(t)
	if err != nil {
		return nil, fmt.Errorf("NVReadPublic 0x%X: %w", nvIndex, err)
	}
	pub, err := rpRsp.NVPublic.Contents()
	if err != nil {
		return nil, fmt.Errorf("NVReadPublic contents 0x%X: %w", nvIndex, err)
	}

	nvReadCmd := tpm2.NVRead{
		AuthHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHOwner,
			Auth:   tpm2.PasswordAuth(nil),
		},
		NVIndex: tpm2.NamedHandle{
			Handle: nvIndex,
			Name:   rpRsp.NVName,
		},
		Size:   pub.DataSize,
		Offset: 0,
	}
	readRsp, err := nvReadCmd.Execute(t)
	if err != nil {
		return nil, fmt.Errorf("NVRead 0x%X: %w", nvIndex, err)
	}
	return readRsp.Data.Buffer, nil
}

// unsealDiskKeyEncrypted unseals the disk key from TPM using a salted HMAC
// session and AES-128-CFB parameter encryption. The session salt is encrypted
// with the EK public key, so the unsealed plaintext key in the response is
// protected from passive bus snoopers.
func unsealDiskKeyEncrypted(pcrSel legacytpm2.PCRSelection) ([]byte, error) {
	t, err := openTPM2()
	if err != nil {
		return nil, err
	}
	defer t.Close()

	pcrSelection := toTPMLPCRSelection(pcrSel)
	ekPub, err := readEKPublic(t)
	if err != nil {
		return nil, err
	}
	srkName, err := readSRKName(t)
	if err != nil {
		return nil, err
	}

	// Read the sealed private and public blobs
	priv, err := nvReadAll(t, tpm2.TPMHandle(TpmSealedDiskPrivHdl))
	if err != nil {
		return nil, fmt.Errorf("reading sealed private blob: %w", err)
	}
	pub, err := nvReadAll(t, tpm2.TPMHandle(TpmSealedDiskPubHdl))
	if err != nil {
		return nil, fmt.Errorf("reading sealed public blob: %w", err)
	}

	// Load the sealed object under the SRK
	loadCmd := tpm2.Load{
		ParentHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMHandle(TpmSRKHdl),
			Name:   srkName,
			Auth:   tpm2.PasswordAuth(nil),
		},
		InPrivate: tpm2.TPM2BPrivate{Buffer: priv},
		InPublic:  tpm2.BytesAs2B[tpm2.TPMTPublic](pub),
	}
	loadRsp, err := loadCmd.Execute(t)
	if err != nil {
		return nil, fmt.Errorf("loading sealed object: %w", err)
	}
	defer (tpm2.FlushContext{FlushHandle: loadRsp.ObjectHandle}).Execute(t)

	// Create an encrypted policy session, salted with the EK
	sess, sessCloser, err := tpm2.PolicySession(t, tpm2.TPMAlgSHA256,
		16, /* nonce size */
		tpm2.Salted(tpm2.TPMHandle(TpmEKHdl), *ekPub),
		tpm2.AESEncryption(128, tpm2.EncryptOut),
	)
	if err != nil {
		return nil, fmt.Errorf("creating encrypted policy session: %w", err)
	}
	defer sessCloser()

	// Unseal using the PCR policy
	_, err = (tpm2.PolicyPCR{
		PolicySession: sess.Handle(),
		Pcrs:          pcrSelection,
	}).Execute(t)
	if err != nil {
		return nil, fmt.Errorf("PolicyPCR: %w", err)
	}
	unsealCmd := tpm2.Unseal{
		ItemHandle: tpm2.AuthHandle{
			Handle: loadRsp.ObjectHandle,
			Name:   loadRsp.Name,
			Auth:   sess,
		},
	}
	unsealRsp, err := unsealCmd.Execute(t)
	if err != nil {
		return nil, err
	}
	return unsealRsp.OutData.Buffer, nil
}

// sealDiskKeyEncrypted seals the key into TPM under the SRK with a PCR policy,
// using a salted HMAC session with AES-128-CFB parameter encryption.
// It mirrors sealDiskKeyLegacy in tpm.go but uses encrypted sessions.
func sealDiskKeyEncrypted(log *base.LogObject, key []byte, pcrSel legacytpm2.PCRSelection) error {
	t, err := openTPM2()
	if err != nil {
		return err
	}
	defer t.Close()

	// Clean up any stale NV indices
	nvUndefine(t, tpm2.TPMHandle(TpmSealedDiskPubHdl))
	nvUndefine(t, tpm2.TPMHandle(TpmSealedDiskPrivHdl))

	pcrSelection := toTPMLPCRSelection(pcrSel)
	ekPub, err := readEKPublic(t)
	if err != nil {
		return err
	}
	srkName, err := readSRKName(t)
	if err != nil {
		return err
	}

	// Create a trial session to compute the policy digest
	trialSess, trialCloser, err := tpm2.PolicySession(t, tpm2.TPMAlgSHA256, 16, tpm2.Trial())
	if err != nil {
		return fmt.Errorf("creating trial policy session: %w", err)
	}
	defer trialCloser()

	_, err = (tpm2.PolicyPCR{
		PolicySession: trialSess.Handle(),
		Pcrs:          pcrSelection,
	}).Execute(t)
	if err != nil {
		return fmt.Errorf("PolicyPCR (trial): %w", err)
	}

	pgdRsp, err := (tpm2.PolicyGetDigest{
		PolicySession: trialSess.Handle(),
	}).Execute(t)
	if err != nil {
		return fmt.Errorf("PolicyGetDigest: %w", err)
	}
	policyDigest := pgdRsp.PolicyDigest

	// Seal the key under the SRK with the computed policy
	createCmd := tpm2.Create{
		ParentHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMHandle(TpmSRKHdl),
			Name:   srkName,
			Auth: tpm2.HMAC(tpm2.TPMAlgSHA256, 16,
				tpm2.Salted(tpm2.TPMHandle(TpmEKHdl), *ekPub),
				tpm2.AESEncryption(128, tpm2.EncryptIn),
			),
		},
		InSensitive: tpm2.TPM2BSensitiveCreate{
			Sensitive: &tpm2.TPMSSensitiveCreate{
				Data: tpm2.NewTPMUSensitiveCreate(
					&tpm2.TPM2BSensitiveData{Buffer: key},
				),
			},
		},
		InPublic: tpm2.New2B(tpm2.TPMTPublic{
			Type:    tpm2.TPMAlgKeyedHash,
			NameAlg: tpm2.TPMAlgSHA256,
			ObjectAttributes: tpm2.TPMAObject{
				FixedTPM:    true,
				FixedParent: true,
			},
			AuthPolicy: policyDigest,
		}),
	}
	createRsp, err := createCmd.Execute(t)
	if err != nil {
		return fmt.Errorf("Create (seal): %w", err)
	}

	// Store the inner bytes (without TPM2B size prefix) to match legacy format.
	// Legacy tpm2.Seal() returns tpmutil.U16Bytes which are the inner contents
	// of TPM2B_PRIVATE and TPM2B_PUBLIC respectively.
	priv := createRsp.OutPrivate.Buffer
	public := tpm2.Marshal(createRsp.OutPublic)
	if len(public) >= 2 {
		public = public[2:]
	}

	if err := nvWriteBlob(t, tpm2.TPMHandle(TpmSealedDiskPrivHdl), priv); err != nil {
		return fmt.Errorf("writing sealed private blob: %w", err)
	}
	if err := nvWriteBlob(t, tpm2.TPMHandle(TpmSealedDiskPubHdl), public); err != nil {
		return fmt.Errorf("writing sealed public blob: %w", err)
	}

	return nil
}

// nvWriteBlob defines an NV index and writes a blob into it.
func nvWriteBlob(t transport.TPM, nvIndex tpm2.TPMHandle, data []byte) error {
	defCmd := tpm2.NVDefineSpace{
		AuthHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHOwner,
			Auth:   tpm2.PasswordAuth(nil),
		},
		PublicInfo: tpm2.New2B(tpm2.TPMSNVPublic{
			NVIndex: nvIndex,
			NameAlg: tpm2.TPMAlgSHA256,
			Attributes: tpm2.TPMANV{
				OwnerWrite: true,
				OwnerRead:  true,
				NT:         tpm2.TPMNTOrdinary,
			},
			DataSize: uint16(len(data)),
		}),
	}
	if _, err := defCmd.Execute(t); err != nil {
		return fmt.Errorf("NVDefineSpace 0x%X: %w", nvIndex, err)
	}

	rpRsp, err := (tpm2.NVReadPublic{NVIndex: nvIndex}).Execute(t)
	if err != nil {
		return fmt.Errorf("NVReadPublic 0x%X: %w", nvIndex, err)
	}

	writeCmd := tpm2.NVWrite{
		AuthHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHOwner,
			Auth:   tpm2.PasswordAuth(nil),
		},
		NVIndex: tpm2.NamedHandle{
			Handle: nvIndex,
			Name:   rpRsp.NVName,
		},
		Data: tpm2.TPM2BMaxNVBuffer{Buffer: data},
	}
	if _, err := writeCmd.Execute(t); err != nil {
		return fmt.Errorf("NVWrite 0x%X: %w", nvIndex, err)
	}
	return nil
}

// nvUndefine removes an NV index, ignoring errors (for cleanup).
func nvUndefine(t transport.TPM, nvIndex tpm2.TPMHandle) {
	rpRsp, err := (tpm2.NVReadPublic{NVIndex: nvIndex}).Execute(t)
	if err != nil {
		// index doesn't exist
		return
	}
	(tpm2.NVUndefineSpace{
		AuthHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHOwner,
			Auth:   tpm2.PasswordAuth(nil),
		},
		NVIndex: tpm2.NamedHandle{
			Handle: nvIndex,
			Name:   rpRsp.NVName,
		},
	}).Execute(t)
}

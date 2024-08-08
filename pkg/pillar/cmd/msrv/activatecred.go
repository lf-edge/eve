// Copyright (c) 2023 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package msrv

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
	etpm "github.com/lf-edge/eve/pkg/pillar/evetpm"
)

// TPMDevicePath is the path to the TPM device, we use a variable here so that
// we can override it in the tests.
var TPMDevicePath = etpm.TpmDevicePath

// ActivateCredTpmParam provides the parameters required to activate the
// TPM credential using EK and AIK.
type ActivateCredTpmParam struct {
	Ek      string `json:"ek"`
	AikPub  string `json:"aikpub"`
	AikName string `json:"aikname"`
}

// ActivateCredGenerated contains the generated credential and data to sign.
type ActivateCredGenerated struct {
	Data   string `json:"data"`
	Cred   string `json:"cred"`
	Secret string `json:"secret"`
}

// ActivateCredActivated contains the activated credential (decrypted secret)
// and signature of the ActivateCredGenerated.Data.
type ActivateCredActivated struct {
	Secret string `json:"secret"`
	Sig    string `json:"sig"`
}

// handles the GET request /tmp/activate-credential/, this is used to get the
// TPM's EK public key, AIK public key and AIK name.
func getActivateCredentialParams() ([]byte, []byte, []byte, error) {
	rw, err := tpm2.OpenTPM(TPMDevicePath)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to open TPM: %w", err)
	}
	defer rw.Close()

	ekPub, _, _, err := tpm2.ReadPublic(rw, etpm.TpmEKHdl)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to read EK public: %w", err)
	}

	ekPubByte, err := ekPub.Encode()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to encode EK public: %w", err)
	}

	var aikName tpmutil.U16Bytes
	aikPub, aikName, _, err := tpm2.ReadPublic(rw, etpm.TpmAIKHdl)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to read AIK public: %w", err)
	}

	aikPubByte, err := aikPub.Encode()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to encode AIK public: %w", err)
	}

	aikNameMarshaled := &bytes.Buffer{}
	if err := aikName.TPMMarshal(aikNameMarshaled); err != nil {
		return nil, nil, nil, fmt.Errorf("failed to marshal AIK name: %w", err)
	}

	return ekPubByte, aikPubByte, aikNameMarshaled.Bytes(), nil
}

// handles the POST request /tmp/activate-credential/, this is used to activate
// the credential (decrypt the secret) using EK and AIK.
func activateCredential(jsonData []byte) ([]byte, []byte, error) {
	rw, err := tpm2.OpenTPM(TPMDevicePath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to open TPM: %w", err)
	}
	defer rw.Close()

	var credPayload ActivateCredGenerated
	if err := json.Unmarshal(jsonData, &credPayload); err != nil {
		return nil, nil, fmt.Errorf("failed to unmarshal credential payload: %w", err)
	}

	credBlob, err := base64.StdEncoding.DecodeString(credPayload.Cred)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode credential blob: %w", err)
	}

	encryptedSecret, err := base64.StdEncoding.DecodeString(credPayload.Secret)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode encrypted secret: %w", err)
	}

	// we need to skip the first 2 bytes of the credBlob and encryptedSecret
	// as it contains the type. so make sure the length is greater than 2.
	if len(credBlob) < 2 || len(encryptedSecret) < 2 {
		return nil, nil, fmt.Errorf("invalid credential blob or encrypted secret")
	}
	credBlob = credBlob[2:]
	encryptedSecret = encryptedSecret[2:]

	// start the auth session
	session, _, err := tpm2.StartAuthSession(rw,
		tpm2.HandleNull,
		tpm2.HandleNull,
		make([]byte, 16),
		nil,
		tpm2.SessionPolicy,
		tpm2.AlgNull,
		tpm2.AlgSHA256)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to start auth session: %w", err)
	}

	// set the auth session policy, this is equal to empty password, but needed anyways.
	auth := tpm2.AuthCommand{Session: tpm2.HandlePasswordSession, Attributes: tpm2.AttrContinueSession}
	_, _, err = tpm2.PolicySecret(rw,
		tpm2.HandleEndorsement,
		auth,
		session,
		nil, nil, nil, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("policy secret failed: %w", err)
	}

	// activate the credential using the auth session
	auths := []tpm2.AuthCommand{auth, {Session: session, Attributes: tpm2.AttrContinueSession}}
	recoveredCred, err := tpm2.ActivateCredentialUsingAuth(rw,
		auths,
		etpm.TpmAIKHdl,
		etpm.TpmEKHdl,
		credBlob,
		encryptedSecret)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to activate credential: %w", err)
	}

	dataToSign, err := base64.StdEncoding.DecodeString(credPayload.Data)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode data to sign: %w", err)
	}

	digest, validation, err := tpm2.Hash(rw, tpm2.AlgSHA256, dataToSign, tpm2.HandleOwner)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to hash data: %w", err)
	}

	sig, err := tpm2.Sign(rw, etpm.TpmAIKHdl, etpm.EmptyPassword, digest, validation, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to sign data: %w", err)
	}

	return recoveredCred, sig.RSA.Signature, nil
}

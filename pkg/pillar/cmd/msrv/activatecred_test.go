// Copyright (c) 2023 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package msrv_test

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/legacy/tpm2/credactivation"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/cmd/msrv"
	etpm "github.com/lf-edge/eve/pkg/pillar/evetpm"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/onsi/gomega"
	"github.com/sirupsen/logrus"
)

const TpmSimPath = "/tmp/eve-tpm/srv.sock"

var log = base.NewSourceLogObject(logrus.StandardLogger(), "acitavatecred", 1234)

func waitForTpmReadyState() error {
	for i := 0; i < 10; i++ {
		rw, err := tpm2.OpenTPM(msrv.TPMDevicePath)
		if err != nil {
			return fmt.Errorf("Failed to open TPM: %w", err)
		}

		_, _, err = tpm2.GetCapability(rw, tpm2.CapabilityHandles, 1, uint32(tpm2.HandleTypeTransient)<<24)
		if err != nil {
			// this is RCRetry, so retry
			if strings.Contains(err.Error(), "code 0x22") {
				time.Sleep(100 * time.Millisecond)
				continue
			} else {
				return fmt.Errorf("Something is wrong with the TPM : %w", err)
			}
		} else {
			return nil
		}
	}

	return fmt.Errorf("TPM did't become ready after 10 attempts, failing the test")
}

func isTpmAvailable(path string) bool {
	_, err := os.Stat(path)
	if err != nil {
		log.Warnf("TPM device %s is not available: %v", msrv.TPMDevicePath, err)
		return false
	}
	return true
}

func prepareTPM() error {
	//Make sure the TPM is ready for use, swtpm takes some time to become ready
	if err := waitForTpmReadyState(); err != nil {
		return fmt.Errorf("Failed to wait for TPM ready state: %w", err)
	}

	// Create EK and AIK in case it is not already created
	err := etpm.CreateKey(log, msrv.TPMDevicePath, etpm.TpmEKHdl, tpm2.HandleEndorsement, etpm.DefaultEkTemplate, false)
	if err != nil {
		return fmt.Errorf("error in creating Endorsement key: %w ", err)
	}
	err = etpm.CreateKey(log, msrv.TPMDevicePath, etpm.TpmAIKHdl, tpm2.HandleOwner, etpm.DefaultAikTemplate, false)
	if err != nil {
		return fmt.Errorf("error in creating Attestation key: %w ", err)
	}

	return nil
}

// TestTpmActivateCred contains TPM kong-fu, not for the faint of heart.
func TestTpmActivateCred(t *testing.T) {
	t.Parallel()
	g := gomega.NewGomegaWithT(t)

	if !isTpmAvailable(msrv.TPMDevicePath) {
		// no TPM device available, check for TPM socket, see if we ended up
		// here from tests/tpm/prep-and-test.sh script.
		if !isTpmAvailable(TpmSimPath) {
			t.Skip("Neither HW or SW TPM device available, skipping the test")
		}

		// set the TPM device path to swtpm socket path
		msrv.TPMDevicePath = TpmSimPath

		// make sure TPM is prepare it before running the test.
		err := prepareTPM()
		g.Expect(err).ToNot(gomega.HaveOccurred())
	}

	logger := logrus.StandardLogger()
	log := base.NewSourceLogObject(logger, "pubsub", 1234)
	ps := pubsub.New(pubsub.NewMemoryDriver(), logger, log)

	srv := &msrv.Msrv{
		Log:    log,
		PubSub: ps,
		Logger: logger,
	}

	dir, err := os.MkdirTemp("/tmp", "msrv_test")
	g.Expect(err).ToNot(gomega.HaveOccurred())
	defer os.RemoveAll(dir)

	err = srv.Init(dir, true)
	g.Expect(err).ToNot(gomega.HaveOccurred())

	err = srv.Activate()
	g.Expect(err).ToNot(gomega.HaveOccurred())

	handler := srv.MakeMetadataHandler()

	// Get the activate credential parameters
	pCred := httptest.NewRequest(http.MethodGet, "/eve/v1/tpm/activatecredential/", nil)
	pCred.RemoteAddr = "192.168.1.1:0"
	pCredRec := httptest.NewRecorder()

	handler.ServeHTTP(pCredRec, pCred)
	defer pCredRec.Body.Reset()
	g.Expect(pCredRec.Code).To(gomega.Equal(http.StatusOK))

	var credParam msrv.ActivateCredTpmParam
	err = json.Unmarshal(pCredRec.Body.Bytes(), &credParam)
	g.Expect(err).ToNot(gomega.HaveOccurred())

	// Decode the EK back to tpm2.Public, in practices you need to find a
	// way to trust EK using decive cert or OEM cert or whatever.
	eKBytes, err := base64.StdEncoding.DecodeString(credParam.Ek)
	g.Expect(err).ToNot(gomega.HaveOccurred())

	ekPub, err := tpm2.DecodePublic(eKBytes)
	g.Expect(err).ToNot(gomega.HaveOccurred())

	// Decode the name back to name tpm2.Name
	nameBytes, err := base64.StdEncoding.DecodeString(credParam.AikName)
	g.Expect(err).ToNot(gomega.HaveOccurred())

	name, err := tpm2.DecodeName(bytes.NewBuffer(nameBytes))
	g.Expect(err).ToNot(gomega.HaveOccurred())

	// Decode the AIK back to tpm2.Public
	aikBytes, err := base64.StdEncoding.DecodeString(credParam.AikPub)
	g.Expect(err).ToNot(gomega.HaveOccurred())

	aikPub, err := tpm2.DecodePublic(aikBytes)
	g.Expect(err).ToNot(gomega.HaveOccurred())

	// Verify the name matches the AIK
	nameHash, err := name.Digest.Alg.Hash()
	g.Expect(err).ToNot(gomega.HaveOccurred())

	p, err := aikPub.Encode()
	g.Expect(err).ToNot(gomega.HaveOccurred())

	aikPubHash := nameHash.New()
	aikPubHash.Write(p)
	aikPubDigest := aikPubHash.Sum(nil)
	g.Expect(bytes.Equal(name.Digest.Value, aikPubDigest)).To(gomega.BeTrue())

	// Verify the AIK is a restricted signing key
	g.Expect((aikPub.Attributes & tpm2.FlagFixedTPM)).To(gomega.BeEquivalentTo(tpm2.FlagFixedTPM))
	g.Expect((aikPub.Attributes & tpm2.FlagRestricted)).To(gomega.BeEquivalentTo(tpm2.FlagRestricted))
	g.Expect((aikPub.Attributes & tpm2.FlagFixedParent)).To(gomega.BeEquivalentTo(tpm2.FlagFixedParent))
	g.Expect((aikPub.Attributes & tpm2.FlagSensitiveDataOrigin)).To(gomega.BeEquivalentTo(tpm2.FlagSensitiveDataOrigin))

	// Generate a credential
	encKey, err := ekPub.Key()
	g.Expect(err).ToNot(gomega.HaveOccurred())

	dataToSign := []byte("Data to sign")
	credential := make([]byte, 32)
	rand.Read(credential)
	symBlockSize := int(ekPub.RSAParameters.Symmetric.KeyBits) / 8
	credBlob, encryptedSecret, err := credactivation.Generate(name.Digest, encKey, symBlockSize, credential)
	g.Expect(err).ToNot(gomega.HaveOccurred())

	var activeCredParam msrv.ActivateCredGenerated
	activeCredParam.Cred = base64.StdEncoding.EncodeToString(credBlob)
	activeCredParam.Secret = base64.StdEncoding.EncodeToString(encryptedSecret)
	activeCredParam.Data = base64.StdEncoding.EncodeToString(dataToSign)
	jsonStr, err := json.Marshal(activeCredParam)
	g.Expect(err).ToNot(gomega.HaveOccurred())

	// Ask TPM to activate (decrypt) the credential
	aCred := httptest.NewRequest(http.MethodPost, "/eve/v1/tpm/activatecredential/", bytes.NewBuffer(jsonStr))
	aCred.RemoteAddr = "192.168.1.1:0"
	aCredRec := httptest.NewRecorder()

	handler.ServeHTTP(aCredRec, aCred)
	defer aCredRec.Body.Reset()
	g.Expect(aCredRec.Code).To(gomega.Equal(http.StatusOK))

	var actCred msrv.ActivateCredActivated
	err = json.Unmarshal(aCredRec.Body.Bytes(), &actCred)
	g.Expect(err).ToNot(gomega.HaveOccurred())

	recovered, err := base64.StdEncoding.DecodeString(actCred.Secret)
	g.Expect(err).ToNot(gomega.HaveOccurred())

	g.Expect(bytes.Equal(recovered, credential)).To(gomega.BeTrue())

	// Verify the the signature
	sig, err := base64.StdEncoding.DecodeString(actCred.Sig)
	g.Expect(err).ToNot(gomega.HaveOccurred())

	dataHash := crypto.SHA256.New()
	dataHash.Write(dataToSign)
	dataDigest := dataHash.Sum(nil)

	sinerPubKey, err := aikPub.Key()
	g.Expect(err).ToNot(gomega.HaveOccurred())

	sinerPub := sinerPubKey.(*rsa.PublicKey)
	err = rsa.VerifyPKCS1v15(sinerPub, crypto.SHA256, dataDigest[:], sig)
	g.Expect(err).ToNot(gomega.HaveOccurred())
}

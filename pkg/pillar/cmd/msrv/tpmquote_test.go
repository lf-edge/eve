// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package msrv

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/legacy/tpm2/credactivation"
	"github.com/lf-edge/eve/pkg/pillar/base"
	etpm "github.com/lf-edge/eve/pkg/pillar/evetpm"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/onsi/gomega"
	uuid "github.com/satori/go.uuid"
	"github.com/sirupsen/logrus"
)

// TestTpmQuote needs a swtpm provisioned like tests/tpm/prep-and-test.sh,
// with an EK certificate at 0x01c00002.
func TestTpmQuote(t *testing.T) {
	g := gomega.NewGomegaWithT(t)
	TPMDevicePath = etpm.SimTpmPath
	if !etpm.SimTpmAvailable() {
		t.Skip("SWTPM device not available, skipping the test")
	}
	g.Expect(etpm.SimTpmWaitForTpmReadyState()).To(gomega.Succeed())

	dir := t.TempDir()
	eventLog := []byte("test event log")
	tpmEventLogPath = filepath.Join(t.TempDir(), "eventlog")
	g.Expect(os.WriteFile(tpmEventLogPath, eventLog, 0o600)).To(gomega.Succeed())
	tpmInUse = func() bool { return true }

	logger := logrus.StandardLogger()
	log := base.NewSourceLogObject(logger, "tpmquote_test", os.Getpid())
	ps := pubsub.New(pubsub.NewMemoryDriver(), logger, log)
	pub, err := ps.NewPublication(pubsub.PublicationOptions{
		AgentName:  "zedrouter",
		TopicType:  types.AppNetworkStatus{},
		Persistent: true,
	})
	g.Expect(err).ToNot(gomega.HaveOccurred())
	appUUID := uuid.FromStringOrNil("6ba7b810-9dad-11d1-80b4-000000000000")
	err = pub.Publish(appUUID.String(), types.AppNetworkStatus{
		UUIDandVersion: types.UUIDandVersion{UUID: appUUID, Version: "1.0"},
		DisplayName:    "vllm",
		AppNetAdapterList: []types.AppNetAdapterStatus{{
			AssignedAddresses: types.AssignedAddrs{IPv4Addrs: []types.AssignedAddr{
				{Address: net.ParseIP("192.168.1.1")}}},
		}},
	})
	g.Expect(err).ToNot(gomega.HaveOccurred())

	srv := &Msrv{Log: log, PubSub: ps, Logger: logger}
	g.Expect(srv.Init(dir, true)).To(gomega.Succeed())
	g.Expect(srv.Activate()).To(gomega.Succeed())
	handler := srv.MakeMetadataHandler()

	do := func(method, path, from string, body []byte) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, bytes.NewReader(body))
		req.RemoteAddr = from + ":0"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec
	}

	// Identity: part description, AIK, EK certificate and its chain.
	rec := do(http.MethodGet, "/eve/v1/tpm/identity", "10.0.0.9", nil)
	g.Expect(rec.Code).To(gomega.Equal(http.StatusOK), rec.Body.String())
	var id etpm.TpmIdentity
	g.Expect(json.Unmarshal(rec.Body.Bytes(), &id)).To(gomega.Succeed())
	t.Logf("TPM %s (%s) model %q firmware %s, %d EK certs, %d chain certs",
		id.Manufacturer, id.ManufacturerID, id.Model, id.FirmwareVersion,
		len(id.EKCertificates), len(id.EKCertChain))
	g.Expect(id.ManufacturerID).ToNot(gomega.BeEmpty())
	g.Expect(id.FirmwareVersion).ToNot(gomega.BeEmpty())
	g.Expect(id.AIKHierarchy).To(gomega.Equal("owner"))
	g.Expect(id.EKCertificates).To(gomega.HaveLen(1))
	g.Expect(id.EKCertificates[0].Index).To(gomega.Equal(uint32(etpm.TpmEKCertRSAHdl)))
	ekCert, err := x509.ParseCertificate(id.EKCertificates[0].DER)
	g.Expect(err).ToNot(gomega.HaveOccurred())
	ekPub, err := tpm2.DecodePublic(id.EKPublic)
	g.Expect(err).ToNot(gomega.HaveOccurred())
	ekKey, err := ekPub.Key()
	g.Expect(err).ToNot(gomega.HaveOccurred())
	g.Expect(ekCert.PublicKey.(*rsa.PublicKey).Equal(ekKey)).To(gomega.BeTrue(),
		"EK certificate does not certify the EK")
	g.Expect(id.EKCertChain).To(gomega.HaveLen(1))
	ca, err := x509.ParseCertificate(id.EKCertChain[0])
	g.Expect(err).ToNot(gomega.HaveOccurred())
	g.Expect(ekCert.CheckSignatureFrom(ca)).To(gomega.Succeed())
	g.Expect(id.EKCertificates[0].IssuerURLs).To(gomega.Equal(ekCert.IssuingCertificateURL))
	g.Expect(id.EKCertificates[0].IssuerURLs).To(gomega.HaveLen(1))

	// aik_name is the Name of aik_public, and the AIK is a restricted
	// signing key.
	aikName, err := tpm2.DecodeName(bytes.NewBuffer(id.AIKName))
	g.Expect(err).ToNot(gomega.HaveOccurred())
	g.Expect(aikName.Digest.Alg).To(gomega.Equal(tpm2.AlgSHA256))
	aikPubDigest := sha256.Sum256(id.AIKPublic)
	g.Expect([]byte(aikName.Digest.Value)).To(gomega.Equal(aikPubDigest[:]))
	aikPub, err := tpm2.DecodePublic(id.AIKPublic)
	g.Expect(err).ToNot(gomega.HaveOccurred())
	g.Expect(aikPub.NameAlg).To(gomega.Equal(tpm2.AlgSHA256))
	aikAttrs := tpm2.FlagRestricted | tpm2.FlagSign | tpm2.FlagFixedTPM | tpm2.FlagFixedParent
	g.Expect(aikPub.Attributes & aikAttrs).To(gomega.Equal(aikAttrs))

	// Credential activation with that EK proves the AIK is in the same TPM.
	activate := func(ek crypto.PublicKey, secret []byte) *httptest.ResponseRecorder {
		blob, encSecret, err := credactivation.Generate(aikName.Digest, ek, 16, secret)
		g.Expect(err).ToNot(gomega.HaveOccurred())
		body, err := json.Marshal(TpmActivateRequest{CredentialBlob: blob, EncryptedSecret: encSecret})
		g.Expect(err).ToNot(gomega.HaveOccurred())
		return do(http.MethodPost, "/eve/v1/tpm/activate", "10.0.0.9", body)
	}
	secret := []byte("0123456789abcdef0123456789abcdef")
	rec = activate(ekKey, secret)
	g.Expect(rec.Code).To(gomega.Equal(http.StatusOK), rec.Body.String())
	var act TpmActivateResponse
	g.Expect(json.Unmarshal(rec.Body.Bytes(), &act)).To(gomega.Succeed())
	g.Expect(act.Secret).To(gomega.Equal(secret))

	// EVE's owner-hierarchy key at TpmEKHdl cannot activate it.
	rw, err := tpm2.OpenTPM(etpm.SimTpmPath)
	g.Expect(err).ToNot(gomega.HaveOccurred())
	ownerEK, _, _, err := tpm2.ReadPublic(rw, etpm.TpmEKHdl)
	rw.Close()
	g.Expect(err).ToNot(gomega.HaveOccurred())
	ownerKey, err := ownerEK.Key()
	g.Expect(err).ToNot(gomega.HaveOccurred())
	rec = activate(ownerKey, secret)
	g.Expect(rec.Code).To(gomega.Equal(http.StatusBadRequest), rec.Body.String())

	rec = do(http.MethodPost, "/eve/v1/tpm/activate", "10.0.0.9",
		[]byte(`{"credential_blob":"AAE=","encrypted_secret":"AAA="}`))
	g.Expect(rec.Code).To(gomega.Equal(http.StatusBadRequest), rec.Body.String())

	// A caller msrv cannot map to an app gets no quote.
	reqBody := []byte(`{"caller_data":"cmVjZWlwdC1rZXktZGlnZXN0"}`)
	rec = do(http.MethodPost, "/eve/v1/tpm/quote", "10.0.0.8", reqBody)
	g.Expect(rec.Code).To(gomega.Equal(http.StatusForbidden), rec.Body.String())

	rec = do(http.MethodPost, "/eve/v1/tpm/quote", "192.168.1.1", reqBody)
	g.Expect(rec.Code).To(gomega.Equal(http.StatusOK), rec.Body.String())
	var resp TpmQuoteResponse
	g.Expect(json.Unmarshal(rec.Body.Bytes(), &resp)).To(gomega.Succeed())
	g.Expect(resp.EventLog).To(gomega.Equal(eventLog))
	g.Expect(resp.Manufacturer).To(gomega.Equal(id.Manufacturer))

	var binding TpmQuoteBinding
	g.Expect(json.Unmarshal(resp.Binding, &binding)).To(gomega.Succeed())
	g.Expect(binding.Caller.Kind).To(gomega.Equal(CallerKindAppInstance))
	g.Expect(binding.Caller.AppUUID).To(gomega.Equal(appUUID.String()))
	g.Expect(string(binding.CallerData)).To(gomega.Equal("receipt-key-digest"))

	// The AIK signed the attestation, which carries the binding hash and
	// the digest of the returned PCR values.
	q := resp.Quote
	aikKey, err := aikPub.Key()
	g.Expect(err).ToNot(gomega.HaveOccurred())
	g.Expect(q.SigAlg).To(gomega.Equal("RSASSA-SHA256"))
	attestDigest := sha256.Sum256(q.Attest)
	g.Expect(rsa.VerifyPKCS1v15(aikKey.(*rsa.PublicKey), crypto.SHA256,
		attestDigest[:], q.Signature)).To(gomega.Succeed())
	ad, err := tpm2.DecodeAttestationData(q.Attest)
	g.Expect(err).ToNot(gomega.HaveOccurred())
	qd := sha256.Sum256(append([]byte(TpmQuoteBindingDomain), resp.Binding...))
	g.Expect([]byte(ad.ExtraData)).To(gomega.Equal(qd[:]))
	h := sha256.New()
	for _, p := range q.PCRs {
		h.Write(p.SHA256)
	}
	g.Expect(h.Sum(nil)).To(gomega.Equal([]byte(ad.AttestedQuoteInfo.PCRDigest)))
	g.Expect(q.PCRs).To(gomega.HaveLen(len(etpm.PcrListForQuote.PCRs)))
	g.Expect(q.ResetCount).To(gomega.Equal(ad.ClockInfo.ResetCount))
	t.Logf("clock %d resetCount %d restartCount %d safe %v firmware %#x",
		q.Clock, q.ResetCount, q.RestartCount, q.Safe, q.FirmwareVersion)

	// Per-IP burst is tpmQuotePerIPBurst; two requests from this IP so far.
	codes := []int{}
	for i := 0; i < tpmQuotePerIPBurst; i++ {
		codes = append(codes, do(http.MethodPost, "/eve/v1/tpm/quote",
			"192.168.1.1", reqBody).Code)
	}
	g.Expect(codes).To(gomega.ContainElement(http.StatusTooManyRequests), "codes %v", codes)
}

// TestWithWriteDeadline checks that a handler slower than the server's read
// and write timeouts keeps its context and delivers its reply.
func TestWithWriteDeadline(t *testing.T) {
	g := gomega.NewGomegaWithT(t)
	slow := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-time.After(300 * time.Millisecond):
		case <-r.Context().Done():
			http.Error(w, "request context canceled", http.StatusServiceUnavailable)
			return
		}
		w.Write([]byte("ok"))
	})
	srv := httptest.NewUnstartedServer(withWriteDeadline(2 * time.Second)(slow))
	srv.Config.ReadTimeout = 100 * time.Millisecond
	srv.Config.WriteTimeout = 100 * time.Millisecond
	srv.Config.SetKeepAlivesEnabled(false)
	srv.Start()
	defer srv.Close()

	resp, err := http.Get(srv.URL)
	g.Expect(err).ToNot(gomega.HaveOccurred())
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	g.Expect(err).ToNot(gomega.HaveOccurred())
	g.Expect(resp.StatusCode).To(gomega.Equal(http.StatusOK), "body %q", body)
	g.Expect(string(body)).To(gomega.Equal("ok"))
}

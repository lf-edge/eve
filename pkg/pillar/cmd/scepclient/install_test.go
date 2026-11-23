// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package scepclient

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/lf-edge/eve-api/go/info"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/sirupsen/logrus"
)

const testProfile = "test-profile"

type testKeyPair struct {
	key  *rsa.PrivateKey
	cert *x509.Certificate
}

func newTestKeyPair(t *testing.T, serial int64) testKeyPair {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: "eve-device"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(time.Hour * time.Duration(serial)),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return testKeyPair{key: key, cert: cert}
}

func newTestSCEPClient(t *testing.T) *SCEPClient {
	t.Helper()
	origCertDir, origKeyDir := certDir, privateKeyDir
	t.Cleanup(func() {
		certDir, privateKeyDir = origCertDir, origKeyDir
	})
	certDir = t.TempDir()
	privateKeyDir = t.TempDir()
	return &SCEPClient{
		log: base.NewSourceLogObject(logrus.StandardLogger(), agentName, 0),
	}
}

// TestRecoverCertInstall simulates a reboot at every step of installReEnrolledCert
// (and before the status of the installed certificate is published), and checks
// that recoverCertInstall leaves a matching certificate and private key installed,
// with the status describing the installed certificate.
func TestRecoverCertInstall(t *testing.T) {
	oldPair := newTestKeyPair(t, 1)
	newPair := newTestKeyPair(t, 2)

	type step int
	const (
		// The re-enrolled certificate is not yet written to the temporary file.
		beforeNewCertSaved step = iota
		// The re-enrolled certificate is written to the temporary file.
		afterNewCertSaved
		// The staged key replaced the old key.
		afterKeyInstalled
		// The re-enrolled certificate replaced the old certificate.
		afterCertInstalled
	)
	tests := []struct {
		name       string
		rebootAt   step
		statusPair *testKeyPair // certificate described by the persisted status
		expPair    *testKeyPair // certificate and key expected to be installed
		expStaged  bool         // staged private key is expected to be kept
		expUpdated bool         // status is expected to be updated
	}{
		{
			name:       "before re-enrolled certificate is saved",
			rebootAt:   beforeNewCertSaved,
			statusPair: &oldPair,
			expPair:    &oldPair,
			expStaged:  true,
		},
		{
			name:       "before private key is installed",
			rebootAt:   afterNewCertSaved,
			statusPair: &oldPair,
			expPair:    &oldPair,
			expStaged:  true,
		},
		{
			name:       "before certificate is installed",
			rebootAt:   afterKeyInstalled,
			statusPair: &oldPair,
			expPair:    &newPair,
			expUpdated: true,
		},
		{
			name:       "before status is published",
			rebootAt:   afterCertInstalled,
			statusPair: &oldPair,
			expPair:    &newPair,
			expUpdated: true,
		},
		{
			name:       "after status is published",
			rebootAt:   afterCertInstalled,
			statusPair: &newPair,
			expPair:    &newPair,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := newTestSCEPClient(t)
			certPath := c.getCertFilePath(testProfile)
			keyPath := c.getPrivateKeyFilePath(testProfile)
			stagedKeyPath := c.getStagedPrivateKeyFilePath(testProfile)
			newCertPath := c.getNewCertFilePath(testProfile)

			// Installed certificate and key, and the staged key for re-enrollment.
			if err := c.saveCertificate(certPath, oldPair.cert); err != nil {
				t.Fatal(err)
			}
			if err := c.savePrivateKey(keyPath, oldPair.key); err != nil {
				t.Fatal(err)
			}
			if err := c.savePrivateKey(stagedKeyPath, newPair.key); err != nil {
				t.Fatal(err)
			}

			// Replay installReEnrolledCert up to the reboot.
			if tt.rebootAt >= afterNewCertSaved {
				if err := c.saveCertificate(newCertPath, newPair.cert); err != nil {
					t.Fatal(err)
				}
			}
			if tt.rebootAt >= afterKeyInstalled {
				if err := os.Rename(stagedKeyPath, keyPath); err != nil {
					t.Fatal(err)
				}
			}
			if tt.rebootAt >= afterCertInstalled {
				if err := os.Rename(newCertPath, certPath); err != nil {
					t.Fatal(err)
				}
			}

			status := types.EnrolledCertificateStatus{
				CertFilepath:       certPath,
				PrivateKeyFilepath: keyPath,
				CertStatus:         info.CertStatus_CERT_STATUS_RENEWAL_PENDING,
			}
			c.populateCertStatus(&status, tt.statusPair.cert)
			expStatus := status
			if tt.expUpdated {
				c.populateCertStatus(&expStatus, tt.expPair.cert)
				expStatus.CertStatus = info.CertStatus_CERT_STATUS_AVAILABLE
			}

			updated := c.recoverCertInstall(testProfile, &status)
			if updated != tt.expUpdated {
				t.Errorf("recoverCertInstall returned %t, expected %t",
					updated, tt.expUpdated)
			}
			if status.SHA256Fingerprint != expStatus.SHA256Fingerprint ||
				!status.ExpirationTimestamp.Equal(expStatus.ExpirationTimestamp) ||
				status.CertStatus != expStatus.CertStatus ||
				status.CertFilepath != certPath || status.PrivateKeyFilepath != keyPath {
				t.Errorf("unexpected status: %+v, expected: %+v", status, expStatus)
			}

			cert, err := c.loadCertificate(certPath)
			if err != nil {
				t.Fatal(err)
			}
			if !cert.Equal(tt.expPair.cert) {
				t.Errorf("unexpected certificate installed (serial %v)", cert.SerialNumber)
			}
			key, err := c.loadPrivateKey(keyPath)
			if err != nil {
				t.Fatal(err)
			}
			if !tt.expPair.key.Equal(key) {
				t.Error("unexpected private key installed")
			}
			if _, err = os.Stat(newCertPath); !os.IsNotExist(err) {
				t.Errorf("%s was not removed: %v", newCertPath, err)
			}
			_, err = os.Stat(stagedKeyPath)
			if stagedExists := err == nil; stagedExists != tt.expStaged {
				t.Errorf("staged private key exists: %t, expected: %t",
					stagedExists, tt.expStaged)
			}

			// Recovery is idempotent.
			if c.recoverCertInstall(testProfile, &status) {
				t.Error("repeated recoverCertInstall updated the status")
			}
		})
	}
}

// TestInstallReEnrolledCert checks that installReEnrolledCert installs
// the re-enrolled certificate together with the staged private key.
func TestInstallReEnrolledCert(t *testing.T) {
	oldPair := newTestKeyPair(t, 1)
	newPair := newTestKeyPair(t, 2)
	c := newTestSCEPClient(t)
	certPath := c.getCertFilePath(testProfile)
	keyPath := c.getPrivateKeyFilePath(testProfile)
	stagedKeyPath := c.getStagedPrivateKeyFilePath(testProfile)

	if err := c.saveCertificate(certPath, oldPair.cert); err != nil {
		t.Fatal(err)
	}
	if err := c.savePrivateKey(keyPath, oldPair.key); err != nil {
		t.Fatal(err)
	}
	if err := c.savePrivateKey(stagedKeyPath, newPair.key); err != nil {
		t.Fatal(err)
	}
	if err := c.installReEnrolledCert(testProfile, newPair.cert); err != nil {
		t.Fatal(err)
	}

	cert, err := c.loadCertificate(certPath)
	if err != nil {
		t.Fatal(err)
	}
	if !cert.Equal(newPair.cert) {
		t.Error("re-enrolled certificate was not installed")
	}
	key, err := c.loadPrivateKey(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if !newPair.key.Equal(key) {
		t.Error("staged private key was not installed")
	}
	for _, path := range []string{stagedKeyPath, c.getNewCertFilePath(testProfile)} {
		if _, err = os.Stat(path); !os.IsNotExist(err) {
			t.Errorf("%s was not removed: %v", path, err)
		}
	}
}

// TestSavedFileModes checks that the certificate is readable by all,
// while the private key is readable only by the owner.
func TestSavedFileModes(t *testing.T) {
	pair := newTestKeyPair(t, 1)
	c := newTestSCEPClient(t)
	certPath := c.getCertFilePath(testProfile)
	keyPath := c.getPrivateKeyFilePath(testProfile)
	if err := c.saveCertificate(certPath, pair.cert); err != nil {
		t.Fatal(err)
	}
	if err := c.savePrivateKey(keyPath, pair.key); err != nil {
		t.Fatal(err)
	}
	for path, expMode := range map[string]os.FileMode{certPath: 0644, keyPath: 0600} {
		fi, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if mode := fi.Mode().Perm(); mode != expMode {
			t.Errorf("%s has mode %o, expected %o", path, mode, expMode)
		}
	}
}

// TestRemoveStaleTmpFiles checks that removeStaleTmpFiles removes temporary
// files left behind by an interrupted write, and nothing else.
func TestRemoveStaleTmpFiles(t *testing.T) {
	pair := newTestKeyPair(t, 1)
	c := newTestSCEPClient(t)
	certPath := c.getCertFilePath(testProfile)
	keyPath := c.getPrivateKeyFilePath(testProfile)
	if err := c.saveCertificate(certPath, pair.cert); err != nil {
		t.Fatal(err)
	}
	if err := c.savePrivateKey(keyPath, pair.key); err != nil {
		t.Fatal(err)
	}
	var tmpFiles []string
	for _, dir := range []string{certDir, privateKeyDir} {
		tmpFile, err := os.CreateTemp(dir, "tmp")
		if err != nil {
			t.Fatal(err)
		}
		tmpFile.Close()
		tmpFiles = append(tmpFiles, tmpFile.Name())
	}
	// A profile whose name starts with "tmp" must not be affected.
	tmpProfileCertPath := c.getCertFilePath("tmp1")
	if err := c.saveCertificate(tmpProfileCertPath, pair.cert); err != nil {
		t.Fatal(err)
	}

	c.removeStaleTmpFiles()

	for _, path := range tmpFiles {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Errorf("%s was not removed: %v", path, err)
		}
	}
	for _, path := range []string{certPath, keyPath, tmpProfileCertPath} {
		if _, err := os.Stat(path); err != nil {
			t.Errorf("%s was removed: %v", path, err)
		}
	}
}

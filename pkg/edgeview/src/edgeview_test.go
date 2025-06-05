// Copyright (c) 2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"path"
	"testing"
	"time"

	etpm "github.com/lf-edge/eve/pkg/pillar/evetpm"

	. "github.com/onsi/gomega"
)

func TestWalkLogDirs(t *testing.T) {
	g := NewWithT(t)

	// test the walkLogDirs function
	newlogDir = "../../newlog/testdata"

	const layout = "2006-01-02 15:04:05.000 -0700 MST"
	timestamp := "2024-11-13 10:58:52.618 +0100 CET"
	parsedTime, err := time.Parse(layout, timestamp)
	g.Expect(err).NotTo(HaveOccurred(), "failed to parse timestamp")

	from := parsedTime.Add(-1 * time.Second)
	to := parsedTime.Add(1 * time.Second)
	foundFiles := walkLogDirs(to.Unix(), from.Unix())
	g.Expect(foundFiles).To(HaveLen(1), "expected exactly one file to be found")

	expected := logfiletime{
		filepath: path.Join(newlogDir, "keepSentQueue/dev.log.1731491932618.gz"),
		filesec:  1731491932,
	}
	g.Expect(foundFiles[0]).To(Equal(expected))
}

// Make sure signWithECPrivateKey will not produce incorrect signatures
// when the r or s values have leading zeros.
func TestEcdsaSignature(t *testing.T) {
	g := NewWithT(t)

	// Generate a new ECDSA private key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key: %v", err)
	}

	msg := []byte("test message")
	for i := 0; i < 10000; i++ {
		sig, r, s, err := signWithECPrivateKey(msg, privateKey)
		if err != nil {
			t.Fatalf("Signing failed: %v", err)
		}

		foundLeadingZero := false
		rBytes := r.Bytes()
		sBytes := s.Bytes()

		// check if r or s has leading zero (P256 size is 32 bytes)
		if len(rBytes) < 32 {
			t.Logf("Found signature with leading zero in r at attempt %d\n", i)
			t.Logf("r length: %d, s length: %d\n", len(rBytes), len(sBytes))
			foundLeadingZero = true
		}
		if len(sBytes) < 32 {
			t.Logf("Found signature with leading zero in s at attempt %d\n", i)
			t.Logf("r length: %d, s length: %d\n", len(rBytes), len(sBytes))
			foundLeadingZero = true
		}

		if foundLeadingZero {
			rBase64 := base64.StdEncoding.EncodeToString(rBytes)
			sBase64 := base64.StdEncoding.EncodeToString(sBytes)
			sigBase64 := base64.StdEncoding.EncodeToString(sig)
			t.Logf("Base64 : r = %s, s = %s (Original)\n", rBase64, sBase64)

			rBase64Fixed := base64.StdEncoding.EncodeToString(etpm.EccIntToBytes(privateKey.Curve, r))
			sBase64Fixed := base64.StdEncoding.EncodeToString(etpm.EccIntToBytes(privateKey.Curve, s))
			sigFixed := append(etpm.EccIntToBytes(privateKey.Curve, r), etpm.EccIntToBytes(privateKey.Curve, s)...)
			sigFixedBase64 := base64.StdEncoding.EncodeToString(sigFixed)
			t.Logf("Base64 : r = %s, s = %s (Fixed Length)\n", rBase64Fixed, sBase64Fixed)

			t.Logf("Base64 Signature : %s (Original)\n", sigBase64)
			t.Logf("Base64 Signature : %s (Fixed Length)\n", sigFixedBase64)

			g.Expect(sigBase64).To(Equal(sigFixedBase64), "Fixed len signature should match original signature")
			return
		}
	}

	t.Fatalf("Test not finished, did not find a signature with a leading zero after 10000 attempts")
}

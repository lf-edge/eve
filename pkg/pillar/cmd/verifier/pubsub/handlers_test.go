// Copyright (c) 2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package pubsub

import (
	"path"
	"testing"

	"github.com/lf-edge/eve/pkg/pillar/base"
	verifier "github.com/lf-edge/eve/pkg/pillar/cmd/verifier/lib"
	"github.com/sirupsen/logrus"
)

func TestMediaTypeInStatusFromVerifiedFilename(t *testing.T) {
	log := base.NewSourceLogObject(logrus.StandardLogger(), "verifier_test", 0)
	mediaType := "application/vnd.docker.distribution.manifest.v2+json"
	tmpID := "tempID"
	sha256 := "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
	infile := "dummyFile"
	dummyPath := t.TempDir()
	v, err := verifier.NewVerifier(dummyPath, log)
	if err != nil {
		t.Fatalf("Error creating verifier: %v", err)
	}

	_, _, verifiedFilename, err := v.ImageVerifierFilenames(infile, sha256, tmpID, mediaType)
	if err != nil {
		t.Fatalf("ImageVerifierFilenames failed: %v", err)
	}
	status := verifyImageStatusFromVerifiedImageFile(verifiedFilename, 12345, dummyPath, log)

	if status == nil {
		t.Fatalf("Status is nil")
	}

	if status.MediaType != mediaType {
		t.Errorf("MediaType in status %v does not match original %v", status.MediaType, mediaType)
	}
}

func TestMediaTypeInStatusFromVerifiedFilenameWithNoMediaType(t *testing.T) {
	log := base.NewSourceLogObject(logrus.StandardLogger(), "verifier_test", 0)
	dummyPath := t.TempDir()
	dummyFilename := "someSha256"
	verifiedFilename := path.Join(dummyPath, dummyFilename)

	status := verifyImageStatusFromVerifiedImageFile(verifiedFilename, 12345, dummyPath, log)

	if status != nil {
		t.Errorf("Status is not nil")
	}

}

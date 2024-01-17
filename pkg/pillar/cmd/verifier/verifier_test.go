// Copyright (c) 2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package verifier

import (
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/sirupsen/logrus"
	"path"
	"testing"
)

func TestMediaTypeInStatusFromVerifiedFilename(t *testing.T) {
	log = base.NewSourceLogObject(logrus.StandardLogger(), "verifier_test", 0)
	mediaType := "application/vnd.docker.distribution.manifest.v2+json"
	tmpID := "tempID"
	sha256 := "dummySha256"
	infile := "dummyFile"

	_, _, verifiedFilename := ImageVerifierFilenames(infile, sha256, tmpID, mediaType)
	status := verifyImageStatusFromVerifiedImageFile(verifiedFilename, 12345, "dummyPath")

	if status == nil {
		t.Fatalf("Status is nil")
	}

	if status.MediaType != mediaType {
		t.Errorf("MediaType in status %v does not match original %v", status.MediaType, mediaType)
	}
}

// Copyright (c) 2017-2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Process input in the form of collections of VerifyImageConfig structs
// and publish the results as collections of VerifyImageStatus structs.
//
// Move the file from DownloadDirname/pending/<sha>
// to DownloadDirname/verifier/<sha> and make RO,
// then attempt to verify sum and optional signature.
// Once sum is verified, move to DownloadDirname/verified/<sha256>

package verifier

import (
	"encoding/hex"
	"fmt"
	"net/url"
	"os"
	"path"
	"strings"

	fileutils "github.com/lf-edge/eve/pkg/pillar/utils/file"
	uuid "github.com/satori/go.uuid"
	log "github.com/sirupsen/logrus"
)

// Verifier struct to hold the verifier object
type Verifier struct {
	basePath string
	logger   Logger
}

// NewVerifier creates a new verifier object
func NewVerifier(basePath string, logger Logger) (*Verifier, error) {
	v := &Verifier{
		basePath: basePath,
		logger:   logger,
	}
	if err := v.initializeDirs(); err != nil {
		return nil, err
	}
	return v, nil
}

// VerifyObjectSha verify the digest of an object, return error if it fails
func (v *Verifier) VerifyObjectSha(location, name, digest string) error {

	verifierFilename := location
	v.logger.Functionf("verifyObjectSha: Verifying %s file %s",
		name, verifierFilename)

	if _, err := os.Stat(verifierFilename); err != nil {
		return fmt.Errorf("verifyObjectSha: Unable to find location: %s. %w", verifierFilename, err)
	}

	imageHashB, err := fileutils.ComputeShaFile(verifierFilename)
	if err != nil {
		return err
	}
	v.logger.Functionf("internal hash consistency validated for %s file %s",
		name, verifierFilename)

	imageHash := hex.EncodeToString(imageHashB)
	configuredHash := strings.ToLower(digest)
	if imageHash != configuredHash {
		v.logger.Errorf("computed   %s", imageHash)
		v.logger.Errorf("configured %s", configuredHash)
		return fmt.Errorf("computed %s configured %s",
			imageHash, configuredHash)
	}

	v.logger.Functionf("Sha validation successful for %s", name)
	return nil
}

// MarkObjectAsVerifying marks a specific object as being verified. Returns size of object, moved location, error
func (v *Verifier) MarkObjectAsVerifying(
	location, digest, mediaType string,
	tmpID uuid.UUID) (int64, string, error) {

	verifierDirname := v.GetVerifierDir()
	pendingFilename, verifierFilename, _ := v.ImageVerifierFilenames(location, digest, tmpID.String(), mediaType)

	// Move to verifier directory which is RO
	// XXX should have dom0 do this and/or have RO mounts
	v.logger.Functionf("markObjectAsVerifying: Move from %s to %s", pendingFilename, verifierFilename)

	info, err := os.Stat(pendingFilename)
	if err != nil {
		// XXX hits sometimes; attempting to verify before download
		// is complete?
		err2 := fmt.Errorf("markObjectAsVerifying failed %w", err)
		v.logger.Error(err2)
		return 0, "", err2
	}

	if _, err := os.Stat(verifierFilename); err == nil {
		v.logger.Warn(verifierFilename + ": file exists")
		if err := os.RemoveAll(verifierFilename); err != nil {
			v.logger.Fatal(err)
		}
	}

	v.logger.Tracef("markObjectAsVerifying: Create %s", verifierDirname)
	if err := os.MkdirAll(verifierDirname, 0700); err != nil {
		v.logger.Fatal(err)
	}

	if err := os.Rename(pendingFilename, verifierFilename); err != nil {
		v.logger.Fatal(err)
	}

	if err := os.Chmod(verifierDirname, 0500); err != nil {
		v.logger.Fatal(err)
	}

	if err := os.Chmod(verifierFilename, 0400); err != nil {
		v.logger.Fatal(err)
	}
	return info.Size(), verifierFilename, nil
}

// MarkObjectAsVerified marks a specific object as verified. Returns the location of the verified object
func (v *Verifier) MarkObjectAsVerified(location, digest, mediaType string, tmpID uuid.UUID) (string, error) {

	verifiedDirname := v.GetVerifiedDir()
	_, verifierFilename, verifiedFilename := v.ImageVerifierFilenames(location, digest, tmpID.String(), mediaType)
	// Move directory from DownloadDirname/verifier to
	// DownloadDirname/verified
	// XXX should have dom0 do this and/or have RO mounts
	v.logger.Functionf("markObjectAsVerified: Move from %s to %s", verifierFilename, verifiedFilename)

	if _, err := os.Stat(verifierFilename); err != nil {
		return "", err
	}

	if _, err := os.Stat(verifiedFilename); err == nil {
		log.Warn(verifiedFilename + ": file exists")
		if err := os.RemoveAll(verifiedFilename); err != nil {
			return "", err
		}
	}

	v.logger.Functionf("markObjectAsVerified: Create %s", verifiedDirname)
	if err := os.MkdirAll(verifiedDirname, 0700); err != nil {
		return "", err
	}

	if err := os.Rename(verifierFilename, verifiedFilename); err != nil {
		return "", err
	}

	if err := os.Chmod(verifiedDirname, 0500); err != nil {
		return "", err
	}

	v.logger.Functionf("markObjectAsVerified - Done. Moved from %s to %s",
		verifierFilename, verifiedFilename)
	return verifiedFilename, nil
}

// ImageVerifierFilenames - Returns pendingFilename, verifierFilename, verifiedFilename
// for the image. The verifierFilename and verifiedFilename always will have an extension
// of the media-type, e.g. abcdeff112.application-vnd.oci.image.manifest.v1+json
// This is because we need the media-type to process the blob. Normally, we carry
// it around in the status (DownloadStatus -> BlobStatus), but those are ephemeral and
// lost during a reboot. We need that information to be persistent and survive reboot,
// so we can reconstruct it. Hence, we preserve it in the filename. It is PathEscape'd
// so it is filename-safe.
func (v *Verifier) ImageVerifierFilenames(infile, sha256, tmpID, mediaType string) (string, string, string) {
	verifierDirname, verifiedDirname := v.GetVerifierDir(), v.GetVerifiedDir()
	// Handle names which are paths
	mediaTypeSafe := url.PathEscape(mediaType)
	verifierFilename := strings.Join([]string{tmpID, sha256, mediaTypeSafe}, ".")
	verifiedFilename := strings.Join([]string{sha256, mediaTypeSafe}, ".")
	return infile, path.Join(verifierDirname, verifierFilename), path.Join(verifiedDirname, verifiedFilename)
}

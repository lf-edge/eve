// Copyright (c) 2017 Zededa, Inc.
// All rights reserved.

// Types which feed in and out of the verifier

// XXX Add types for verifying the signatures on the meta-data (the AIC) itself

package types

import (
	"time"
)

// Types for verifying the images.
// For now we just verify the sha checksum.
// For defense-in-depth we assume that the ZedManager with the help of
// dom0 has moved the image file to a read-only directory before asking
// for the file to be verified.

// The key/index to this is the Safename which is allocated by ZedManager.
// That is the filename in which we store the corresponding json files.
type VerifyImageConfig struct {
	Safename	string	// Also refers to the dirname in pending dir
	DownloadURL	string	// For logging output
	ImageSha256	string	// sha256 of immutable image
}

// The key/index to this is the Safename which comes from VerifyImageConfig.
// That is the filename in which we store the corresponding json files.
type VerifyImageStatus struct {
	Safename	string
	PendingAdd	bool
	PendingModify	bool
	PendingDelete	bool
	ImageSha256	string	// sha256 of immutable image
	State		SwState	// DELIVERED, or INITIAL if failed
	LastErr		string	// Verification error
	LastErrTime	time.Time
}

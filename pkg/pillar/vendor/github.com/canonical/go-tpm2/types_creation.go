// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2

// This file contains types defined in section 15 (Creation Data)
// in part 2 of the library spec.

// CreationData corresponds to the TPMS_CREATION_DATA type, which provides
// information about the creation environment of an object.
type CreationData struct {
	PCRSelect PCRSelectionList // PCRs included in PCRDigest

	// Digest of the selected PCRs using the name algorithm of the object associated with this data.
	PCRDigest           Digest
	Locality            Locality    // Locality at which the object was created
	ParentNameAlg       AlgorithmId // Name algorithm of the parent
	ParentName          Name        // Name of the parent
	ParentQualifiedName Name        // Qualified name of the parent
	OutsideInfo         Data        // External information provided by the caller
}

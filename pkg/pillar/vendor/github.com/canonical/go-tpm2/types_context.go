// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2

// This file contains types defined in section 14 (Context Data)
// in part 2 of the library spec.

// ContextData corresponds to the TPM2B_CONTEXT_DATA type.
type ContextData []byte

// Context corresponds to the TPMS_CONTEXT type which represents a saved
// object or session context.
type Context struct {
	Sequence    uint64      // Sequence number of the context
	SavedHandle Handle      // Handle indicating if this is a session or object
	Hierarchy   Handle      // Hierarchy of the context
	Blob        ContextData // Encrypted context data and integrity HMAC
}

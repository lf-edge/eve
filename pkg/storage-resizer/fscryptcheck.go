// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"path/filepath"

	"github.com/google/fscrypt/metadata"
	"google.golang.org/protobuf/proto"
)

const (
	fscryptPoliciesDir   = ".fscrypt/policies"
	fscryptProtectorsDir = ".fscrypt/protectors"
)

// isFscryptMetadata reports whether rel (relative to the persist root) is an
// fscrypt policy or protector file.
func isFscryptMetadata(rel string) bool {
	dir := filepath.ToSlash(filepath.Dir(rel))
	return dir == fscryptPoliciesDir || dir == fscryptProtectorsDir
}

// validFscryptMetadata reports whether data is a policy or protector fscrypt
// would accept. It applies the same unmarshal and CheckValidity that fscrypt
// runs when it reads the file, so a torn file that is still non-empty -- cut
// at a field boundary or inside one -- is caught here instead of failing the
// vault unlock later. Anything that is not a policy or protector is valid.
//
// fscrypt accepts a policy with no wrapped key, which is what a policy cut
// right after its options decodes to, so that is rejected here too: no
// protector could unlock it.
func validFscryptMetadata(rel string, data []byte) bool {
	switch filepath.ToSlash(filepath.Dir(rel)) {
	case fscryptPoliciesDir:
		policy := &metadata.PolicyData{}
		if proto.Unmarshal(data, policy) != nil || policy.CheckValidity() != nil {
			return false
		}
		return len(policy.WrappedPolicyKeys) > 0
	case fscryptProtectorsDir:
		protector := &metadata.ProtectorData{}
		return proto.Unmarshal(data, protector) == nil && protector.CheckValidity() == nil
	}
	return true
}

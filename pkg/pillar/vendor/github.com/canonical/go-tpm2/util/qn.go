// Copyright 2021 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package util

import (
	"github.com/canonical/go-tpm2"
	"github.com/canonical/go-tpm2/objectutil"
)

// ComputeQualifiedName computes the qualified name of an object from the specified qualified name
// of a root object and a list of ancestor object. The ancestor objects are ordered starting with
// the immediate child of the object associated with the root qualified name.
//
// Deprecated: Use [objectutil.ComputeQualifiedName].
func ComputeQualifiedName(entity Entity, rootQn tpm2.Name, ancestors ...Entity) (tpm2.Name, error) {
	return objectutil.ComputeQualifiedName(entity, rootQn, ancestors...)
}

// ComputeQualifiedNameInHierarchy computes the qualified name of an object protected in the
// specified hierarchy from a list of ancestor object. The ancestor objects are ordered
// starting from the primary object.
//
// Deprecated: Use [objectutil.ComputeQualifiedNameInHierarchy].
func ComputeQualifiedNameInHierarchy(entity Entity, hierarchy tpm2.Handle, ancestors ...Entity) (tpm2.Name, error) {
	return objectutil.ComputeQualifiedNameInHierarchy(entity, hierarchy, ancestors...)
}

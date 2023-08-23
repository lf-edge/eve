// Copyright 2022 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package policyutil

import (
	"github.com/canonical/go-tpm2"
)

// Named is some type that represents an object.
type Named interface {
	Name() tpm2.Name
}

type NVIndex interface {
	Handle() tpm2.Handle
	Name() tpm2.Name
}

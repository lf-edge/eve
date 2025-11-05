//
// Use and distribution licensed under the Apache license version 2.
//
// See the COPYING file in the root project directory for full text.
//

package types

import "errors"

var (
	ErrNoDB = errors.New(
		"pcidb: No pci-ids DB files found (and network fetch disabled)",
	)
	ErrNoPaths = errors.New(
		"pcidb: no search paths and cache path is empty.",
	)
	// Backwards-compat, deprecated, please reference ErrNoDB
	ERR_NO_DB = ErrNoDB
)

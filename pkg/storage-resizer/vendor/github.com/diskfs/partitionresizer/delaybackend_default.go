//go:build !chaos

package partitionresizer

import "github.com/diskfs/go-diskfs/backend"

// maybeWrapBackend returns the backend unchanged in normal builds. The delaying
// wrapper exists only in -tags chaos builds (see delaybackend_chaos.go), so
// production binaries carry none of that code.
func maybeWrapBackend(b backend.Storage) backend.Storage { return b }

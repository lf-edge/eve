package resolver

import (
	"context"

	oras "oras.land/oras-go/v2"
)

// ResolverCloser hands out oras targets for references and releases whatever it
// holds when done. One ResolverCloser can serve several references; Target is
// what binds it to a particular one, because an oras target addresses a single
// repository.
type ResolverCloser interface { //nolint:revive
	// Target returns the target that reads and writes the given reference.
	Target(ctx context.Context, ref string) (oras.Target, error)
	// Context returns the context the resolver was created with.
	Context() context.Context
	// Finalize releases anything the resolver is holding, such as a lease.
	Finalize(ctx context.Context) error
}

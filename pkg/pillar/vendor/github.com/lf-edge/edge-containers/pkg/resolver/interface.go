package resolver

import (
	"context"

	"github.com/containerd/containerd/remotes"
)

type ResolverCloser interface {
	remotes.Resolver
	Context() context.Context
	Finalize(ctx context.Context) error
}

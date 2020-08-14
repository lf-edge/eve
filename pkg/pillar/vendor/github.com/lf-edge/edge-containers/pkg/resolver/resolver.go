package resolver

/*
 Provides a github.com/containerd/containerd/remotes#Resolver that resolves
 to an existing resolver

*/

import (
	"context"

	"github.com/containerd/containerd/remotes"
)

// Resolver resolver to push to/pull using passed resolver
type Resolver struct {
	remotes.Resolver
	ctx context.Context
}

func NewResolver(ctx context.Context, resolver remotes.Resolver) (context.Context, *Resolver, error) {
	return ctx, &Resolver{Resolver: resolver, ctx: ctx}, nil
}

func (r *Resolver) Finalize(ctx context.Context) error {
	return nil
}

func (r *Resolver) Context() context.Context {
	return r.ctx
}

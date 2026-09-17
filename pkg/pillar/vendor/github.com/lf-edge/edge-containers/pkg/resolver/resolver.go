package resolver

/*
 Provides a ResolverCloser that wraps an oras target the caller already has.

*/

import (
	"context"

	oras "oras.land/oras-go/v2"
)

// Resolver serves a target the caller already holds.
type Resolver struct {
	target oras.Target
	ctx    context.Context
}

// NewResolver create a Resolver that hands out the given target for every reference.
func NewResolver(ctx context.Context, target oras.Target) (context.Context, *Resolver, error) {
	return ctx, &Resolver{target: target, ctx: ctx}, nil
}

func (r *Resolver) Target(_ context.Context, _ string) (oras.Target, error) {
	return r.target, nil
}

func (r *Resolver) Finalize(_ context.Context) error {
	return nil
}

func (r *Resolver) Context() context.Context {
	return r.ctx
}

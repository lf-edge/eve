package resolver

/*
 Provides a github.com/containerd/containerd/remotes#Resolver that resolves
 to a containerd socket

*/

import (
	"context"
	"fmt"

	"github.com/containerd/containerd/remotes"
	auth "oras.land/oras-go/pkg/auth/docker"
)

type Registry struct {
	remotes.Resolver
	ctx context.Context
}

func NewRegistry(ctx context.Context) (context.Context, *Registry, error) {
	cli, err := auth.NewClient()
	if err != nil {
		return nil, nil, fmt.Errorf("unable to get authenticating client to registry: %v", err)
	}
	resolver, err := cli.Resolver(ctx, nil, false)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to get resolver for registry: %v", err)
	}
	return ctx, &Registry{Resolver: resolver, ctx: ctx}, nil
}

func (r *Registry) Finalize(ctx context.Context) error {
	return nil
}

func (r *Registry) Context() context.Context {
	return r.ctx
}

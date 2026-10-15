package resolver

/*
 Provides an oras target that reads and writes an OCI registry, authenticating
 from the local docker credential store.

*/

import (
	"context"
	"fmt"

	oras "oras.land/oras-go/v2"
	"oras.land/oras-go/v2/registry/remote"
	"oras.land/oras-go/v2/registry/remote/auth"
	"oras.land/oras-go/v2/registry/remote/credentials"
	"oras.land/oras-go/v2/registry/remote/retry"
)

// Registry resolver that reads and writes an OCI registry.
type Registry struct {
	ctx        context.Context
	plainHTTP  bool
	credential auth.CredentialFunc
}

// registryOpts settings accumulated by the RegistryOpt passed to NewRegistryWithOpts.
type registryOpts struct {
	plainHTTP bool
}

// RegistryOpt configures a Registry created by NewRegistryWithOpts.
type RegistryOpt func(*registryOpts)

// WithPlainHTTP directs the resolver to contact the registry over HTTP rather than
// HTTPS, for a registry served without TLS such as a lab-local or test registry.
func WithPlainHTTP() RegistryOpt {
	return func(o *registryOpts) {
		o.plainHTTP = true
	}
}

// NewRegistry create a Registry resolver that reaches the registry over HTTPS.
func NewRegistry(ctx context.Context) (context.Context, *Registry, error) {
	return NewRegistryWithOpts(ctx)
}

// NewRegistryWithOpts create a Registry resolver configured by opts.
func NewRegistryWithOpts(ctx context.Context, opts ...RegistryOpt) (context.Context, *Registry, error) {
	var settings registryOpts
	for _, opt := range opts {
		opt(&settings)
	}
	store, err := credentials.NewStoreFromDocker(credentials.StoreOptions{})
	if err != nil {
		return nil, nil, fmt.Errorf("unable to read docker credentials: %v", err)
	}
	return ctx, &Registry{
		ctx:        ctx,
		plainHTTP:  settings.plainHTTP,
		credential: credentials.Credential(store),
	}, nil
}

// Target returns a target bound to the repository named by ref.
func (r *Registry) Target(_ context.Context, ref string) (oras.Target, error) {
	repo, err := remote.NewRepository(ref)
	if err != nil {
		return nil, fmt.Errorf("unable to parse reference %s: %v", ref, err)
	}
	repo.PlainHTTP = r.plainHTTP
	repo.Client = &auth.Client{
		Client:     retry.DefaultClient,
		Cache:      auth.NewCache(),
		Credential: r.credential,
	}
	return repo, nil
}

func (r *Registry) Finalize(_ context.Context) error {
	return nil
}

func (r *Registry) Context() context.Context {
	return r.ctx
}

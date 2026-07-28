// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package kubeclient holds the process-wide client-go plumbing used by
// kube-init: typed clientset, dynamic client, apiextensions clientset,
// discovery + deferred RESTMapper, and the shared informer factories.
//
// One instance is constructed early in the daemon lifecycle (once the
// k3s kubeconfig file exists) and reused by every subsystem —
// kubectlx, deploy, monitor, update. Reusing a single set of informer
// factories across the daemon means every subsystem sees the same
// event stream and no subsystem opens its own watch connection.
//
// The RESTMapper is deferred + discovery-cached. On a
// meta.NoKindMatchError, callers Reset() the mapper and retry once —
// this tolerates a CRD that has just been installed.
package kubeclient

import (
	"context"
	"fmt"
	"os"
	"time"

	apiextclientset "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/client-go/discovery"
	discocache "k8s.io/client-go/discovery/cached/memory"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/dynamic/dynamicinformer"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/restmapper"
	"k8s.io/client-go/tools/clientcmd"
)

// Client bundles every client-go handle kube-init needs. Fields are
// exported so subsystems can reach directly for the one they want
// without needing an accessor method per shape. The zero value is
// unusable; construct with New.
type Client struct {
	// Config is the loaded *rest.Config from the k3s kubeconfig file.
	Config *rest.Config

	// Clientset is the typed core+apps+batch+rbac clientset. Use for
	// GVKs whose typed shape you already know at compile time.
	Clientset kubernetes.Interface

	// APIExtClientset is the typed clientset for CustomResourceDefinition
	// objects (apiextensions.k8s.io/v1). Used by WaitCRDEstablished.
	APIExtClientset apiextclientset.Interface

	// Dynamic is the unstructured/dynamic client. Used for CR objects
	// whose Go types we do not vendor (KubeVirt, CDI, Longhorn) and for
	// server-side apply of arbitrary manifests.
	Dynamic dynamic.Interface

	// Discovery is the discovery client backing Mapper. Held so callers
	// (mostly Mapper.Reset consumers) can query it directly if needed.
	Discovery discovery.DiscoveryInterface

	// Mapper is a deferred RESTMapper on top of a memory-cached
	// discovery client. Callers should Reset() on a NoKindMatchError
	// and retry once — this handles the CRD-just-installed race.
	Mapper meta.RESTMapper

	// InformerFactory is the typed shared factory (core+apps+batch+…).
	// Started by Start. Every subsystem should read informers from this
	// factory rather than constructing its own.
	InformerFactory informers.SharedInformerFactory

	// DynamicFactory is the unstructured shared factory. Used for CRs
	// whose GVK is not known to the typed factory.
	DynamicFactory dynamicinformer.DynamicSharedInformerFactory
}

// New builds a Client from the kubeconfig at kubeconfigPath. Returns
// an error if the file is missing or unreadable — callers are expected
// to wait for the file to exist first (see WaitForKubeconfig) or gate
// on upstream readiness (e.g. k3s.WaitForK3sReady).
//
// The informer factories are constructed but not started; call Start
// once the caller is ready to have goroutines running.
func New(kubeconfigPath string) (*Client, error) {
	config, err := clientcmd.BuildConfigFromFlags("", kubeconfigPath)
	if err != nil {
		return nil, fmt.Errorf("kubeclient: load kubeconfig %s: %w", kubeconfigPath, err)
	}
	return newFromConfig(config)
}

// newFromConfig is the internal seam so tests can pass a synthetic
// *rest.Config (e.g. envtest) without touching the filesystem.
func newFromConfig(config *rest.Config) (*Client, error) {
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("kubeclient: build typed clientset: %w", err)
	}
	apiext, err := apiextclientset.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("kubeclient: build apiextensions clientset: %w", err)
	}
	dyn, err := dynamic.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("kubeclient: build dynamic client: %w", err)
	}
	disco, err := discovery.NewDiscoveryClientForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("kubeclient: build discovery client: %w", err)
	}
	cached := discocache.NewMemCacheClient(disco)
	mapper := restmapper.NewDeferredDiscoveryRESTMapper(cached)
	return &Client{
		Config:          config,
		Clientset:       clientset,
		APIExtClientset: apiext,
		Dynamic:         dyn,
		Discovery:       disco,
		Mapper:          mapper,
		InformerFactory: informers.NewSharedInformerFactory(clientset, informerResync),
		DynamicFactory:  dynamicinformer.NewDynamicSharedInformerFactory(dyn, informerResync),
	}, nil
}

// informerResync is the periodic resync interval for both informer
// factories. 10 minutes matches the kubectl default and is short
// enough that a missed watch event is corrected in bounded time
// without producing meaningful load on the API server.
const informerResync = 10 * time.Minute

// Start begins the shared informer factories' goroutines. Safe to call
// once; subsequent calls are no-ops per client-go's contract. stopCh
// is passed straight through — cancel it (typically on daemon
// shutdown) to stop all informers and let their goroutines exit.
func (c *Client) Start(stopCh <-chan struct{}) {
	c.InformerFactory.Start(stopCh)
	c.DynamicFactory.Start(stopCh)
}

// ResetMapper invalidates the discovery cache backing Mapper. Call
// after a NoKindMatchError to pick up a CRD that just landed, then
// retry the failed operation once.
func (c *Client) ResetMapper() {
	// The DeferredDiscoveryRESTMapper reads through the cached
	// discovery client on every lookup; resetting the underlying
	// cached client is enough to force re-discovery on the next call.
	// We call Reset on the mapper itself for completeness — recent
	// versions no-op internally but the API is stable.
	if r, ok := c.Mapper.(*restmapper.DeferredDiscoveryRESTMapper); ok {
		r.Reset()
	}
}

// defaultClient is the process-wide *Client set by SetDefault and
// consulted by Default. Threading a *Client through every subsystem
// would add a parameter to dozens of functions many layers deep; the
// singleton is the pragmatic escape hatch. Set it exactly once from
// main.go after the k3s kubeconfig is loadable, then use Default()
// from anywhere.
var defaultClient *Client

// SetDefault registers c as the process-wide default. Not thread-safe
// — call once from main before spawning subsystem goroutines.
func SetDefault(c *Client) {
	defaultClient = c
}

// Default returns the process-wide *Client set by SetDefault. Panics
// if called before SetDefault — that indicates a lifecycle bug
// (kubeclient consumed before the k3s API was reachable), and a nil
// pointer dereference somewhere deeper would be a more confusing
// diagnostic than an explicit panic here.
func Default() *Client {
	if defaultClient == nil {
		panic("kubeclient: Default() called before SetDefault; " +
			"k3s API must be reachable before subsystems consume it")
	}
	return defaultClient
}

// WaitForKubeconfig polls for the kubeconfig file at kubeconfigPath
// until it becomes readable or ctx is cancelled. Returns immediately
// if the file already exists.
//
// This is separate from New so callers that already know the file
// exists (e.g. code running after k3s.WaitForK3sReady) don't pay for
// a redundant stat.
func WaitForKubeconfig(ctx context.Context, kubeconfigPath string) error {
	const pollInterval = 500 * time.Millisecond
	for {
		if _, err := os.Stat(kubeconfigPath); err == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("kubeclient: wait for kubeconfig %s: %w",
				kubeconfigPath, ctx.Err())
		case <-time.After(pollInterval):
		}
	}
}

// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package kubectlx

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/lf-edge/eve/pkg/kube/kube-init/kubeclient"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	utilyaml "k8s.io/apimachinery/pkg/util/yaml"
	"k8s.io/client-go/util/retry"
)

// DefaultFieldManager is the SSA field-manager used when opts.FieldManager is empty; keep stable across releases.
const DefaultFieldManager = "kube-init"

// ApplyOptions tunes Apply / ApplyFile / ApplyURL. Zero values give
// sane defaults suitable for kube-init's boot path.
type ApplyOptions struct {
	// FieldManager identifies the caller for server-side apply. Empty
	// = DefaultFieldManager ("kube-init"). Override for one-off tools
	// that should not overwrite kube-init-owned fields.
	FieldManager string

	// Namespace overrides the object's own metadata.namespace for
	// namespaced kinds. Rarely needed — most manifests already spell
	// out the target namespace — but supported for parity with
	// `kubectl apply -n <ns>`. Cluster-scoped kinds ignore this.
	Namespace string

	// MaxAttempts caps how many times a transient failure is retried.
	// Zero = default (10).
	MaxAttempts int

	// InitialBackoff is the first inter-attempt sleep. Zero = 1s.
	InitialBackoff time.Duration

	// MaxBackoff caps the exponential backoff. Zero = 30s.
	MaxBackoff time.Duration

	// PerAttemptTimeout bounds a single Apply request. Zero = 60s.
	// Set to a longer value for large SSA payloads (operator manifests
	// with dozens of embedded objects can push past 60s on constrained
	// devices during initial CRD registration).
	PerAttemptTimeout time.Duration
}

func (o *ApplyOptions) withDefaults() {
	if o.FieldManager == "" {
		o.FieldManager = DefaultFieldManager
	}
	if o.MaxAttempts <= 0 {
		o.MaxAttempts = 10
	}
	if o.InitialBackoff <= 0 {
		o.InitialBackoff = 1 * time.Second
	}
	if o.MaxBackoff <= 0 {
		o.MaxBackoff = 30 * time.Second
	}
	if o.PerAttemptTimeout <= 0 {
		o.PerAttemptTimeout = 60 * time.Second
	}
}

// ErrApplyExhausted is returned when MaxAttempts is reached without
// success. The wrapped error is the last apply failure — callers can
// still inspect it with errors.Is / errors.As.
var ErrApplyExhausted = errors.New("kubectlx apply: max attempts exhausted")

// crdEstablishTimeout bounds the wait for a just-applied CRD to become
// Established. Establishment is normally sub-second; this only has to
// cover a previous generation of the same CRD still finalizing.
const crdEstablishTimeout = 2 * time.Minute

// Apply parses one or more objects from raw YAML/JSON bytes (multi-doc
// YAML supported) and server-side-applies each via the dynamic client.
// Objects are applied in document order, so authors can rely on
// "CRDs before CRs" within a single manifest.
//
// After applying a CustomResourceDefinition, Apply blocks until that CRD
// reports Established before moving to the next document. Ordering alone
// is not enough: a CR whose CRD was created microseconds earlier is
// rejected with a 404 until the apiserver has Established the kind and
// begun serving it. applyOne does classify that 404 as retryable
// (isCRDLifecycleRace) and retries, but a bounded retry budget against
// an unbounded wait is a race we lose sometimes — on 2026-08-02 the
// NetworkAttachmentDefinition in multus-daemonset.yaml exhausted five
// attempts over 38s, failing the cluster transition and bricking the
// node. Waiting on the condition removes the race instead of racing it
// faster: the 404 never happens, so there is nothing to classify.
//
// Returns the first non-nil per-object error. Callers that want
// best-effort semantics across multiple objects should split the
// manifest themselves and call Apply per document.
func Apply(ctx context.Context, kc *kubeclient.Client, data []byte, opts ApplyOptions) error {
	opts.withDefaults()
	objs, err := parseManifest(data)
	if err != nil {
		return fmt.Errorf("kubectlx apply: parse manifest: %w", err)
	}
	for i, obj := range objs {
		if err := applyOne(ctx, kc, obj, opts); err != nil {
			return fmt.Errorf("kubectlx apply doc[%d] (%s): %w",
				i, describeObj(obj), err)
		}
		if name, ok := crdName(obj); ok {
			if err := WaitCRDEstablished(ctx, kc, name, crdEstablishTimeout); err != nil {
				return fmt.Errorf("kubectlx apply doc[%d] (%s): wait Established: %w",
					i, describeObj(obj), err)
			}
		}
	}
	return nil
}

// crdName returns the metadata.name of obj when it is a v1
// CustomResourceDefinition, so Apply knows to gate on its
// establishment. The apiextensions group is matched without its version
// so a future v2 still gates.
func crdName(obj *unstructured.Unstructured) (string, bool) {
	gk := obj.GroupVersionKind().GroupKind()
	if gk.Group != "apiextensions.k8s.io" || gk.Kind != "CustomResourceDefinition" {
		return "", false
	}
	name := obj.GetName()
	return name, name != ""
}

// ApplyFile reads a manifest from disk and applies it via Apply.
func ApplyFile(ctx context.Context, kc *kubeclient.Client, path string, opts ApplyOptions) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("kubectlx apply: read %s: %w", path, err)
	}
	return Apply(ctx, kc, data, opts)
}

// ApplyURL fetches a manifest via HTTP(S) under ctx and applies it.
// The fetch itself is subject to opts.PerAttemptTimeout on each retry.
// Non-2xx status is a fatal (non-retryable) error.
func ApplyURL(ctx context.Context, kc *kubeclient.Client, url string, opts ApplyOptions) error {
	opts.withDefaults()
	data, err := fetchURL(ctx, url, opts.PerAttemptTimeout)
	if err != nil {
		return fmt.Errorf("kubectlx apply: fetch %s: %w", url, err)
	}
	return Apply(ctx, kc, data, opts)
}

// DeleteFile reads a manifest from disk and deletes each object it
// contains. Missing objects (NotFound) are folded into nil — the
// caller's intent (absent) is already satisfied. Errors on individual
// objects are collected; the first is returned.
func DeleteFile(ctx context.Context, kc *kubeclient.Client, path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("kubectlx delete: read %s: %w", path, err)
	}
	return DeleteBytes(ctx, kc, data)
}

// DeleteURL fetches a manifest and deletes each object it contains.
func DeleteURL(ctx context.Context, kc *kubeclient.Client, url string) error {
	data, err := fetchURL(ctx, url, 60*time.Second)
	if err != nil {
		return fmt.Errorf("kubectlx delete: fetch %s: %w", url, err)
	}
	return DeleteBytes(ctx, kc, data)
}

// DeleteBytes deletes every object parsed from data. Multi-document
// YAML is supported. NotFound is not an error.
func DeleteBytes(ctx context.Context, kc *kubeclient.Client, data []byte) error {
	objs, err := parseManifest(data)
	if err != nil {
		return fmt.Errorf("kubectlx delete: parse manifest: %w", err)
	}
	var firstErr error
	for _, obj := range objs {
		gvk := obj.GroupVersionKind()
		var mapping *meta.RESTMapping
		err := withMapperReset(kc, func() error {
			m, err := kc.Mapper.RESTMapping(gvk.GroupKind(), gvk.Version)
			if err != nil {
				return err
			}
			mapping = m
			return nil
		})
		if err != nil {
			if apierrors.IsNotFound(err) || isNoKindMatch(err) {
				continue
			}
			if firstErr == nil {
				firstErr = fmt.Errorf("%s: %w", describeObj(obj), err)
			}
			continue
		}
		iface := kc.Dynamic.Resource(mapping.Resource)
		var derr error
		if mapping.Scope.Name() == meta.RESTScopeNameNamespace {
			derr = iface.Namespace(obj.GetNamespace()).
				Delete(ctx, obj.GetName(), metav1.DeleteOptions{})
		} else {
			derr = iface.Delete(ctx, obj.GetName(), metav1.DeleteOptions{})
		}
		if derr != nil && !apierrors.IsNotFound(derr) && firstErr == nil {
			firstErr = fmt.Errorf("%s: %w", describeObj(obj), derr)
		}
	}
	return firstErr
}

// Get retrieves a single object by GVK + namespace + name using the
// dynamic client. Returns a *unstructured.Unstructured. On
// NoKindMatchError the RESTMapper is reset and the lookup retried
// once.
func Get(
	ctx context.Context, kc *kubeclient.Client,
	gvk schema.GroupVersionKind, namespace, name string,
) (*unstructured.Unstructured, error) {
	var obj *unstructured.Unstructured
	err := withMapperReset(kc, func() error {
		mapping, err := kc.Mapper.RESTMapping(gvk.GroupKind(), gvk.Version)
		if err != nil {
			return err
		}
		reqCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		if mapping.Scope.Name() == meta.RESTScopeNameNamespace {
			obj, err = kc.Dynamic.Resource(mapping.Resource).
				Namespace(namespace).Get(reqCtx, name, metav1.GetOptions{})
		} else {
			obj, err = kc.Dynamic.Resource(mapping.Resource).
				Get(reqCtx, name, metav1.GetOptions{})
		}
		return err
	})
	return obj, err
}

// applyOne server-side-applies a single unstructured object with retry
// on transient errors and a mapper-reset-retry on NoKindMatchError.
func applyOne(
	ctx context.Context, kc *kubeclient.Client,
	obj *unstructured.Unstructured, opts ApplyOptions,
) error {
	gvk := obj.GroupVersionKind()
	if opts.Namespace != "" && obj.GetNamespace() == "" {
		obj.SetNamespace(opts.Namespace)
	}
	name := obj.GetName()
	if name == "" {
		return fmt.Errorf("object %s has no metadata.name (generateName not supported by SSA)", gvk)
	}

	body, err := obj.MarshalJSON()
	if err != nil {
		return fmt.Errorf("marshal %s/%s: %w", gvk.Kind, name, err)
	}

	backoff := retry.DefaultBackoff
	backoff.Duration = opts.InitialBackoff
	backoff.Cap = opts.MaxBackoff
	backoff.Steps = opts.MaxAttempts
	backoff.Factor = 2.0
	backoff.Jitter = 0.5

	var attempts int
	err = retry.OnError(backoff, isRetryable, func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		attempts++
		return withMapperReset(kc, func() error {
			mapping, err := kc.Mapper.RESTMapping(gvk.GroupKind(), gvk.Version)
			if err != nil {
				return err
			}
			reqCtx, cancel := context.WithTimeout(ctx, opts.PerAttemptTimeout)
			defer cancel()
			force := true
			applyOpts := metav1.PatchOptions{
				FieldManager: opts.FieldManager,
				Force:        &force,
			}
			var iface = kc.Dynamic.Resource(mapping.Resource)
			if mapping.Scope.Name() == meta.RESTScopeNameNamespace {
				_, err = iface.Namespace(obj.GetNamespace()).
					Patch(reqCtx, name, types.ApplyPatchType, body, applyOpts)
			} else {
				_, err = iface.Patch(reqCtx, name, types.ApplyPatchType, body, applyOpts)
			}
			return err
		})
	})
	if err != nil {
		if apierrors.IsAlreadyExists(err) {
			// Server-side apply should not surface AlreadyExists (it
			// reconciles ownership), but a create-shape fallback might.
			// Treat as success — the object exists in the desired
			// shape.
			log.Printf("kubectlx: %s/%s already exists (treating as success)", gvk.Kind, name)
			return nil
		}
		if isRetryable(err) {
			return fmt.Errorf("%w after %d attempts: %w",
				ErrApplyExhausted, attempts, err)
		}
		return err
	}
	if attempts > 1 {
		log.Printf("kubectlx: %s/%s applied after %d attempts", gvk.Kind, name, attempts)
	}
	return nil
}

// withMapperReset runs fn once; on meta.NoKindMatchError it invalidates
// the RESTMapper's discovery cache and runs fn a second time. Every
// other error is passed through unchanged. This handles the
// CRD-just-installed race in exactly one place — callers do not need to
// know that mapper resets exist.
func withMapperReset(kc *kubeclient.Client, fn func() error) error {
	err := fn()
	if err == nil {
		return nil
	}
	if !isNoKindMatch(err) {
		return err
	}
	kc.ResetMapper()
	return fn()
}

// isNoKindMatch returns true if err's chain contains a
// meta.NoKindMatchError.
func isNoKindMatch(err error) bool {
	if err == nil {
		return false
	}
	var nkm *meta.NoKindMatchError
	return errors.As(err, &nkm)
}

// isCRDLifecycleRace reports whether err is a CR apply that lost a race
// with its CRD's lifecycle. Both shapes below are permanent verdicts in
// general — which is why isRetryable rejects Forbidden and NotFound
// outright — but here they are pure timing:
//
//   - Forbidden "...while custom resource definition is terminating":
//     the previous CRD is still finalizing, so the apiserver refuses new
//     CRs of that kind. Once it is gone and re-Established the apply
//     succeeds.
//   - NotFound "the server could not find the requested resource": the
//     kind is not served yet. NoKindMatchError covers the client-side
//     RESTMapper miss, but once the mapper holds a (stale) mapping the
//     request reaches the apiserver and comes back as a 404 on the
//     resource endpoint instead. A server-side apply creates the object,
//     so a 404 here is never "this object is missing".
//
// Matching on message text is unavoidable: the apiserver reports both
// through generic Forbidden/NotFound status errors with no machine-
// readable reason distinguishing them from the permanent cases.
func isCRDLifecycleRace(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	if apierrors.IsForbidden(err) &&
		strings.Contains(msg, "custom resource definition is terminating") {
		return true
	}
	if apierrors.IsNotFound(err) &&
		strings.Contains(msg, "could not find the requested resource") {
		return true
	}
	return false
}

// isRetryable returns true for errors that are worth another attempt:
// server-side timeouts, service unavailable, transient throttling,
// generic i/o problems, CRD-race NoKindMatchError, and the CRD-lifecycle
// races isCRDLifecycleRace identifies. It intentionally excludes NotFound
// (Get semantics — the caller decides) and Forbidden / Unauthorized /
// Invalid (permanent) in every other case.
func isRetryable(err error) bool {
	if err == nil {
		return false
	}
	if isNoKindMatch(err) {
		return true
	}
	if isCRDLifecycleRace(err) {
		return true
	}
	if apierrors.IsServerTimeout(err) ||
		apierrors.IsServiceUnavailable(err) ||
		apierrors.IsTooManyRequests(err) ||
		apierrors.IsInternalError(err) ||
		apierrors.IsTimeout(err) {
		return true
	}
	if apierrors.IsForbidden(err) ||
		apierrors.IsUnauthorized(err) ||
		apierrors.IsInvalid(err) ||
		apierrors.IsBadRequest(err) ||
		apierrors.IsNotFound(err) {
		return false
	}
	// context.Canceled is caller-driven abort (peer-fail cancels
	// runCtx; daemon shutdown cancels ctx). Retrying just sleeps
	// through backoffs before the loop-head ctx check catches on —
	// a spurious ~30s×10 wait during shutdown, and a misleading
	// "max attempts exhausted: context canceled" surface error.
	if errors.Is(err, context.Canceled) {
		return false
	}
	// context.DeadlineExceeded from a per-attempt timeout is worth
	// retrying — the caller ctx is still alive (checked at loop head).
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	// Unknown errors: retry rather than surface immediately. A novel
	// error is more often transient plumbing than a permanent misuse.
	return true
}

// parseManifest splits a multi-document YAML or JSON payload into
// unstructured objects. Empty documents (blank space between `---`
// separators) are skipped. Returns an error only if the entire input
// is undecodable — a bad document within a multi-doc stream aborts
// parsing at that document and reports its offset.
func parseManifest(data []byte) ([]*unstructured.Unstructured, error) {
	dec := utilyaml.NewYAMLOrJSONDecoder(bytes.NewReader(data), 4096)
	var out []*unstructured.Unstructured
	for i := 0; ; i++ {
		var raw map[string]any
		if err := dec.Decode(&raw); err != nil {
			if err == io.EOF {
				break
			}
			return nil, fmt.Errorf("decode doc %d: %w", i, err)
		}
		if len(raw) == 0 {
			continue
		}
		obj := &unstructured.Unstructured{Object: raw}
		if obj.GetKind() == "" || obj.GetAPIVersion() == "" {
			return nil, fmt.Errorf("doc %d: missing apiVersion or kind", i)
		}
		out = append(out, obj)
	}
	return out, nil
}

// fetchURL is a thin http.Get with a deadline. Any non-2xx status is a
// fatal error (returned as-is) so the retry classifier doesn't loop on
// a 404 forever.
func fetchURL(ctx context.Context, url string, timeout time.Duration) ([]byte, error) {
	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("http %d %s", resp.StatusCode, resp.Status)
	}
	return io.ReadAll(resp.Body)
}

// describeObj formats an object for error messages: "Kind ns/name" for
// namespaced objects, "Kind name" for cluster-scoped. Uses just the
// name if kind is empty (undecoded object).
func describeObj(obj *unstructured.Unstructured) string {
	if obj == nil {
		return "<nil>"
	}
	kind := obj.GetKind()
	name := obj.GetName()
	if ns := obj.GetNamespace(); ns != "" {
		return fmt.Sprintf("%s %s/%s", kind, ns, name)
	}
	return fmt.Sprintf("%s %s", kind, name)
}

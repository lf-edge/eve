// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package clustermode

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"time"

	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/utils/ptr"

	"github.com/lf-edge/eve/pkg/kube/kube-init/k3s"
	"github.com/lf-edge/eve/pkg/kube/kube-init/kubeclient"
	"github.com/lf-edge/eve/pkg/kube/kube-init/state"
)

// TokenRestartPending is set on the bootstrap node once it has rotated the
// k3s token, and cleared at its next k3s start. The rotation rewrites its
// token file without a restart, so that file cannot tell it one is due.
var TokenRestartPending state.Marker = "/var/lib/k3s-token-restart-pending"

const (
	tokenRestartNamespace = "kube-system"

	// tokenRotatedConfigMap holds the hash of the token the bootstrap node
	// rotated to and then restarted on. Members restart only once it
	// matches the controller's token.
	tokenRotatedConfigMap = "eve-k3s-token-rotated"
	tokenRotatedKey       = "tokenHash"

	// tokenRestartLease lets one server at a time restart k3s. Its holder
	// cannot renew while its own apiserver is down, so the duration
	// outlives a restart and the holder releases it once Ready again.
	tokenRestartLease         = "eve-k3s-token-restart"
	tokenRestartLeaseDuration = 10 * time.Minute

	tokenRestartAPITimeout = 30 * time.Second
)

// nextTokenRestart spaces out retries after a restart that did not pick up
// the new token. No lock: health worker runs never overlap.
var nextTokenRestart time.Time

// tokenRestartAPI is the cluster state ReconcileTokenRestart reads and
// writes; an interface so tests need no apiserver.
type tokenRestartAPI interface {
	PublishedHash(ctx context.Context) (string, error)
	Publish(ctx context.Context, hash string) error
	AllNodesReady(ctx context.Context) (bool, error)
	HoldsLease(ctx context.Context, holder string) (bool, error)
	AcquireLease(ctx context.Context, holder string, now time.Time) (bool, error)
	ReleaseLease(ctx context.Context, holder string) error
}

// Indirections for tests.
var (
	newTokenRestartAPI = func() (tokenRestartAPI, error) {
		if !kubeclient.HasDefault() {
			return nil, errors.New("no kubernetes client yet")
		}
		return &kubeTokenRestartAPI{cs: kubeclient.Default().Clientset}, nil
	}
	restartPending     = func() (bool, error) { return state.IsMarked(TokenRestartPending) }
	markRestartPending = func() error { return state.Mark(TokenRestartPending) }
)

// ReconcileTokenRestart restarts k3s on each server, one at a time, after
// the bootstrap node rotates the cluster token, as
// https://docs.k3s.io/cli/token requires. The bootstrap node goes first and
// then publishes the token's hash; each member whose k3s still runs on an
// older token then takes the restart lease in turn. A server restarts only
// while every node is Ready, so a restart never costs etcd quorum.
//
// restart asks the daemon to restart k3s; the drop-in already holds the
// controller's token by then.
func ReconcileTokenRestart(ctx context.Context, cs *k3s.ClusterStatus,
	nodeName string, restart func()) error {
	if cluster, err := isClusterMode(); err != nil || !cluster {
		return err
	}
	if present, err := clusterConfigPresent(); err != nil || !present {
		return err
	}
	stored, err := storedToken()
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read running token: %w", err)
	}
	pending, err := restartPending()
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(ctx, tokenRestartAPITimeout)
	defer cancel()
	api, err := newTokenRestartAPI()
	if err != nil {
		return err
	}
	published, err := api.PublishedHash(ctx)
	if err != nil {
		return fmt.Errorf("read published token hash: %w", err)
	}

	current := k3s.TokenHash(cs.EncryptedToken)
	onCurrent := k3s.SameToken(stored, cs.EncryptedToken)
	if cs.IsBootstrapNode && !pending && onCurrent && published != current {
		if err := api.Publish(ctx, current); err != nil {
			return fmt.Errorf("publish token hash: %w", err)
		}
		log.Printf("published the rotated cluster token for the other servers")
		published = current
	}

	need := needsTokenRestart(cs.IsBootstrapNode, pending, onCurrent, published, current)
	held, err := api.HoldsLease(ctx, nodeName)
	if err != nil {
		return fmt.Errorf("read restart lease: %w", err)
	}
	if held {
		if err := api.ReleaseLease(ctx, nodeName); err != nil {
			return fmt.Errorf("release restart lease: %w", err)
		}
		if need {
			nextTokenRestart = time.Now().Add(tokenRetryBackoff)
			return fmt.Errorf("k3s restarted but not on the rotated token (retry in %v)",
				tokenRetryBackoff)
		}
		log.Printf("k3s restarted on the rotated cluster token; released the restart lease")
		return nil
	}
	if !need || time.Now().Before(nextTokenRestart) {
		return nil
	}

	if ready, err := api.AllNodesReady(ctx); err != nil || !ready {
		return err
	}
	if ok, err := api.AcquireLease(ctx, nodeName, time.Now()); err != nil || !ok {
		return err
	}
	if err := provisionConfig(ctx, false); err != nil {
		if relErr := api.ReleaseLease(ctx, nodeName); relErr != nil {
			log.Printf("WARNING: release restart lease: %v", relErr)
		}
		return fmt.Errorf("rewrite cluster config before restart: %w", err)
	}
	log.Printf("restarting k3s on the rotated cluster token")
	restart()
	return nil
}

// needsTokenRestart reports whether this server's k3s must restart: the
// bootstrap node once it has rotated, a member once the bootstrap node has
// published the controller's token and the member still runs on another.
func needsTokenRestart(bootstrap, pending, onCurrent bool, published, current string) bool {
	if bootstrap {
		return pending
	}
	return !onCurrent && published == current
}

// kubeTokenRestartAPI implements tokenRestartAPI against the apiserver.
type kubeTokenRestartAPI struct {
	cs kubernetes.Interface
}

func (a *kubeTokenRestartAPI) PublishedHash(ctx context.Context) (string, error) {
	cm, err := a.cs.CoreV1().ConfigMaps(tokenRestartNamespace).Get(ctx,
		tokenRotatedConfigMap, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return cm.Data[tokenRotatedKey], nil
}

func (a *kubeTokenRestartAPI) Publish(ctx context.Context, hash string) error {
	cms := a.cs.CoreV1().ConfigMaps(tokenRestartNamespace)
	cm, err := cms.Get(ctx, tokenRotatedConfigMap, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		_, err = cms.Create(ctx, &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{Name: tokenRotatedConfigMap},
			Data:       map[string]string{tokenRotatedKey: hash},
		}, metav1.CreateOptions{})
		return err
	}
	if err != nil {
		return err
	}
	if cm.Data == nil {
		cm.Data = map[string]string{}
	}
	cm.Data[tokenRotatedKey] = hash
	_, err = cms.Update(ctx, cm, metav1.UpdateOptions{})
	return err
}

func (a *kubeTokenRestartAPI) AllNodesReady(ctx context.Context) (bool, error) {
	nodes, err := a.cs.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return false, err
	}
	for _, n := range nodes.Items {
		if !nodeReady(&n) {
			return false, nil
		}
	}
	return len(nodes.Items) > 0, nil
}

func nodeReady(n *corev1.Node) bool {
	for _, c := range n.Status.Conditions {
		if c.Type == corev1.NodeReady {
			return c.Status == corev1.ConditionTrue
		}
	}
	return false
}

func (a *kubeTokenRestartAPI) HoldsLease(ctx context.Context, holder string) (bool, error) {
	l, err := a.cs.CoordinationV1().Leases(tokenRestartNamespace).Get(ctx,
		tokenRestartLease, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return ptr.Deref(l.Spec.HolderIdentity, "") == holder, nil
}

// AcquireLease takes the restart lease if it is free, expired or already
// ours. Losing a create or update race is not an error.
func (a *kubeTokenRestartAPI) AcquireLease(ctx context.Context, holder string,
	now time.Time) (bool, error) {
	leases := a.cs.CoordinationV1().Leases(tokenRestartNamespace)
	l, err := leases.Get(ctx, tokenRestartLease, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		l = &coordinationv1.Lease{ObjectMeta: metav1.ObjectMeta{Name: tokenRestartLease}}
		claimLease(l, holder, now)
		_, err = leases.Create(ctx, l, metav1.CreateOptions{})
		if apierrors.IsAlreadyExists(err) {
			return false, nil
		}
		return err == nil, err
	}
	if err != nil {
		return false, err
	}
	if !leaseFree(l, holder, now) {
		return false, nil
	}
	claimLease(l, holder, now)
	_, err = leases.Update(ctx, l, metav1.UpdateOptions{})
	if apierrors.IsConflict(err) {
		return false, nil
	}
	return err == nil, err
}

func (a *kubeTokenRestartAPI) ReleaseLease(ctx context.Context, holder string) error {
	leases := a.cs.CoordinationV1().Leases(tokenRestartNamespace)
	l, err := leases.Get(ctx, tokenRestartLease, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if ptr.Deref(l.Spec.HolderIdentity, "") != holder {
		return nil
	}
	l.Spec.HolderIdentity = nil
	_, err = leases.Update(ctx, l, metav1.UpdateOptions{})
	return err
}

// leaseFree reports whether holder may take l: no holder, holder itself,
// or a holder that let it expire.
func leaseFree(l *coordinationv1.Lease, holder string, now time.Time) bool {
	h := ptr.Deref(l.Spec.HolderIdentity, "")
	if h == "" || h == holder {
		return true
	}
	if l.Spec.RenewTime == nil || l.Spec.LeaseDurationSeconds == nil {
		return true
	}
	expiry := l.Spec.RenewTime.Add(time.Duration(*l.Spec.LeaseDurationSeconds) * time.Second)
	return now.After(expiry)
}

func claimLease(l *coordinationv1.Lease, holder string, now time.Time) {
	t := metav1.NewMicroTime(now)
	l.Spec.HolderIdentity = ptr.To(holder)
	l.Spec.LeaseDurationSeconds = ptr.To(int32(tokenRestartLeaseDuration / time.Second))
	l.Spec.AcquireTime = &t
	l.Spec.RenewTime = &t
}

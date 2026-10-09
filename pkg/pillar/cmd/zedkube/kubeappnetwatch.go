// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build k

package zedkube

import (
	"context"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"
)

// watchKubeAppWorkloads starts the two long-running Kubernetes watches that keep
// reconcileKubeAppNetworks/reconcileKubeAppDNS close to real-time: a Pod watch scoped to
// this node (any pod change here may change a marker or a synthesized AppNetworkConfig)
// and a cluster-wide ReplicaSet watch (an owning ReplicaSet's identity feeds
// kubeAppNames/kubeAppNetConfigForPod, and it can change independently of its pods, e.g.
// when a Deployment rolls out a new generation). Each watch only triggers a reconcile --
// it never inspects the event itself -- because reconcileKubeAppNetworks re-lists from
// scratch every time, so there is no local cache to keep in sync.
//
// z.nodeName must already be resolved before this is called (see Run()).
func (z *zedkube) watchKubeAppWorkloads() {
	go z.watchAndTrigger("pods", func(ctx context.Context,
		clientset *kubernetes.Clientset) (watch.Interface, error) {
		return clientset.CoreV1().Pods("").Watch(ctx, metav1.ListOptions{
			FieldSelector: "spec.nodeName=" + z.nodeName,
		})
	})
	go z.watchAndTrigger("replicasets", func(ctx context.Context,
		clientset *kubernetes.Clientset) (watch.Interface, error) {
		return clientset.AppsV1().ReplicaSets("").Watch(ctx, metav1.ListOptions{})
	})
}

// watchAndTrigger runs one watch forever, (re)establishing it with a fixed backoff
// whenever its result channel closes (expiry, transient API error, the watch silently
// stopping, …), and signals kubeAppNetTrigger (non-blocking) on every event. name is only
// for logging.
func (z *zedkube) watchAndTrigger(name string, startWatch func(context.Context,
	*kubernetes.Clientset) (watch.Interface, error)) {
	for {
		clientset, err := getKubeClientSet()
		if err != nil {
			log.Warnf("watchKubeAppWorkloads(%s): clientset: %v", name, err)
			time.Sleep(kubeAppWatchRetryDelay)
			continue
		}
		watcher, err := startWatch(context.Background(), clientset)
		if err != nil {
			log.Warnf("watchKubeAppWorkloads(%s): watch: %v", name, err)
			time.Sleep(kubeAppWatchRetryDelay)
			continue
		}
		log.Noticef("watchKubeAppWorkloads(%s): watch established", name)
		for range watcher.ResultChan() {
			select {
			case z.kubeAppNetTrigger <- struct{}{}:
			default:
				// A signal is already pending; this event is covered by it.
			}
		}
		watcher.Stop()
		log.Noticef("watchKubeAppWorkloads(%s): watch closed, retrying", name)
		time.Sleep(kubeAppWatchRetryDelay)
	}
}

// Copyright (c) 2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build kubevirt

package zedkube

import (
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/kubeapi"
	v1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/kubectl/pkg/drain"
)

const (
	drainRetryMax  = 5
	cordonTriesMax = 10
	// A unique key to log for searching and viewing node drain times
	drainCompletionLogKey = "kubevirt_node_drain_completion_time_seconds"
)

func getLocalNode(nodeuuid string) (*v1.Node, error) {
	config, err := kubeapi.GetKubeConfig()
	if err != nil {
		return nil, fmt.Errorf("getLocalNode: can't get kubeconfig %v", err)
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("getLocalNode: can't get clientset %v", err)
	}

	log.Functionf("getLocalNode with nodeuuid:%s", nodeuuid)
	labelSelector := metav1.LabelSelector{MatchLabels: map[string]string{"node-uuid": nodeuuid}}
	options := metav1.ListOptions{LabelSelector: metav1.FormatLabelSelector(&labelSelector)}
	nodes, err := clientset.CoreV1().Nodes().List(context.Background(), options)
	if err != nil {
		return nil, fmt.Errorf("getLocalNode: can't get nodes %v, on uuid %s", err, nodeuuid)
	}
	if len(nodes.Items) == 0 {
		return nil, fmt.Errorf("getLocalNode: can't find node with node-uuid:%s", nodeuuid)
	}
	log.Noticef("getLocalNode with nodeuuid:%s found node:%s unschedulable:%v", nodeuuid, nodes.Items[0].ObjectMeta.Name, nodes.Items[0].Spec.Unschedulable)
	return &nodes.Items[0], nil
}

func isNodeCordoned(nodeuuid string) (bool, error) {
	log.Noticef("isNodeCordoned nodeuuid:%s", nodeuuid)
	node, err := getLocalNode(nodeuuid)
	if err != nil {
		return false, fmt.Errorf("isNodeCordoned getLocalNode err:%v", err)
	}
	// Competing docs on how to check if a node is cordoned

	// Check the spec for the taint first
	for _, taint := range node.Spec.Taints {
		if taint.Key == "node.kubernetes.io/unschedulable" && taint.Effect == "NoSchedule" {
			log.Noticef("isNodeCordoned nodeuuid:%s unschedulable via taint:%v", nodeuuid, taint)
			return true, nil
		}
	}

	// Then check the spec for the unschedulable flag
	if node.Spec.Unschedulable {
		return true, nil
	}

	return false, nil
}

func cordonNode(nodeuuid string, cordon bool) error {
	config, err := kubeapi.GetKubeConfig()
	if err != nil {
		return fmt.Errorf("cordonNode: can't get kubeconfig %v", err)
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return fmt.Errorf("cordonNode: can't get clientset %v", err)
	}

	labelSelector := metav1.LabelSelector{MatchLabels: map[string]string{"node-uuid": nodeuuid}}
	options := metav1.ListOptions{LabelSelector: metav1.FormatLabelSelector(&labelSelector)}
	nodes, err := clientset.CoreV1().Nodes().List(context.Background(), options)
	if err != nil {
		return fmt.Errorf("cordonNode: can't get nodes %v, on uuid %s", err, nodeuuid)
	}
	if len(nodes.Items) == 0 {
		return fmt.Errorf("cordonNode: can't find node")
	}
	node := nodes.Items[0]

	node.Spec.Unschedulable = cordon
	_, err = clientset.CoreV1().Nodes().Update(context.Background(), &node, metav1.UpdateOptions{})
	if err != nil {
		return fmt.Errorf("Failed to cordon node:%s err:%v\n", node.ObjectMeta.Name, err)
	}
	log.Noticef("cordonNode node:%s node:%s unschedulable:%v complete", nodeuuid, node.ObjectMeta.Name, cordon)
	return nil
}

func getNodeUptime(nodeuuid string) (time.Duration, error) {
	node, err := getLocalNode(nodeuuid)
	if err != nil {
		return time.Duration(0), fmt.Errorf("getNodeUptime getLocalNode err:%v", err)
	}
	for _, condition := range node.Status.Conditions {
		if condition.Type == "Ready" && condition.Status == "True" {
			return time.Since(condition.LastTransitionTime.Time), nil
		}
	}
	return time.Duration(0), fmt.Errorf("getNodeUptime: can't find Ready condition")
}

// Check for an extended time of any responses from a set defined as Unreachable-type
//
//	responses of the k8s api.
//	To allow us to short circuit the drain process for a node where k3s is firmly down
//	IsInternalError, IsServerTimeout, IsServiceUnavailable, IsTimeout, IsTooManyRequests
func isExtendedKubeAPIUnreachable(duration time.Duration) (bool, error) {
	config, err := kubeapi.GetKubeConfig()
	if err != nil {
		return false, fmt.Errorf("isExtendedKubeAPIUnreachable: can't get kubeconfig %v", err)
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return false, fmt.Errorf("isExtendedKubeAPIUnreachable: can't get clientset %v", err)
	}

	startTime := time.Now()
	for time.Since(startTime) < duration {
		_, err = clientset.CoreV1().Nodes().List(context.Background(), metav1.ListOptions{})
		if err == nil {
			return false, fmt.Errorf("api is available")
		}
		if err != nil {
			if !k8serrors.IsInternalError(err) && !k8serrors.IsServerTimeout(err) &&
				!k8serrors.IsServiceUnavailable(err) && !k8serrors.IsTimeout(err) &&
				!k8serrors.IsTooManyRequests(err) {
				return false, fmt.Errorf("Non ServiceUnreachable error: %v", err)
			}
			log.Warnf("isExtendedKubeAPIUnreachable: err:%v", err)
		}
		time.Sleep(5 * time.Second)
	}
	return true, nil
}

func cordonAndDrainNode(ctx *zedkube) {
	log.Notice("cordonAndDrainNode nodedrain-step:drain-starting")
	publishNodeDrainStatus(ctx, kubeapi.STARTING)

	//
	// 1. Attempt to safely handle the case where the kube api is down
	//	for an extended period of time and the controller requested device operation is needed anyways.
	//  eg. k3s not running on local node due to needing a reboot operation.
	//
	unavail, err := isExtendedKubeAPIUnreachable(ctx.drainSkipK8sAPINotReachableTimeout)
	if unavail && (err == nil) {
		log.Noticef("cordonAndDrainNode nodedrain-step:drain-complete due to extended kube api service unreachability after duration:%v", ctx.drainSkipK8sAPINotReachableTimeout)
		publishNodeDrainStatus(ctx, kubeapi.COMPLETE)
		return
	}

	//
	// 2. Is the Node Cordoned
	//
	cordoned, err := isNodeCordoned(ctx.nodeuuid)
	if err != nil {
		log.Errorf("cordonAndDrainNode can't read local node cordon state, err:%v", err)
	}

	//
	// 3. Cordon the node to stop new deployed workloads
	//
	if !cordoned {
		cordonTry := 0
		for cordonTry < cordonTriesMax {
			log.Functionf("cordonAndDrainNode try:%d", cordonTry)
			err := cordonNode(ctx.nodeuuid, true)
			if err == nil {
				break
			}
			//Retries for kubernetes api cache
			//Operation cannot be fulfilled on nodes \\\"<node>\\\": the object has been modified; please apply your changes to the latest version and try again
			// or connection refused

			log.Errorf("cordonAndDrainNode nodedrain-step:drain-cordon-failure err:%v", err)
			cordonTry = cordonTry + 1
			time.Sleep(time.Second * 5)
		}
		if cordonTry == cordonTriesMax {
			log.Errorf("cordonAndDrainNode nodedrain-step:drain-cordon-failure err:%v", err)
			publishNodeDrainStatus(ctx, kubeapi.FAILEDCORDON)
			return
		}
	}

	log.Noticef("cordonAndDrainNode nodedrain-step:drain-cordon-complete")
	publishNodeDrainStatus(ctx, kubeapi.CORDONED)

	//
	// 4. Drains
	//
	drainRetry := 1
	for {
		log.Noticef("cordonAndDrainNode nodedrain-step:drain-attempt try:%d", drainRetry)

		err := drainNode(ctx)
		if err == nil {
			break
		}
		log.Errorf("cordonAndDrainNode nodedrain-step:drain-failure try:%d err:%v", drainRetry, err)
		drainRetry = drainRetry + 1
		if drainRetry >= drainRetryMax {
			log.Error("cordonAndDrainNode nodedrain-step:drain-failure-givingup NodeDrainStatus->FAILEDDRAIN")
			publishNodeDrainStatus(ctx, kubeapi.FAILEDDRAIN)
			return
		}
		publishNodeDrainStatus(ctx, kubeapi.DRAINRETRYING)
		time.Sleep(time.Second * 300)
	}

	// Allow fault injection
	for {
		if !kubeapi.DrainStatusFaultInjectionWait() {
			break
		}
		time.Sleep(time.Second * 30)
	}

	requestTime := getNodeDrainRequestTime(ctx)
	//
	// 5. Drain Complete: notify requester
	//
	log.Notice("cordonAndDrainNode nodedrain-step:drain-complete")
	// Please keep this log message unchanged as it is intended to be mined for statistics
	log.Noticef("%s:%f", drainCompletionLogKey, time.Since(requestTime).Seconds())
	publishNodeDrainStatus(ctx, kubeapi.COMPLETE)
	return
}

func onPodDeletedOrEvicted(pod *v1.Pod, usingEviction bool) {
	log.Noticef("nodedrain-step:pod-evict-progress pod:%s evict:%v", pod.Name, usingEviction)
}

type drainLogger struct {
	log *base.LogObject
	out io.Writer
	err bool
}

func (dl *drainLogger) Write(p []byte) (n int, err error) {
	if dl.err {
		dl.log.Errorf("nodedrain-step:pod-evict-err err:%s", string(p))
	} else {
		dl.log.Noticef("nodedrain-step:pod-evict-progress msg:%s", string(p))
	}
	return len(p), nil
}

func drainNode(ctx *zedkube) error {
	config, err := kubeapi.GetKubeConfig()
	if err != nil {
		return fmt.Errorf("drainNode: can't get kubeconfig %v", err)
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return fmt.Errorf("drainNode: can't get clientset %v", err)
	}

	labelSelector := metav1.LabelSelector{MatchLabels: map[string]string{"node-uuid": ctx.nodeuuid}}
	options := metav1.ListOptions{LabelSelector: metav1.FormatLabelSelector(&labelSelector)}
	nodes, err := clientset.CoreV1().Nodes().List(context.Background(), options)
	if err != nil {
		return fmt.Errorf("drainNode: can't get nodes %v, on uuid %s", err, ctx.nodeuuid)
	}
	if len(nodes.Items) == 0 {
		return fmt.Errorf("drainNode: can't find node")
	}
	node := nodes.Items[0]
	nodeName := node.Name

	// https://longhorn.io/docs/archives/1.4.0/volumes-and-nodes/maintenance/#updating-the-node-os-or-container-runtime
	// https://github.com/longhorn/longhorn/discussions/8593
	lhPodSelectors := []string{
		"app!=csi-attacher",
		"app!=csi-provisioner",
		"app!=longhorn-admission-webhook",
		"app!=longhorn-conversion-webhook",
		"app!=longhorn-driver-deployer",
	}
	podSelectorStr := strings.Join(lhPodSelectors, ",")

	drainHelper := &drain.Helper{
		Client:                clientset,
		Force:                 true,
		GracePeriodSeconds:    -1,
		IgnoreAllDaemonSets:   true,
		Out:                   &drainLogger{log: log, err: false},
		ErrOut:                &drainLogger{log: log, err: true},
		DeleteEmptyDirData:    true,
		Timeout:               ctx.drainTimeout,
		PodSelector:           podSelectorStr,
		OnPodDeletedOrEvicted: onPodDeletedOrEvicted,
	}
	err = drain.RunNodeDrain(drainHelper, nodeName)
	if err != nil {
		drainErr := fmt.Errorf("drainNode RunNodeDrain Failure: %v", err)
		log.Error(drainErr)
		return drainErr
	}
	log.Noticef("drainNode: node %s drained", nodeName)
	return nil
}

// deletePods : only those resident in namespace and on node specified
func deletePods(clientset *kubernetes.Clientset, namespace string, nodeName string) error {
	gracePeriod := int64(-1)

	propagationPolicy := metav1.DeletePropagationBackground
	return clientset.CoreV1().Pods(namespace).DeleteCollection(context.Background(),
		metav1.DeleteOptions{
			GracePeriodSeconds: &gracePeriod,
			PropagationPolicy:  &propagationPolicy,
		},
		metav1.ListOptions{
			FieldSelector: "spec.nodeName=" + nodeName,
		})
}

// try to drain and delete the node before we remove the cluster config and
// transition into single-node mode. Otherwise, if the node is later added to
// the cluster again, it will not be allowed due to duplicate node names.
func drainAndDeleteNode(ctx *zedkube) {
	config, err := kubeapi.GetKubeConfig()
	if err != nil {
		log.Errorf("drainAndDeleteNode: can't get kubeconfig %v", err)
		return
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		log.Errorf("drainAndDeleteNode: can't get clientset %v", err)
		return
	}

	nodeName := ctx.nodeName
	node, err := clientset.CoreV1().Nodes().Get(context.Background(), nodeName, metav1.GetOptions{})
	if err != nil {
		log.Errorf("drainAndDeleteNode: can't get nodes %v, for %s", err, nodeName)
		return
	}

	// cordon the node first
	node.Spec.Unschedulable = true
	_, err = clientset.CoreV1().Nodes().Update(context.Background(), node, metav1.UpdateOptions{})
	if err != nil {
		log.Errorf("drainAndDeleteNode: cordon node %s failed: %v, continue the delete", nodeName, err)
		return
	}

	if err = deletePods(clientset, kubeapi.EVEKubeNameSpace, nodeName); err != nil {
		log.Errorf("drainAndDeleteNode: deletePods err:%v", err)
		return
	}

	//
	// This path will be passed through for both:
	// - cluster delete
	// - node delete (UI node replace)
	//
	// Some background: the motivation to drain a node is to give time for another
	// node in the cluster to complete a replica rebuild where the only source data could
	// reside on this local node.
	// Example:
	//	- node 1 outage, recovers, starts rebuilds
	//  - node 2 outage before node 1 rebuilds complete, recovers, starts rebuilds
	//  - both 1 and 2 are now rebuilding replicas off of data on node 3
	//  - user requests node 3 replacement for some maintenance (fan replacement, memory upgrade, ...)
	//
	// - cluster delete: every node is leaving the cluster and rebooting, there are no rebuilds
	//	to complete. Drain is not needed.
	//
	// - node delete (UI node replace): there are still nodes resident in the cluster which could
	//  have data they need on this node to complete a replica rebuild.  Drain is required.
	//

	drainRequired := true
	replicas, err := kubeapi.LonghornReplicaList(nodeName, "")
	if err != nil {
		log.Errorf("drainAndDeleteNode LonghornReplicaList:%v", err)
		return
	}
	if (err == nil) && (len(replicas.Items) == 0) {
		log.Noticef("drainAndDeleteNode found no replicas on this node, no rebuilds could need data here")
		drainRequired = false
	}

	if drainRequired {
		if err = drainNode(ctx); err != nil {
			log.Error(fmt.Errorf("drainAndDeleteNode: drain err:%v", err))
			return
		}
	}

	if err := clientset.CoreV1().Nodes().Delete(context.Background(), nodeName, metav1.DeleteOptions{}); err != nil {
		log.Errorf("drainAndDeleteNode: clientset.CoreV1().Nodes().Delete failed: %v", err)
		return
	}
	log.Noticef("drainAndDeleteNode: node %s drained and deleted", nodeName)
	return
}

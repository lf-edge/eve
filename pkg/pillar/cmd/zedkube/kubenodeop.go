// Copyright (c) 2024 Zededa, Inc.
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
	apierrors "k8s.io/apimachinery/pkg/api/errors"
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

func getLocalNode(ctx *zedkubeContext) (*v1.Node, error) {
	config, err := kubeapi.GetKubeConfig()
	if err != nil {
		return nil, fmt.Errorf("getLocalNode: can't get kubeconfig %v", err)
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("getLocalNode: can't get clientset %v", err)
	}

	log.Noticef("getLocalNode with nodeuuid:%s", ctx.nodeuuid)
	labelSelector := metav1.LabelSelector{MatchLabels: map[string]string{"node-uuid": ctx.nodeuuid}}
	options := metav1.ListOptions{LabelSelector: metav1.FormatLabelSelector(&labelSelector)}
	nodes, err := clientset.CoreV1().Nodes().List(context.Background(), options)
	if err != nil {
		return nil, fmt.Errorf("getLocalNode: can't get nodes %v, on uuid %s", err, ctx.nodeuuid)
	}
	if len(nodes.Items) == 0 {
		return nil, fmt.Errorf("getLocalNode: can't find node with node-uuid:%s", ctx.nodeuuid)
	}
	log.Noticef("getLocalNode with nodeuuid:%s found node:%s unschedulable:%v", ctx.nodeuuid, nodes.Items[0].ObjectMeta.Name, nodes.Items[0].Spec.Unschedulable)
	return &nodes.Items[0], nil
}

func isNodeCordoned(ctx *zedkubeContext) (bool, error) {
	log.Noticef("isNodeCordoned nodeuuid:%s", ctx.nodeuuid)
	node, err := getLocalNode(ctx)
	if err != nil {
		return false, fmt.Errorf("isNodeCordoned getLocalNode err:%v", err)
	}
	// For some odd reason, at some points the api has not yet set 'Unschedulable' but
	// Does correctly have the taint listed.  Since the taint seems more reliable, use it.
	log.Noticef("isNodeCordoned nodeuuid:%s unschedulable:%v", ctx.nodeuuid, node.Spec.Unschedulable)
	for _, taint := range node.Spec.Taints {
		log.Noticef("isNodeCordoned nodeuuid:%s taint_key:%s", ctx.nodeuuid, taint.Key)
		if taint.Key == "node.kubernetes.io/unreachable" {
			return true, nil
		}
	}
	return false, nil
}

func cordonNode(ctx *zedkubeContext, cordon bool) error {
	config, err := kubeapi.GetKubeConfig()
	if err != nil {
		return fmt.Errorf("cordonNode: can't get kubeconfig %v", err)
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return fmt.Errorf("cordonNode: can't get clientset %v", err)
	}

	labelSelector := metav1.LabelSelector{MatchLabels: map[string]string{"node-uuid": ctx.nodeuuid}}
	options := metav1.ListOptions{LabelSelector: metav1.FormatLabelSelector(&labelSelector)}
	nodes, err := clientset.CoreV1().Nodes().List(context.Background(), options)
	if err != nil {
		return fmt.Errorf("cordonNode: can't get nodes %v, on uuid %s", err, ctx.nodeuuid)
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
	log.Noticef("cordonNode node:%s node:%s unschedulable:%v complete", ctx.nodeuuid, node.ObjectMeta.Name, cordon)
	return nil
}

func cordonAndDrainNode(ctx *zedkubeContext) {
	log.Notice("cordonAndDrainNode nodedrain-step:drain-starting")
	publishNodeDrainStatus(ctx, kubeapi.STARTING)

	//
	// 1. Is the Node Cordoned
	//
	cordoned, err := isNodeCordoned(ctx)
	if err != nil {
		log.Errorf("cordonAndDrainNode can't read local node cordon state, err:%v", err)
	}

	//
	// 2. Cordon the node to stop new deployed workloads
	//
	if !cordoned {
		cordonTry := 0
		for cordonTry < cordonTriesMax {
			log.Functionf("cordonAndDrainNode try:%d", cordonTry)
			err := cordonNode(ctx, true)
			if err == nil {
				break
			}
			//Retries for kubernetes api cache
			//Operation cannot be fulfilled on nodes \\\"<node>\\\": the object has been modified; please apply your changes to the latest version and try again
			if !apierrors.IsConflict(err) {
				log.Errorf("cordonAndDrainNode nodedrain-step:drain-cordon-failure err:%v", err)
				publishNodeDrainStatus(ctx, kubeapi.FAILEDCORDON)
				return
			}
			cordonTry = cordonTry + 1
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
	// 3. Drains
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
	request_time := getNodeDrainRequestTime(ctx)
	//
	// 4. Drain Complete
	//
	log.Notice("cordonAndDrainNode nodedrain-step:drain-complete")
	// Please keep this log message unchanged as it is intended to be mined for statistics
	log.Noticef("%s:%f", drainCompletionLogKey, time.Since(request_time).Seconds())
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

func drainNode(ctx *zedkubeContext) error {
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
		Timeout:               time.Hour * time.Duration(ctx.drainTimeoutHours),
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
func drainAndDeleteNode(ctx *zedkubeContext) {
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

	labelSelector := metav1.LabelSelector{MatchLabels: map[string]string{"node-uuid": ctx.nodeuuid}}
	options := metav1.ListOptions{LabelSelector: metav1.FormatLabelSelector(&labelSelector)}
	nodes, err := clientset.CoreV1().Nodes().List(context.Background(), options)
	if err != nil {
		log.Errorf("drainAndDeleteNode: can't get nodes %v, on uuid %s", err, ctx.nodeuuid)
		return
	}
	if len(nodes.Items) == 0 {
		log.Errorf("drainAndDeleteNode: can't find node")
		return
	}
	node := nodes.Items[0]
	nodeName := node.Name

	// cordon the node first
	node.Spec.Unschedulable = true
	_, err = clientset.CoreV1().Nodes().Update(context.Background(), &node, metav1.UpdateOptions{})
	if err != nil {
		log.Errorf("drainAndDeleteNode: cordon node %s failed: %v, continue the delete", nodeName, err)
	}

	if err = deletePods(clientset, kubeapi.EVEKubeNameSpace, nodeName); err != nil {
		log.Errorf("drainAndDeleteNode: deletePods err:%v", err)
		return
	}

	if err = drainNode(ctx); err != nil {
		log.Error(fmt.Errorf("drainAndDeleteNode: drain err:%v", err))
		return
	}

	if err := clientset.CoreV1().Nodes().Delete(context.Background(), nodeName, metav1.DeleteOptions{}); err != nil {
		log.Errorf("drainAndDeleteNode: clientset.CoreV1().Nodes().Delete failed: %v", err)
	}
	log.Noticef("drainAndDeleteNode: node %s drained and deleted", nodeName)
}

// Copyright (c) 2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build kubevirt

package zedkube

import (
	"context"
	"fmt"
	"net/http"
	"reflect"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/cipher"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/utils/netutils"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func handleDNSCreate(ctxArg interface{}, _ string, statusArg interface{}) {
	ctx := ctxArg.(*zedkubeContext)
	dns := statusArg.(types.DeviceNetworkStatus)
	applyDNS(ctx, dns)
}

func handleDNSModify(ctxArg interface{}, _ string, statusArg interface{}, _ interface{}) {
	ctx := ctxArg.(*zedkubeContext)
	dns := statusArg.(types.DeviceNetworkStatus)
	applyDNS(ctx, dns)
}

func applyDNS(ctx *zedkubeContext, dns types.DeviceNetworkStatus) {
	ctx.deviceNetworkStatus = dns
	changed := updateClusterIPReadiness(ctx)
	if changed {
		if ctx.clusterIPIsReady {
			if ctx.statusServer == nil {
				startClusterStatusServer(ctx)
			}
		} else {
			if ctx.statusServer != nil {
				stopClusterStatusServer(ctx)
			}
		}
		publishKubeConfigStatus(ctx)
	}
}

func applyClusterConfig(ctx *zedkubeContext, config, oldconfig *types.EdgeNodeClusterConfig) {
	noChange := reflect.DeepEqual(config, oldconfig)
	if noChange {
		log.Noticef("getKubeConfig: no change in cluster config")
		return
	}
	if config == nil {
		// Before we let NIM to remove the cluster IP, we need to remove the node
		// from the cluster.
		stopClusterStatusServer(ctx)
		ctx.clusterConfig = types.EdgeNodeClusterConfig{}
		return
	} else {
		clusterIPChanged := !netutils.EqualIPNets(ctx.clusterConfig.ClusterIPPrefix,
			config.ClusterIPPrefix)
		ctx.clusterConfig = *config
		if clusterIPChanged {
			stopClusterStatusServer(ctx)
			updateClusterIPReadiness(ctx)
			if ctx.clusterIPIsReady {
				startClusterStatusServer(ctx)
			}
		}
	}
	publishKubeConfigStatus(ctx)
}

// publishKubeConfigStatus publishes the cluster config status
func publishKubeConfigStatus(ctx *zedkubeContext) {
	status := types.EdgeNodeClusterStatus{
		ClusterName:      ctx.clusterConfig.ClusterName,
		ClusterID:        ctx.clusterConfig.ClusterID,
		ClusterInterface: ctx.clusterConfig.ClusterInterface,
		ClusterIPPrefix:  ctx.clusterConfig.ClusterIPPrefix,
		ClusterIPIsReady: ctx.clusterIPIsReady,
		IsWorkerNode:     ctx.clusterConfig.IsWorkerNode,
		JoinServerIP:     ctx.clusterConfig.JoinServerIP,
		BootstrapNode:    ctx.clusterConfig.BootstrapNode,
	}

	if ctx.clusterConfig.CipherToken.IsCipher {
		decToken, err := decryptClusterToken(ctx)
		if err != nil {
			log.Errorf("publishKubeConfigStatus: failed to decrypt cluster token: %v", err)
			status.Error = types.ErrorDescription{
				Error:     err.Error(),
				ErrorTime: time.Now(),
			}
		} else {
			status.EncryptedClusterToken = decToken
		}
	} else {
		log.Errorf("publishKubeConfigStatus: cluster token is not from configitme or encrypted")
	}
	// publish the cluster status for the kube container
	ctx.pubEdgeNodeClusterStatus.Publish("global", status)
}

func decryptClusterToken(ctx *zedkubeContext) (string, error) {
	if !ctx.clusterConfig.CipherToken.IsCipher {
		return "", fmt.Errorf("decryptClusterToken: cluster token is not encrypted")
	}

	decryptAvailable := ctx.subControllerCert != nil && ctx.subEdgeNodeCert != nil
	if !decryptAvailable {
		return "", fmt.Errorf("decryptClusterToken: certificates are not available")
	}
	status, decBlock, err := cipher.GetCipherCredentials(
		&cipher.DecryptCipherContext{
			Log:                  log,
			AgentName:            agentName,
			AgentMetrics:         ctx.cipherMetrics,
			PubSubControllerCert: ctx.subControllerCert,
			PubSubEdgeNodeCert:   ctx.subEdgeNodeCert,
		},
		ctx.clusterConfig.CipherToken)
	if ctx.pubCipherBlockStatus != nil {
		err2 := ctx.pubCipherBlockStatus.Publish(status.Key(), status)
		if err2 != nil {
			return "", fmt.Errorf("decryptClusterToken: publish failed %v", err2)
		}
	}
	if err != nil {
		ctx.cipherMetrics.RecordFailure(log, types.DecryptFailed)
		return "", fmt.Errorf("decryptClusterToken: failed to decrypt cluster token: %v", err)
	}

	err = ctx.cipherMetrics.Publish(log, ctx.pubCipherMetrics, "global")
	if err != nil {
		log.Errorf("decryptClusterToken: publish failed for cipher metrics: %v", err)
		return "", fmt.Errorf("decryptClusterToken: failed to publish cipher metrics: %v", err)
	}

	return decBlock.ClusterToken, nil
}

func updateClusterIPReadiness(ctx *zedkubeContext) (changed bool) {
	var ready bool
	haveClusterIPConfig := ctx.clusterConfig.ClusterInterface != "" &&
		ctx.clusterConfig.ClusterIPPrefix != nil
	if haveClusterIPConfig {
		for _, port := range ctx.deviceNetworkStatus.Ports {
			if port.InvalidConfig || port.IfName == "" {
				continue
			}
			if port.Logicallabel != ctx.clusterConfig.ClusterInterface {
				continue
			}
			for _, addr := range port.AddrInfoList {
				if addr.Addr.Equal(ctx.clusterConfig.ClusterIPPrefix.IP) {
					ready = true
					break
				}
			}
			if ready {
				break
			}
		}
	}
	if ctx.clusterIPIsReady != ready {
		ctx.clusterIPIsReady = ready
		return true
	}
	return false
}

func startClusterStatusServer(ctx *zedkubeContext) {
	if ctx.statusServer != nil {
		// Already running.
		return
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		clusterStatusHTTPHandler(w, r, ctx)
	})
	ctx.statusServer = &http.Server{
		Addr:    ctx.clusterConfig.ClusterIPPrefix.IP.String() + ":" + types.ClusterStatusPort,
		Handler: mux,
	}
	ctx.statusServerWG.Add(1)

	// Start the server in a goroutine
	go func() {
		defer ctx.statusServerWG.Done()
		if err := ctx.statusServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Errorf("Cluster status server ListenAndServe failed: %v", err)
		}
		log.Noticef("Cluster status server stopped")
	}()
}

func stopClusterStatusServer(ctx *zedkubeContext) {
	if ctx.statusServer == nil {
		return
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := ctx.statusServer.Shutdown(shutdownCtx); err != nil {
		log.Errorf("Cluster status server shutdown failed: %v", err)
	} else {
		log.Noticef("Cluster status server shutdown completed")
	}

	// Wait for the server goroutine to finish
	ctx.statusServerWG.Wait()
	ctx.statusServer = nil
	log.Noticef("Cluster status server goroutine has stopped")
}

func clusterStatusHTTPHandler(w http.ResponseWriter, r *http.Request, ctx *zedkubeContext) {
	clientset, err := getKubeClientSet()
	if err != nil {
		log.Errorf("clusterStatusHTTPHandler: can't get clientset %v", err)
		fmt.Fprint(w, "")
		return
	}

	err = getnodeNameAndUUID(ctx)
	if err != nil {
		log.Errorf("clusterStatusHTTPHandler: Error getting nodeName and nodeUUID")
		fmt.Fprint(w, "")
		return
	}

	node, err := clientset.CoreV1().Nodes().Get(context.Background(), ctx.nodeName, metav1.GetOptions{})
	if err != nil {
		log.Errorf("clusterStatusHTTPHandler: can't get node %v, for %s", err, ctx.nodeName)
		fmt.Fprint(w, "")
		return
	}

	var isMaster, useEtcd bool
	labels := node.GetLabels()
	if _, ok := labels["node-role.kubernetes.io/master"]; ok {
		isMaster = true
	}
	if _, ok := labels["node-role.kubernetes.io/etcd"]; ok {
		useEtcd = true
	}

	if isMaster && useEtcd {
		fmt.Fprint(w, "cluster")
		return
	}
	log.Functionf("clusterStatusHTTPHandler: not master or etcd")
	fmt.Fprint(w, "")
}

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
	z := ctxArg.(*zedkube)
	dns := statusArg.(types.DeviceNetworkStatus)
	z.applyDNS(dns)
}

func handleDNSModify(ctxArg interface{}, _ string, statusArg interface{}, _ interface{}) {
	z := ctxArg.(*zedkube)
	dns := statusArg.(types.DeviceNetworkStatus)
	z.applyDNS(dns)
}

func (z *zedkube) applyDNS(dns types.DeviceNetworkStatus) {
	z.deviceNetworkStatus = dns
	changed := z.updateClusterIPReadiness()
	if changed {
		if z.clusterIPIsReady {
			if z.statusServer == nil {
				z.startClusterStatusServer()
			}
		} else {
			if z.statusServer != nil {
				z.stopClusterStatusServer()
			}
		}
		z.publishKubeConfigStatus()
	}
}

func (z *zedkube) applyClusterConfig(config, oldconfig *types.EdgeNodeClusterConfig) {
	noChange := reflect.DeepEqual(config, oldconfig)
	if noChange {
		log.Noticef("getKubeConfig: no change in cluster config")
		return
	}
	if config == nil {
		// Before we let NIM to remove the cluster IP, we need to remove the node
		// from the cluster.
		z.stopClusterStatusServer()
		z.clusterConfig = types.EdgeNodeClusterConfig{}
		return
	} else {
		clusterIPChanged := !netutils.EqualIPNets(z.clusterConfig.ClusterIPPrefix,
			config.ClusterIPPrefix)
		z.clusterConfig = *config
		if clusterIPChanged {
			z.stopClusterStatusServer()
			z.updateClusterIPReadiness()
			if z.clusterIPIsReady {
				z.startClusterStatusServer()
			}
		}
	}
	z.publishKubeConfigStatus()
}

// publishKubeConfigStatus publishes the cluster config status
func (z *zedkube) publishKubeConfigStatus() {
	status := types.EdgeNodeClusterStatus{
		ClusterName:      z.clusterConfig.ClusterName,
		ClusterID:        z.clusterConfig.ClusterID,
		ClusterInterface: z.clusterConfig.ClusterInterface,
		ClusterIPPrefix:  z.clusterConfig.ClusterIPPrefix,
		ClusterIPIsReady: z.clusterIPIsReady,
		IsWorkerNode:     z.clusterConfig.IsWorkerNode,
		JoinServerIP:     z.clusterConfig.JoinServerIP,
		BootstrapNode:    z.clusterConfig.BootstrapNode,
	}

	if z.clusterConfig.CipherToken.IsCipher {
		decToken, err := z.decryptClusterToken()
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
	z.pubEdgeNodeClusterStatus.Publish("global", status)
}

func (z *zedkube) decryptClusterToken() (string, error) {
	if !z.clusterConfig.CipherToken.IsCipher {
		return "", fmt.Errorf("decryptClusterToken: cluster token is not encrypted")
	}

	decryptAvailable := z.subControllerCert != nil && z.subEdgeNodeCert != nil
	if !decryptAvailable {
		return "", fmt.Errorf("decryptClusterToken: certificates are not available")
	}
	status, decBlock, err := cipher.GetCipherCredentials(
		&cipher.DecryptCipherContext{
			Log:                  log,
			AgentName:            agentName,
			AgentMetrics:         z.cipherMetrics,
			PubSubControllerCert: z.subControllerCert,
			PubSubEdgeNodeCert:   z.subEdgeNodeCert,
		},
		z.clusterConfig.CipherToken)
	if z.pubCipherBlockStatus != nil {
		err2 := z.pubCipherBlockStatus.Publish(status.Key(), status)
		if err2 != nil {
			return "", fmt.Errorf("decryptClusterToken: publish failed %v", err2)
		}
	}
	if err != nil {
		z.cipherMetrics.RecordFailure(log, types.DecryptFailed)
		return "", fmt.Errorf("decryptClusterToken: failed to decrypt cluster token: %v", err)
	}

	err = z.cipherMetrics.Publish(log, z.pubCipherMetrics, "global")
	if err != nil {
		log.Errorf("decryptClusterToken: publish failed for cipher metrics: %v", err)
		return "", fmt.Errorf("decryptClusterToken: failed to publish cipher metrics: %v", err)
	}

	return decBlock.ClusterToken, nil
}

func (z *zedkube) updateClusterIPReadiness() (changed bool) {
	var ready bool
	haveClusterIPConfig := z.clusterConfig.ClusterInterface != "" &&
		z.clusterConfig.ClusterIPPrefix != nil
	if haveClusterIPConfig {
		for _, port := range z.deviceNetworkStatus.Ports {
			if port.InvalidConfig || port.IfName == "" {
				continue
			}
			if port.Logicallabel != z.clusterConfig.ClusterInterface {
				continue
			}
			for _, addr := range port.AddrInfoList {
				if addr.Addr.Equal(z.clusterConfig.ClusterIPPrefix.IP) {
					ready = true
					break
				}
			}
			if ready {
				break
			}
		}
	}
	if z.clusterIPIsReady != ready {
		z.clusterIPIsReady = ready
		return true
	}
	return false
}

func (z *zedkube) startClusterStatusServer() {
	if z.statusServer != nil {
		// Already running.
		return
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		z.clusterStatusHTTPHandler(w, r)
	})
	z.statusServer = &http.Server{
		// Listen on the ClusterIPPrefix IP and the ClusterStatusPort
		// the firewall rule is explicitly added to allow traffic to this port in kubevirt
		// this is documented in pkg/pillar/docs/zedkube.md section "Cluster Status Server"
		Addr:    z.clusterConfig.ClusterIPPrefix.IP.String() + ":" + types.ClusterStatusPort,
		Handler: mux,
	}
	z.statusServerWG.Add(1)

	// Start the server in a goroutine
	go func() {
		defer z.statusServerWG.Done()
		if err := z.statusServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Errorf("Cluster status server ListenAndServe failed: %v", err)
		}
		log.Noticef("Cluster status server stopped")
	}()
}

func (z *zedkube) stopClusterStatusServer() {
	if z.statusServer == nil {
		return
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := z.statusServer.Shutdown(shutdownCtx); err != nil {
		log.Errorf("Cluster status server shutdown failed: %v", err)
	} else {
		log.Noticef("Cluster status server shutdown completed")
	}

	// Wait for the server goroutine to finish
	z.statusServerWG.Wait()
	z.statusServer = nil
	log.Noticef("Cluster status server goroutine has stopped")
}

func (z *zedkube) clusterStatusHTTPHandler(w http.ResponseWriter, r *http.Request) {
	// Check if the request method is GET
	if r.Method != http.MethodGet {
		// Respond with 405 Method Not Allowed if the method is not GET
		w.WriteHeader(http.StatusMethodNotAllowed)
		w.Write([]byte("405 - Method Not Allowed"))
		return
	}

	clientset, err := getKubeClientSet()
	if err != nil {
		log.Errorf("clusterStatusHTTPHandler: can't get clientset %v", err)
		fmt.Fprint(w, "")
		return
	}

	node, err := clientset.CoreV1().Nodes().Get(context.Background(), z.nodeName, metav1.GetOptions{})
	if err != nil {
		log.Errorf("clusterStatusHTTPHandler: can't get node %v, for %s", err, z.nodeName)
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

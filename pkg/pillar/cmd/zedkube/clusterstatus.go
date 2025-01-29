// Copyright (c) 2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build kubevirt

package zedkube

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"reflect"
	"strings"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/agentbase"
	"github.com/lf-edge/eve/pkg/pillar/cipher"
	"github.com/lf-edge/eve/pkg/pillar/kubeapi"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/utils/netutils"
	uuid "github.com/satori/go.uuid"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
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
	mux.HandleFunc("/app", func(w http.ResponseWriter, r *http.Request) {
		z.appIDHandler(w, r)
	})
	mux.HandleFunc("/app/", func(w http.ResponseWriter, r *http.Request) {
		z.appIDHandler(w, r)
	})

	mux.HandleFunc("/cluster-app", func(w http.ResponseWriter, r *http.Request) {
		z.clusterAppIDHandler(w, r)
	})
	mux.HandleFunc("/cluster-app/", func(w http.ResponseWriter, r *http.Request) {
		z.clusterAppIDHandler(w, r)
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

func (z *zedkube) appIDHandler(w http.ResponseWriter, r *http.Request) {
	// Extract the UUID from the URL
	uuidStr := strings.TrimPrefix(r.URL.Path, "/app")
	uuidStr = strings.TrimPrefix(uuidStr, "/")

	af := agentbase.GetApplicationInfo("/run/", "/persist/status/", "/persist/kubelog/", uuidStr)
	if af.AppInfo == nil {
		http.Error(w, "App not found", http.StatusNotFound)
		return
	}
	appInfoJSON, err := json.MarshalIndent(af, "", "  ")
	if err != nil {
		http.Error(w, "Error marshalling appInfo to JSON", http.StatusInternalServerError)
		return
	}
	// Handle the request for the given UUID
	fmt.Fprintf(w, "%s", appInfoJSON)
}

func (z *zedkube) clusterAppIDHandler(w http.ResponseWriter, r *http.Request) {
	// Extract the UUID from the URL
	uuidStr := strings.TrimPrefix(r.URL.Path, "/cluster-app")
	uuidStr = strings.TrimPrefix(uuidStr, "/")

	af := agentbase.GetApplicationInfo("/run/", "/persist/status/", "/persist/kubelog/", uuidStr)
	if af.AppInfo == nil {
		http.Error(w, "App not found", http.StatusNotFound)
		return
	}
	appInfoJSON, err := json.MarshalIndent(af, "", "  ")
	if err != nil {
		http.Error(w, "Error marshalling appInfo to JSON", http.StatusInternalServerError)
		return
	}

	// Initialize combined JSON with local app info
	combinedJSON := `{
  "key": "cluster-app",
  "value": [` + strings.TrimSuffix(string(appInfoJSON), "\n")

	hosts, notClusterMode, err := z.getClusterNodeIPs()
	if err == nil && !notClusterMode {
		for _, host := range hosts {
			client := &http.Client{
				Timeout: 5 * time.Second, // Set a timeout of 5 seconds (adjust as needed)
			}
			req, err := http.NewRequest("POST", "http://"+host+":"+types.ClusterStatusPort+"/app/"+uuidStr, nil)
			if err != nil {
				log.Errorf("clusterAppIDHandler: %v", err)
				continue
			}

			resp, err := client.Do(req)
			if err != nil {
				if os.IsTimeout(err) {
					errorInfo := struct {
						Hostname string `json:"hostname"`
						Errors   string `json:"errors"`
					}{
						Hostname: host,
						Errors:   err.Error(),
					}
					errorJSON, jsonErr := json.MarshalIndent(errorInfo, "", "  ")
					if jsonErr != nil {
						log.Errorf("clusterAppIDHandler: error marshalling error info to JSON: %v", jsonErr)
					} else {
						// Append the error JSON to combinedJSON
						combinedJSON = combinedJSON + "," + string(errorJSON)
					}
				} else {
					log.Errorf("clusterAppIDHandler: %v", err)
				}
				continue
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				log.Errorf("clusterAppIDHandler: received non-OK status %d from %s", resp.StatusCode, host)
				continue
			}

			remoteAppInfoJSON, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				log.Errorf("clusterAppIDHandler: error reading response from %s: %v", host, err)
				continue
			}

			// Replace outermost { and } with [ and ] in remoteAppInfoJSON
			combinedJSON = combinedJSON + "," + strings.TrimSuffix(string(remoteAppInfoJSON), "\n")
		}
	}

	// Ensure the combined JSON is properly closed
	combinedJSON += "]\n}\n"

	// Return the combined JSON to the caller
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(combinedJSON))
}

func (z *zedkube) checkAppNameForUUID(appStr string) (string, error) {
	// Verify the extracted UUID string
	if _, err := uuid.FromString(appStr); err != nil {
		// then check if this is the app Name
		sub := z.subAppInstanceConfig
		items := sub.GetAll()
		if len(items) == 0 {
			return "", fmt.Errorf("App not found")
		}
		var foundApp bool
		for _, item := range items {
			aiconfig := item.(types.AppInstanceConfig)
			if aiconfig.DisplayName == appStr {
				appStr = aiconfig.UUIDandVersion.UUID.String()
				foundApp = true
				break
			}
		}
		if !foundApp {
			return "", fmt.Errorf("App not found")
		}
	}
	return appStr, nil
}

func (z *zedkube) getClusterNodeIPs() ([]string, bool, error) {
	if !z.clusterIPIsReady {
		return nil, true, nil
	}

	config, err := kubeapi.GetKubeConfig()
	if err != nil {
		log.Errorf("getClusterNodes: config is nil")
		return nil, false, err
	}
	z.config = config

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		log.Errorf("collectAppLogs: can't get clientset %v", err)
		return nil, false, err
	}

	nodes, err := clientset.CoreV1().Nodes().List(context.Background(), metav1.ListOptions{})
	if err != nil {
		log.Errorf("Error getting cluster nodes")
		return nil, false, err
	}

	// get all the nodes internal ip addresses except for my own
	clusterIPStr := z.clusterConfig.ClusterIPPrefix.IP.String()
	var hosts []string
	for _, node := range nodes.Items {
		for _, addr := range node.Status.Addresses {
			if addr.Type == corev1.NodeInternalIP && addr.Address != clusterIPStr {
				hosts = append(hosts, addr.Address)
			}
		}
	}
	return hosts, false, nil
}

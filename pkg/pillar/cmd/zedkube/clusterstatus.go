// Copyright (c) 2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build k

package zedkube

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
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
		// NIM can publish network status due to cluster config
		// removal, and we don't want to publish the dummy/empty
		// cluster status in that case.
		if z.clusterConfig.ClusterInterface != "" {
			z.publishKubeConfigStatus()
			return
		}
	}
	// The LB-CIDR / mgmt-IP overlap check is independent of the cluster
	// interface: the LB interface may be a different port, and the mgmt IP on
	// the LB interface can change (via DHCP or static reconfiguration) without
	// affecting cluster-IP readiness. Re-publish on every DNS update when LB is
	// configured so the
	// per-node check re-runs on all nodes (bootstrap and non-bootstrap);
	// pubsub de-dupes unchanged payloads.
	if len(z.clusterConfig.LBInterfaces) > 0 {
		z.publishKubeConfigStatus()
	}
}

// The controller or edge-node cert the Token decryption depends on might be updated
// later than the initial waiting for. Re-publish it.
func (z *zedkube) applyCertsChange(certtype string) {
	if z.clusterIPIsReady && z.clusterConfig.ClusterInterface != "" {
		// Publication is created in Run(); just check if there's a published value.
		st, err := z.pubEdgeNodeClusterStatus.Get("global")
		if err != nil {
			// no value published yet -> publish now
			z.publishKubeConfigStatus()
			return
		}

		existing, ok := st.(types.EdgeNodeClusterStatus)
		if !ok || existing.EncryptedClusterToken == "" {
			// unexpected type or token missing -> publish
			log.Noticef("applyCertsChange: re-publishing kube config status due to %s cert update", certtype)
			z.publishKubeConfigStatus()
		}
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
		drainAndDeleteNode(z)
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
		ClusterInterface: z.resolveClusterInterfaceName(),
		ClusterIPPrefix:  z.clusterConfig.ClusterIPPrefix,
		ClusterIPIsReady: z.clusterIPIsReady,
		IsWorkerNode:     z.clusterConfig.IsWorkerNode,
		JoinServerIP:     z.clusterConfig.JoinServerIP,
		BootstrapNode:    z.clusterConfig.BootstrapNode,
	}

	if z.clusterConfig.CipherToken.IsCipher {
		decToken, decGzipManifest, err := z.decryptClusterTokenAndManifest()
		if err != nil {
			log.Errorf("publishKubeConfigStatus: failed to decrypt cluster token: %v", err)
			status.Error = types.ErrorDescription{
				Error:     err.Error(),
				ErrorTime: time.Now(),
			}
		} else {
			status.EncryptedClusterToken = decToken

			// Don't store the decrypted manifest in EdgeNodeClusterStatus as its a pubsub published
			// structure and could lead to some log.Fatal due to this buffer size.
			regExists, err := kubeapi.RegistrationExists(kubeapi.PillarPersistManifestPath)
			if regExists && (err == nil) {
				log.Warn("Registration exists, overwriting")
			}
			if z.clusterConfig.BootstrapNode && (len(decGzipManifest) != 0) {
				go func() {
					err := kubeapi.RegistrationAdd(kubeapi.PillarPersistManifestPath, decGzipManifest)
					if err != nil {
						log.Errorf("Registration err:%v", err)
					} else {
						log.Noticef("Registration success")
					}
				}()
			}
		}
	} else {
		log.Errorf("publishKubeConfigStatus: cluster token is not from configitme or encrypted")
	}

	// All nodes populate LBIPPrefixes so dpcmanager can filter kube-vip VIPs
	// (/32 host-route addresses) from AddrInfoList regardless of bootstrap role.
	for _, lb := range z.clusterConfig.LBInterfaces {
		if lb.IPPrefix != "" {
			status.LBIPPrefixes = append(status.LBIPPrefixes, lb.IPPrefix)
		}
	}

	// Only the bootstrap node manages kube-vip load balancing; other nodes leave
	// LBInterfaces empty so cluster-init.sh does not apply kubevip.
	// All nodes check whether their own mgmt IPs conflict with any LB CIDR and
	// report the result in LBConfigError so the controller can see per-node
	// conflicts even from non-bootstrap nodes.
	if z.clusterConfig.BootstrapNode {
		// resolveLBInterfaces runs the overlap check and caches the error in
		// z.lbConfigError; it omits conflicting entries from the returned list.
		status.LBInterfaces = z.resolveLBInterfaces()
		status.LBConfigError = z.lbConfigError
	} else {
		// Non-bootstrap nodes do not control kube-vip, but they still check
		// their own mgmt IPs against each LB CIDR and report any conflict.
		status.LBConfigError = z.checkLBCIDRConflict()
	}

	// publish the cluster status for the kube container
	log.Functionf("publishKubeConfigStatus: publishing")
	z.pubEdgeNodeClusterStatus.Publish("global", status)
}

func (z *zedkube) resolveClusterInterfaceName() string {
	if z.clusterConfig.ClusterInterface == "" {
		return ""
	}
	port := z.deviceNetworkStatus.LookupPortByLogicallabel(z.clusterConfig.ClusterInterface)
	if port == nil {
		return ""
	}
	return port.IfName
}

// resolveLBInterfaces translates the logical-label in each LBInterfaceConfig.Interface
// to the Linux interface name required by cluster-init.sh / kube-vip. For each
// entry it checks ALL L3 ports against the LB CIDR: an IP on any L3 port
// (mgmt or app-shared) could be allocated as a VIP by kube-vip-cloud-provider,
// and when the /32 floats to another node it wins ARP for that IP, causing
// routing conflicts. On a conflict the offending entry is dropped and
// z.lbConfigError is populated so collectLBPoolStatus can surface it to the
// controller; a clean pass clears it.
func (z *zedkube) resolveLBInterfaces() []types.LBInterfaceConfig {
	var resolved []types.LBInterfaceConfig
	var confErr types.ErrorDescription
	for _, lb := range z.clusterConfig.LBInterfaces {
		port := z.deviceNetworkStatus.LookupPortByLogicallabel(lb.Interface)
		if port == nil {
			msg := fmt.Sprintf("LB interface %q not found in device network status; kube-vip not applied",
				lb.Interface)
			log.Errorf("resolveLBInterfaces: %s", msg)
			confErr.SetErrorDescription(types.ErrorDescription{Error: msg})
			continue
		}
		if port.IfName == "" {
			msg := fmt.Sprintf("LB interface %q has empty Linux interface name; kube-vip not applied",
				lb.Interface)
			log.Errorf("resolveLBInterfaces: %s", msg)
			confErr.SetErrorDescription(types.ErrorDescription{Error: msg})
			continue
		}
		_, lbNet, err := net.ParseCIDR(lb.IPPrefix)
		if err != nil {
			msg := fmt.Sprintf("invalid LB CIDR %q for interface %q: %v; kube-vip not applied",
				lb.IPPrefix, lb.Interface, err)
			log.Errorf("resolveLBInterfaces: %s", msg)
			confErr.SetErrorDescription(types.ErrorDescription{Error: msg})
			continue
		}
		conflict := false
		for i := range z.deviceNetworkStatus.Ports {
			p := &z.deviceNetworkStatus.Ports[i]
			if !p.IsL3Port {
				continue
			}
			if ip := findPortIPInCIDR(p, lbNet); ip != nil {
				msg := fmt.Sprintf(
					"LB CIDR %s contains local IP %s on port %s; kube-vip not applied",
					lb.IPPrefix, ip, p.Logicallabel)
				log.Errorf("resolveLBInterfaces: %s", msg)
				confErr.SetErrorDescription(types.ErrorDescription{Error: msg})
				conflict = true
				break
			}
		}
		if conflict {
			continue
		}
		resolved = append(resolved, types.LBInterfaceConfig{
			Interface: port.IfName,
			IPPrefix:  lb.IPPrefix,
		})
	}
	// Preserve ErrorTime when the error string is unchanged to avoid spurious
	// pubsub publishes on every DNS update (pubsub uses deep equality).
	if confErr.Error != "" && confErr.Error == z.lbConfigError.Error {
		confErr = z.lbConfigError
	}
	z.lbConfigError = confErr
	return resolved
}

// findPortIPInCIDR returns the first IP of port that falls inside lbNet, or nil.
func findPortIPInCIDR(port *types.NetworkPortStatus, lbNet *net.IPNet) net.IP {
	if port == nil || lbNet == nil {
		return nil
	}
	for _, ai := range port.AddrInfoList {
		if ai.Addr == nil {
			continue
		}
		if lbNet.Contains(ai.Addr) {
			return ai.Addr
		}
	}
	return nil
}

// checkLBCIDRConflict checks ALL L3 ports against each LB CIDR. An IP on any
// L3 port (mgmt or app-shared) could be allocated as a VIP by
// kube-vip-cloud-provider; when the /32 floats to another node it wins ARP for
// that IP, causing routing conflicts. Updates and returns z.lbConflictError;
// empty means no conflict. Runs on all nodes (bootstrap and non-bootstrap) so
// each node reports its own verdict via LBConfigError.
func (z *zedkube) checkLBCIDRConflict() types.ErrorDescription {
	for _, lb := range z.clusterConfig.LBInterfaces {
		if lb.IPPrefix == "" {
			continue
		}
		_, lbNet, err := net.ParseCIDR(lb.IPPrefix)
		if err != nil {
			// Controller validates CIDRs before sending; log and skip.
			log.Errorf("checkLBCIDRConflict: invalid LB CIDR %s: %v", lb.IPPrefix, err)
			continue
		}
		for i := range z.deviceNetworkStatus.Ports {
			p := &z.deviceNetworkStatus.Ports[i]
			if !p.IsL3Port || p.IfName == "" {
				continue
			}
			if ip := findPortIPInCIDR(p, lbNet); ip != nil {
				msg := fmt.Sprintf(
					"LB CIDR %s contains local IP %s on port %s",
					lb.IPPrefix, ip, p.Logicallabel)
				log.Errorf("checkLBCIDRConflict: %s", msg)
				// Preserve ErrorTime for the same persistent conflict to avoid
				// spurious pubsub publishes on every DNS update.
				if msg != z.lbConflictError.Error {
					z.lbConflictError.SetErrorDescription(types.ErrorDescription{Error: msg})
				}
				return z.lbConflictError
			}
		}
	}
	z.lbConflictError = types.ErrorDescription{}
	return types.ErrorDescription{}
}

func (z *zedkube) decryptClusterTokenAndManifest() (string, []byte, error) {
	if !z.clusterConfig.CipherToken.IsCipher {
		return "", []byte{}, fmt.Errorf("decryptClusterTokenAndManifest: cluster token is not encrypted")
	}

	decryptAvailable := z.subControllerCert != nil && z.subEdgeNodeCert != nil
	if !decryptAvailable {
		return "", []byte{}, fmt.Errorf("decryptClusterTokenAndManifest: certificates are not available")
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
			return "", []byte{}, fmt.Errorf("decryptClusterTokenAndManifest: publish failed %v", err2)
		}
	}
	if err != nil {
		z.cipherMetrics.RecordFailure(log, types.DecryptFailed)
		return "", []byte{}, fmt.Errorf("decryptClusterTokenAndManifest: failed to decrypt cluster token: %v", err)
	}

	err = z.cipherMetrics.Publish(log, z.pubCipherMetrics, "global")
	if err != nil {
		log.Errorf("decryptClusterTokenAndManifest: publish failed for cipher metrics: %v", err)
		return "", []byte{}, fmt.Errorf("decryptClusterTokenAndManifest: failed to publish cipher metrics: %v", err)
	}

	return decBlock.ClusterToken, decBlock.GzipRegistrationManifestYaml, nil
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
			if port.ClusterIPAddr != nil &&
				port.ClusterIPAddr.Equal(z.clusterConfig.ClusterIPPrefix.IP) {
				ready = true
				break
			}
		}
	}
	resolvedName := z.resolveClusterInterfaceName()
	ifNameChanged := z.lastPublishedClusterIfName != resolvedName
	if ifNameChanged {
		z.lastPublishedClusterIfName = resolvedName
	}
	if z.clusterIPIsReady != ready || ifNameChanged {
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
	serverAddr := net.JoinHostPort(
		z.clusterConfig.ClusterIPPrefix.IP.String(), types.ClusterStatusPort)
	z.statusServer = &http.Server{
		// Listen on the ClusterIPPrefix IP and the ClusterStatusPort
		// the firewall rule is explicitly added to allow traffic to this port in EVE 'k'
		// this is documented in pkg/pillar/docs/zedkube.md section "Cluster Status Server"
		Addr:    serverAddr,
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

// clusterStatusHTTPHandler handles HTTP requests for the cluster status
// If the node is a master and etcd node, it returns the cluster status in the format:
// cluster:<cluster-uuid>
// Otherwise, it returns an empty response.
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

	var isControlPlane, isMaster, useEtcd bool
	labels := node.GetLabels()
	if _, ok := labels["node-role.kubernetes.io/master"]; ok {
		isMaster = true
	}
	// Master label removed: https://github.com/k3s-io/k3s/pull/12395
	if controlPlaneVal, ok := labels["node-role.kubernetes.io/control-plane"]; ok {
		isControlPlane = (controlPlaneVal == "true")
	}
	if _, ok := labels["node-role.kubernetes.io/etcd"]; ok {
		useEtcd = true
	}

	if (isControlPlane || isMaster) && useEtcd {
		// Return cluster status with cluster UUID: cluster:<cluster-uuid>
		clusterUUID := z.clusterConfig.ClusterID.UUID.String()
		fmt.Fprintf(w, "cluster:%s", clusterUUID)
		return
	}
	log.Functionf("clusterStatusHTTPHandler: not control-plane and etcd")
	fmt.Fprint(w, "")
}

func (z *zedkube) appIDHandler(w http.ResponseWriter, r *http.Request) {
	// Extract the UUID from the URL
	uuidStr := strings.TrimPrefix(r.URL.Path, "/app")
	uuidStr = strings.TrimPrefix(uuidStr, "/")

	af := agentbase.GetApplicationInfo("/run/", "/persist/kubelog/", uuidStr)
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

	af := agentbase.GetApplicationInfo("/run/", "/persist/kubelog/", uuidStr)
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

			if resp.StatusCode != http.StatusOK {
				log.Errorf("clusterAppIDHandler: received non-OK status %d from %s", resp.StatusCode, host)
				continue
			}

			remoteAppInfoJSON, err := ioutil.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil {
				log.Errorf("clusterAppIDHandler: error reading response from %s: %v", host, err)
				continue
			}
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

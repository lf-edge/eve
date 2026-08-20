// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build k

package zedkube

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	netattdefv1 "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/apis/k8s.cni.cncf.io/v1"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/kubeapi"
	"github.com/lf-edge/eve/pkg/pillar/types"
	utils "github.com/lf-edge/eve/pkg/pillar/utils/file"
	uuid "github.com/satori/go.uuid"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// Synthesizing AppNetworkConfig for directly-deployed Kubernetes workloads.
//
// Such workloads (raw yaml / helm charts) have no controller-assigned
// AppInstanceConfig, so zedrouter has no AppNetworkConfig to drive MAC/IP
// allocation and to match inbound CNI requests against. zedkube fills that
// gap: it watches the pods scheduled on THIS node that attach to a per-NI NAD
// ("eve-kube-app/ni-<...>") and publishes a synthesized types.AppNetworkConfig
// (with KubeApp set) which zedrouter consumes through its normal pipeline
// (subKubeAppNetworkConfig -> handleAppNetworkCreate -> doActivateAppNetwork).
//
// Node scope: like controller-managed clustered apps (see zedmanager
// getKubeAppActivateStatus), the network is activated only on the node where
// the workload runs. Each node publishes to its OWN local zedrouter; this is
// deliberately NOT leader-gated (contrast with the cluster-wide NAD in
// ninad.go). On migration the pod reappears on another node, whose zedkube
// then publishes; the CNI plugin's own retries cover the brief gap.
//
// Identity: the synthetic appUUID is base.KubeAppUUID(namespace, ownerName),
// where ownerName is the workload's controlling owner (the bare ReplicaSet
// for an RS-style app), or the pod name itself for an ownerless bare Pod. It
// is a pure function of stable metadata, so every node and every restart
// derive the same UUID -> the ClusterDeterministic MAC stays stable across
// reboot and migration. A same-named bare Pod therefore retains its network
// identity when recreated. For a Deployment Pod, the immediate ReplicaSet
// owner remains the network identity while the controlling Deployment name is
// used as the human-facing AppNetworkConfig display/DNS name.
//
// VMIs (virt-launcher pods) are intentionally skipped here: their pod name is
// "virt-launcher-<vmi>-<rand>", which the zedrouter matcher
// (KubePodMatchesOwner) does not yet resolve. RS-style workloads are the
// supported shape; VMI support is a follow-up.

const networksAnnotation = "k8s.v1.cni.cncf.io/networks"

// kubeAppMarkerDir holds one marker file per pod scheduled on this node -- for
// every pod, not just NI-attached ones. eve-bridge has no Kubernetes API
// access of its own, so it reads "<dir>/<namespace>_<podname>" at eth0-CNI
// time to learn how to route that pod's primary interface (see
// kubeAppNetKind). A missing marker makes the primary-interface CNI call fail
// so the kubelet retries, rather than guess: zedkube is now the sole
// classifier for every pod on the node, and a zedkube crash is an acceptable
// dependency because the watchdog reboots the whole device when an agent
// stops kicking. THIS PATH, AND THE kubeAppNetKind VALUES BELOW, ARE A
// CONTRACT shared with pkg/kube/eve-bridge.
const kubeAppMarkerDir = "/run/zedkube/kubeapp-net"

// kubeAppNetKind is the marker file content: how eve-bridge should route a
// pod's primary eth0 interface. Kept as a bare string rather than JSON since a
// marker only ever says one of these three things.
type kubeAppNetKind string

const (
	// kubeAppNetKindController: a controller-managed (ENC) app. eth0 is not
	// the default route; explicit routes to the Kubernetes node/service
	// subnets are added on eth0 instead so the app can still reach the
	// Kubernetes API, and the app's Network Instance interface becomes the
	// default route via its own DHCP lease.
	kubeAppNetKindController kubeAppNetKind = "controller"
	// kubeAppNetKindNative: an ordinary Kubernetes pod, or a native
	// workload that did not request a different default route. eth0 stays
	// the default route.
	kubeAppNetKindNative kubeAppNetKind = "native"
	// kubeAppNetKindNativeNIDefault: a native workload whose networks
	// annotation set default-route on one of its Network Instance
	// attachments. Routed the same as kubeAppNetKindController: eth0 is not
	// the default route, with explicit node/service routes added, so the
	// requested NI can become the default instead.
	kubeAppNetKindNativeNIDefault kubeAppNetKind = "native-ni-default"
)

// reconcileKubeAppNetworks lists the pods scheduled on this node,
// (re)publishes a synthesized AppNetworkConfig for each directly-deployed
// workload attaching to a per-NI NAD, and (re)writes the primary-interface
// routing marker for every pod on the node.
func (z *zedkube) reconcileKubeAppNetworks() {
	z.reconcileKubeAppNetworksWithClient(getKubeClientSet)
}

func (z *zedkube) reconcileKubeAppNetworksWithClient(
	getClient func() (*kubernetes.Clientset, error)) {
	if z.nodeName == "" {
		// Node identity not known yet; nothing to reconcile against.
		return
	}
	clientset, err := getClient()
	if err != nil {
		log.Errorf("reconcileKubeAppNetworks: clientset: %v", err)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	pods, err := clientset.CoreV1().Pods("").List(ctx, metav1.ListOptions{
		FieldSelector: "spec.nodeName=" + z.nodeName,
	})
	if err != nil {
		log.Errorf("reconcileKubeAppNetworks: list pods on %s: %v", z.nodeName, err)
		return
	}
	replicaSets, err := clientset.AppsV1().ReplicaSets("").List(ctx, metav1.ListOptions{})
	if err != nil {
		// Keep networking functional if owner lookup temporarily fails. DNS
		// names will use the immediate ReplicaSet owner until a later
		// reconciliation succeeds.
		log.Warnf("reconcileKubeAppNetworks: list ReplicaSets: %v", err)
	}
	var deploymentNames map[string]string
	if replicaSets != nil {
		deploymentNames = deploymentNamesByReplicaSet(replicaSets.Items)
	}

	desired := make(map[string]types.AppNetworkConfig)
	markers := make(map[string]kubeAppNetKind, len(pods.Items))
	for i := range pods.Items {
		pod := &pods.Items[i]
		config, niDefault, attached := z.kubeAppNetConfigForPod(pod, deploymentNames)
		if attached {
			desired[config.Key()] = config
		}
		markerName := kubeAppMarkerName(pod.Namespace, pod.Name)
		markers[markerName] = kubeAppNetKindFor(pod, attached, niDefault)
	}

	for key, config := range desired {
		c := config
		if err := z.pubKubeAppNetworkConfig.Publish(key, c); err != nil {
			log.Errorf("reconcileKubeAppNetworks: publish %s: %v", key, err)
		}
	}
	for key := range z.pubKubeAppNetworkConfig.GetAll() {
		if _, ok := desired[key]; !ok {
			if err := z.pubKubeAppNetworkConfig.Unpublish(key); err != nil {
				log.Errorf("reconcileKubeAppNetworks: unpublish %s: %v", key, err)
			}
		}
	}
	reconcileKubeAppMarkers(markers)
}

// kubeAppNetConfigForPod builds the synthesized AppNetworkConfig for a single
// pod. attached is false if the pod is not a directly-deployed workload
// attaching to a per-NI NAD, in which case config and niDefault are
// meaningless. niDefault reports whether any of the pod's NI attachments
// requested default-route (see kubeAppNetKindNativeNIDefault).
// A pod referencing the same NI more than once is not supported (the CNI call
// identifies the adapter only by NI) and is left unattached, so that its
// interface setup fails visibly instead of yielding colliding interfaces.
func (z *zedkube) kubeAppNetConfigForPod(
	pod *corev1.Pod, deploymentNames map[string]string,
) (config types.AppNetworkConfig, niDefault bool, attached bool) {
	return kubeAppNetConfigForPodWithResolver(pod, deploymentNames, z.niUUIDForNAD)
}

func kubeAppNetConfigForPodWithResolver(pod *corev1.Pod,
	deploymentNames map[string]string,
	niUUIDForNAD func(namespace, nadName string) (uuid.UUID, bool),
) (config types.AppNetworkConfig, niDefault bool, attached bool) {
	// VMIs are out of scope for now (see file comment).
	if strings.HasPrefix(pod.Name, base.VMIPodNamePrefix) {
		return types.AppNetworkConfig{}, false, false
	}
	sels := parseNetworksAnnotation(pod.Annotations[networksAnnotation])
	if len(sels) == 0 {
		return types.AppNetworkConfig{}, false, false
	}
	var adapters []types.AppNetAdapterConfig
	attachedNIs := make(map[uuid.UUID]struct{})
	for _, sel := range sels {
		niUUID, matched := niUUIDForNAD(sel.Namespace, sel.Name)
		if !matched {
			continue
		}
		if _, dup := attachedNIs[niUUID]; dup {
			log.Errorf("kubeAppNetConfigForPod: pod %s/%s attaches to Network "+
				"Instance %s more than once, which is not supported",
				pod.Namespace, pod.Name, niUUID)
			return types.AppNetworkConfig{}, false, false
		}
		attachedNIs[niUUID] = struct{}{}
		gatewayVia := parseRequestedGateway(pod, sel.GatewayRequest)
		if gatewayVia != nil {
			// Makes this NI (rather than eth0) the pod's default route, via
			// the requested gateway address.
			niDefault = true
		}
		idx := len(adapters)
		adapters = append(adapters, types.AppNetAdapterConfig{
			Name:            fmt.Sprintf("net%d", idx),
			Network:         niUUID,
			AppMacAddr:      parseRequestedMAC(pod, sel.MacRequest),
			AppIPAddr:       parseRequestedIP(pod, sel.IPRequest),
			DefaultRouteVia: gatewayVia,
			IntfOrder:       uint32(idx),
			// A synthesized config with an empty ACL list would be
			// DEFAULT-DROP in zedrouter (all traffic blocked except
			// DHCP/DNS), so attach a permissive default plus any port-maps
			// requested for this specific interface.
			ACLs: buildKubeAppACLs(sel.PortMappingsRequest),
		})
	}
	if len(adapters) == 0 {
		return types.AppNetworkConfig{}, false, false
	}

	// Keep the immediate controller name as the network identity. For
	// Deployment Pods this is the ReplicaSet name, which prevents old and
	// new rollout generations from sharing a MAC. Use the Deployment name
	// only as the human-facing display/DNS name.
	ownerName, displayName := kubeAppNames(pod, deploymentNames)
	appUUID := base.KubeAppUUID(pod.Namespace, ownerName)
	config = types.AppNetworkConfig{
		UUIDandVersion:    types.UUIDandVersion{UUID: appUUID, Version: "1"},
		DisplayName:       displayName,
		Activate:          true,
		AppNetAdapterList: adapters,
		KubeApp: &types.KubeAppInfo{
			Namespace: pod.Namespace,
			OwnerName: ownerName,
		},
	}
	return config, niDefault, true
}

// parseRequestedMAC parses an optional user-requested static MAC from a
// networks-annotation selection's "mac" field. Empty or unparsable requests
// return nil (EVE then computes a MAC).
func parseRequestedMAC(pod *corev1.Pod, request string) net.HardwareAddr {
	if request == "" {
		return nil
	}
	mac, err := net.ParseMAC(request)
	if err != nil {
		log.Warnf("kubeAppNetConfigForPod: pod %s/%s bad mac %q: %v",
			pod.Namespace, pod.Name, request, err)
		return nil
	}
	return mac
}

// parseRequestedIP parses an optional user-requested static IP from a
// networks-annotation selection's "ips" field. EVE's adapter model honors at
// most one static IP per interface (AppNetAdapterConfig.AppIPAddr), so only
// the first entry is used; it may be a plain IP or a CIDR (the prefix length
// is then ignored).
func parseRequestedIP(pod *corev1.Pod, requests []string) net.IP {
	if len(requests) == 0 {
		return nil
	}
	if len(requests) > 1 {
		log.Warnf("kubeAppNetConfigForPod: pod %s/%s requested %d ips, only %q "+
			"is supported", pod.Namespace, pod.Name, len(requests), requests[0])
	}
	request := requests[0]
	if ip, _, err := net.ParseCIDR(request); err == nil {
		return ip
	}
	if ip := net.ParseIP(request); ip != nil {
		return ip
	}
	log.Warnf("kubeAppNetConfigForPod: pod %s/%s bad ip %q",
		pod.Namespace, pod.Name, request)
	return nil
}

// parseRequestedGateway parses an optional user-requested default-route gateway from a
// networks-annotation selection's "default-route" field (Multus's GatewayRequest, already
// decoded into net.IP by its own JSON unmarshaling). EVE's adapter model honors at most one
// gateway per interface, so only the first entry is used. The returned address becomes
// AppNetAdapterConfig.DefaultRouteVia: the literal next-hop the adapter's default route (if
// any) is installed via, in place of the Network Instance's own gateway -- it must be
// reachable on the Network Instance, e.g. another application's address.
func parseRequestedGateway(pod *corev1.Pod, requests []net.IP) net.IP {
	if len(requests) == 0 {
		return nil
	}
	if len(requests) > 1 {
		log.Warnf("kubeAppNetConfigForPod: pod %s/%s requested %d default-route gateways, "+
			"only %s is supported", pod.Namespace, pod.Name, len(requests), requests[0])
	}
	gw := requests[0]
	if gw == nil || gw.IsUnspecified() {
		log.Warnf("kubeAppNetConfigForPod: pod %s/%s bad default-route gateway %v",
			pod.Namespace, pod.Name, requests[0])
		return nil
	}
	return gw
}

// kubeAppNetKindFor classifies a pod for the primary-eth0 routing marker (see
// kubeAppNetKind). attached and niDefault are the kubeAppNetConfigForPod
// results for this pod.
func kubeAppNetKindFor(pod *corev1.Pod, attached, niDefault bool) kubeAppNetKind {
	if attached {
		if niDefault {
			return kubeAppNetKindNativeNIDefault
		}
		return kubeAppNetKindNative
	}
	if isControllerEVEAppPod(pod) {
		return kubeAppNetKindController
	}
	return kubeAppNetKindNative
}

// isControllerEVEAppPod reports whether pod is a controller-managed EVE
// application (ENC): running in the eve-kube-app namespace and not one of the
// CDI volume-import helper pods EVE also schedules there. zedkube is the sole
// classifier for every pod now (see kubeAppNetKind), so this replicates the
// namespace check eve-bridge used to make for itself.
func isControllerEVEAppPod(pod *corev1.Pod) bool {
	if pod.Namespace != kubeapi.EVEKubeNameSpace {
		return false
	}
	isVMI := strings.HasPrefix(pod.Name, base.VMIPodNamePrefix)
	if !isVMI && strings.HasPrefix(pod.Name, "cdi-upload-") &&
		strings.Contains(pod.Name, "-pvc-") {
		return false
	}
	return true
}

// deploymentNamesByReplicaSet maps "namespace/replicaset" to the name of its
// controlling Deployment. A directly-created ReplicaSet has no entry and
// therefore keeps its own name.
func deploymentNamesByReplicaSet(replicaSets []appsv1.ReplicaSet) map[string]string {
	names := make(map[string]string)
	for i := range replicaSets {
		rs := &replicaSets[i]
		for _, ref := range rs.OwnerReferences {
			if ref.Controller != nil && *ref.Controller && ref.Kind == "Deployment" {
				names[rs.Namespace+"/"+rs.Name] = ref.Name
				break
			}
		}
	}
	return names
}

// kubeAppNames returns the stable immediate-controller identity used for Pod
// matching and MAC generation, plus a human-facing display name used by DNS
// and status reporting.
func kubeAppNames(pod *corev1.Pod, deploymentNames map[string]string) (
	ownerName, displayName string) {
	ownerName = pod.Name
	displayName = pod.Name
	for _, ref := range pod.OwnerReferences {
		if ref.Controller == nil || !*ref.Controller {
			continue
		}
		ownerName = ref.Name
		displayName = ownerName
		if ref.Kind == "ReplicaSet" {
			deploymentKey := pod.Namespace + "/" + ownerName
			if deploymentName := deploymentNames[deploymentKey]; deploymentName != "" {
				displayName = deploymentName
			}
		}
		break
	}
	return ownerName, displayName
}

// niUUIDForNAD maps a NAD reference ("<namespace>/<name>") from a workload's
// networks annotation to the UUID of the EVE Network Instance it represents.
// Only NADs in the eve-kube-app namespace named by niNADName() (the per-NI
// NADs created in ninad.go) are matched.
func (z *zedkube) niUUIDForNAD(namespace, nadName string) (uuid.UUID, bool) {
	var statuses []types.NetworkInstanceStatus
	for _, item := range z.subNetworkInstanceStatus.GetAll() {
		statuses = append(statuses, item.(types.NetworkInstanceStatus))
	}
	return niUUIDForNADStatuses(namespace, nadName, statuses)
}

func niUUIDForNADStatuses(namespace, nadName string,
	statuses []types.NetworkInstanceStatus) (uuid.UUID, bool) {
	if namespace != kubeapi.EVEKubeNameSpace {
		return uuid.UUID{}, false
	}
	for _, status := range statuses {
		if niNADApplicable(status) && niNADName(status) == nadName {
			return status.UUIDandVersion.UUID, true
		}
	}
	return uuid.UUID{}, false
}

// parseNetworksAnnotation parses the Multus "k8s.v1.cni.cncf.io/networks"
// annotation in either supported form: a JSON array of
// NetworkSelectionElement, or a comma-separated list of
// "[namespace/]name[@interface]" entries. Per the Multus spec, only the
// JSON-array form carries "mac"/"ips"/"portMappings"/"default-route"; the
// comma-separated shorthand never has, and does not here either -- that is a
// property of the annotation grammar itself, not a parsing gap.
func parseNetworksAnnotation(val string) []netattdefv1.NetworkSelectionElement {
	val = strings.TrimSpace(val)
	if val == "" {
		return nil
	}
	if strings.HasPrefix(val, "[") {
		var sels []netattdefv1.NetworkSelectionElement
		if err := json.Unmarshal([]byte(val), &sels); err != nil {
			log.Warnf("parseNetworksAnnotation: bad JSON %q: %v", val, err)
			return nil
		}
		return sels
	}
	var sels []netattdefv1.NetworkSelectionElement
	for _, part := range strings.Split(val, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		var iface string
		if at := strings.Index(part, "@"); at >= 0 {
			iface = part[at+1:]
			part = part[:at]
		}
		var namespace, name string
		if slash := strings.Index(part, "/"); slash >= 0 {
			namespace, name = part[:slash], part[slash+1:]
		} else {
			name = part
		}
		sels = append(sels, netattdefv1.NetworkSelectionElement{
			Namespace:        namespace,
			Name:             name,
			InterfaceRequest: iface,
		})
	}
	return sels
}

// buildKubeAppACLs returns the ACEs for one synthesized adapter. zedrouter
// treats an empty ACL list as default-DROP, so every adapter gets a
// permissive allow-all rule (no action => ALLOW) for both IPv4 and IPv6, then
// any port-maps requested for this specific interface via the standard
// Multus "portMappings" selection field. Restrictive/deny policies are a
// future addition.
func buildKubeAppACLs(portMaps []*netattdefv1.PortMapEntry) []types.ACE {
	acls := []types.ACE{{
		RuleID:  1,
		Name:    "kubeapp-allow-all-ipv4",
		Dir:     types.AceDirBoth,
		Matches: []types.ACEMatch{{Type: "ip", Value: "0.0.0.0/0"}},
	}, {
		RuleID:  2,
		Name:    "kubeapp-allow-all-ipv6",
		Dir:     types.AceDirBoth,
		Matches: []types.ACEMatch{{Type: "ip", Value: "::/0"}},
	}}
	for i, pm := range validPortMaps(portMaps) {
		acls = append(acls, types.ACE{
			RuleID: int32(100 + i),
			Name:   fmt.Sprintf("portmap-%s-%d", pm.Protocol, pm.HostPort),
			Dir:    types.AceDirIngress,
			Matches: []types.ACEMatch{
				{Type: "protocol", Value: pm.Protocol},
				{Type: "lport", Value: strconv.Itoa(pm.HostPort)},
			},
			Actions: []types.ACEAction{
				{PortMap: true, TargetPort: pm.ContainerPort},
			},
		})
	}
	return acls
}

// validPortMaps normalizes and validates the standard Multus "portMappings"
// selection field, skipping entries with an unsupported protocol or an
// out-of-range port. HostIP is not honored: EVE's ACL model port-maps on the
// Network Instance bridge, not a specific host address.
func validPortMaps(portMaps []*netattdefv1.PortMapEntry) []netattdefv1.PortMapEntry {
	var out []netattdefv1.PortMapEntry
	for _, pm := range portMaps {
		if pm == nil {
			continue
		}
		entry := *pm
		entry.Protocol = strings.ToLower(strings.TrimSpace(entry.Protocol))
		if (entry.Protocol != "tcp" && entry.Protocol != "udp") ||
			entry.HostPort <= 0 || entry.HostPort > 65535 ||
			entry.ContainerPort <= 0 || entry.ContainerPort > 65535 {
			log.Warnf("validPortMaps: skipping invalid portMappings entry %+v", entry)
			continue
		}
		out = append(out, entry)
	}
	return out
}

// kubeAppMarkerName is the marker filename (under kubeAppMarkerDir) for a pod.
func kubeAppMarkerName(namespace, podName string) string {
	return namespace + "_" + podName
}

// reconcileKubeAppMarkers writes one marker file per pod currently on this
// node (every pod, not just NI-attached ones -- see kubeAppMarkerDir) and
// removes markers for pods no longer here. Each write goes through
// utils.WriteRename (tmpfile + fsync + rename) so a concurrent eve-bridge read
// never observes a half-written file.
func reconcileKubeAppMarkers(desired map[string]kubeAppNetKind) {
	if err := os.MkdirAll(kubeAppMarkerDir, 0755); err != nil {
		log.Errorf("reconcileKubeAppMarkers: mkdir %s: %v", kubeAppMarkerDir, err)
		return
	}
	for name, kind := range desired {
		path := filepath.Join(kubeAppMarkerDir, name)
		if err := utils.WriteRename(path, []byte(kind)); err != nil {
			log.Errorf("reconcileKubeAppMarkers: write %s: %v", path, err)
		}
	}
	entries, err := os.ReadDir(kubeAppMarkerDir)
	if err != nil {
		log.Errorf("reconcileKubeAppMarkers: read %s: %v", kubeAppMarkerDir, err)
		return
	}
	for _, e := range entries {
		if _, ok := desired[e.Name()]; !ok {
			if err := os.Remove(filepath.Join(kubeAppMarkerDir, e.Name())); err != nil {
				log.Errorf("reconcileKubeAppMarkers: remove %s: %v", e.Name(), err)
			}
		}
	}
}

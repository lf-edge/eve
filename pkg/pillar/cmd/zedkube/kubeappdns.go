// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build k

package zedkube

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/kubeapi"
	"github.com/lf-edge/eve/pkg/pillar/types"
	uuid "github.com/satori/go.uuid"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/client-go/kubernetes"
)

const (
	kubeAppDNSDomain              = "internal"
	kubeAppAllocationCMKey        = "allocations.json"
	kubeAppAllocationManagedLabel = "eve.zededa.com/managed-by"
	kubeAppAllocationManagedValue = "zedkube-ni-dns"
	kubeAppAllocationNILabel      = "eve.zededa.com/network-instance"
	kubeAppAllocationCMVersion    = 1
	coreDNSNamespace              = "kube-system"
	coreDNSCustomCMName           = "coredns-custom"
	coreDNSCustomKey              = "eve-ni.server"
	coreDNSDeploymentName         = "coredns"
	coreDNSRolloutHashAnnotation  = "eve.zededa.com/ni-dns-hash"
)

// kubeAppNIAllocation is the zedrouter-authoritative allocation persisted in
// the per-NI ConfigMap. An allocation may contain only a MAC while an app on a
// switch NI is still waiting for DHCP from the external network.
type kubeAppNIAllocation struct {
	AppUUID       string   `json:"appUUID"`
	AppName       string   `json:"appName"`
	Namespace     string   `json:"namespace"`
	NIUUID        string   `json:"niUUID"`
	NIDisplayName string   `json:"niDisplayName"`
	NodeName      string   `json:"nodeName"`
	MACs          []string `json:"macs,omitempty"`
	IPv4          []string `json:"ipv4,omitempty"`
	IPv6          []string `json:"ipv6,omitempty"`
}

type kubeAppNIAllocationConfig struct {
	Version     int                            `json:"version"`
	Allocations map[string]kubeAppNIAllocation `json:"allocations"`
}

// allocationsForStatus extracts one allocation per NI from a completed
// AppNetworkStatus. It deliberately uses assigned status rather than requested
// pod annotations, leaving MAC/IP authority with zedrouter. Native Kubernetes
// workloads use the stable display name selected by zedkube; controller-managed
// EVE apps use their display name in the EVE application namespace.
func allocationsForStatus(status types.AppNetworkStatus,
	niNames map[uuid.UUID]string, nodeName string) []kubeAppNIAllocation {
	if !status.Activated || !status.ConfigInSync ||
		status.Pending() || status.HasError() {
		return nil
	}

	appName := status.DisplayName
	namespace := kubeapi.EVEKubeNameSpace
	if status.KubeApp != nil {
		namespace = status.KubeApp.Namespace
	}
	if validation.IsDNS1123Label(appName) != nil ||
		validation.IsDNS1123Label(namespace) != nil {
		return nil
	}

	byNI := make(map[uuid.UUID]*kubeAppNIAllocation)
	for _, adapter := range status.AppNetAdapterList {
		niName, ok := niNames[adapter.Network]
		if !ok || validation.IsDNS1123Label(niName) != nil {
			continue
		}
		allocation := byNI[adapter.Network]
		if allocation == nil {
			allocation = &kubeAppNIAllocation{
				AppUUID:       status.UUIDandVersion.UUID.String(),
				AppName:       appName,
				Namespace:     namespace,
				NIUUID:        adapter.Network.String(),
				NIDisplayName: niName,
				NodeName:      nodeName,
			}
			byNI[adapter.Network] = allocation
		}
		if len(adapter.Mac) != 0 {
			allocation.MACs = appendUniqueString(allocation.MACs, adapter.Mac.String())
		}
		for _, addr := range adapter.AssignedAddresses.IPv4Addrs {
			if addr.Address != nil {
				allocation.IPv4 = appendUniqueString(allocation.IPv4, addr.Address.String())
			}
		}
		for _, addr := range adapter.AssignedAddresses.IPv6Addrs {
			if addr.Address != nil {
				allocation.IPv6 = appendUniqueString(allocation.IPv6, addr.Address.String())
			}
		}
	}

	allocations := make([]kubeAppNIAllocation, 0, len(byNI))
	for _, allocation := range byNI {
		sort.Strings(allocation.MACs)
		sort.Strings(allocation.IPv4)
		sort.Strings(allocation.IPv6)
		allocations = append(allocations, *allocation)
	}
	sort.Slice(allocations, func(i, j int) bool {
		return allocations[i].NIUUID < allocations[j].NIUUID
	})
	return allocations
}

func appendUniqueString(values []string, value string) []string {
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}

func allocationCanonicalName(allocation kubeAppNIAllocation) string {
	return fmt.Sprintf("%s.%s.%s.%s", allocation.AppName, allocation.Namespace,
		allocation.NIDisplayName, kubeAppDNSDomain)
}

// renderKubeAppDNS renders a deterministic CoreDNS server block. Canonical
// names are always emitted; the short app.internal alias is included only when
// it resolves to one canonical workload identity across the cluster.
func renderKubeAppDNS(allocations []kubeAppNIAllocation) string {
	type dnsAllocation struct {
		canonical  string
		allocation kubeAppNIAllocation
	}
	var ready []dnsAllocation
	aliasTargets := make(map[string]map[string]struct{})
	for _, allocation := range allocations {
		if len(allocation.IPv4) == 0 && len(allocation.IPv6) == 0 {
			continue
		}
		if validation.IsDNS1123Label(allocation.AppName) != nil ||
			validation.IsDNS1123Label(allocation.Namespace) != nil ||
			validation.IsDNS1123Label(allocation.NIDisplayName) != nil {
			continue
		}
		canonical := allocationCanonicalName(allocation)
		ready = append(ready, dnsAllocation{canonical: canonical, allocation: allocation})
		if aliasTargets[allocation.AppName] == nil {
			aliasTargets[allocation.AppName] = make(map[string]struct{})
		}
		aliasTargets[allocation.AppName][canonical] = struct{}{}
	}
	sort.Slice(ready, func(i, j int) bool {
		if ready[i].canonical == ready[j].canonical {
			return ready[i].allocation.AppUUID < ready[j].allocation.AppUUID
		}
		return ready[i].canonical < ready[j].canonical
	})

	var lines []string
	for _, item := range ready {
		var addresses []string
		for _, address := range item.allocation.IPv4 {
			if ip := net.ParseIP(address); isPublishableDNSAddress(ip) && ip.To4() != nil {
				addresses = appendUniqueString(addresses, ip.String())
			}
		}
		for _, address := range item.allocation.IPv6 {
			if ip := net.ParseIP(address); isPublishableDNSAddress(ip) && ip.To4() == nil {
				addresses = appendUniqueString(addresses, ip.String())
			}
		}
		sort.Strings(addresses)
		for _, address := range addresses {
			names := []string{item.canonical}
			if len(aliasTargets[item.allocation.AppName]) == 1 {
				names = append(names, item.allocation.AppName+"."+kubeAppDNSDomain)
			}
			lines = append(lines, fmt.Sprintf("        %s %s", address, strings.Join(names, " ")))
		}
	}
	if len(lines) == 0 {
		return ""
	}
	return fmt.Sprintf(`internal:53 {
    errors
    cache 30
    hosts {
%s
        ttl 30
        fallthrough
    }
}
`, strings.Join(lines, "\n"))
}

func isPublishableDNSAddress(ip net.IP) bool {
	return ip != nil && ip.IsGlobalUnicast() &&
		!ip.IsUnspecified() && !ip.IsLoopback() &&
		!ip.IsMulticast() && !ip.IsLinkLocalUnicast() &&
		!ip.IsLinkLocalMulticast()
}

func allocationConfigMapName(niDisplayName string) string {
	return "eve-ni-" + niDisplayName + "-allocations"
}

// reconcileNodeNIAllocations replaces only allocations owned by nodeName and
// preserves records written by every other node. The stable app UUID key lets
// a destination node take ownership before a delayed source-node cleanup.
func reconcileNodeNIAllocations(ctx context.Context, client kubernetes.Interface,
	nodeName string, desired []kubeAppNIAllocation) error {
	desiredByCM := make(map[string]map[string]kubeAppNIAllocation)
	niUUIDByCM := make(map[string]string)
	// A colliding ConfigMap gets no new allocations so that one misconfigured
	// NI pair does not block allocation publishing for every other NI.
	var errs []error
	collided := make(map[string]struct{})
	for _, allocation := range desired {
		cmName := allocationConfigMapName(allocation.NIDisplayName)
		if previous := niUUIDByCM[cmName]; previous != "" && previous != allocation.NIUUID {
			if _, seen := collided[cmName]; !seen {
				collided[cmName] = struct{}{}
				errs = append(errs, fmt.Errorf("NI display-name collision for ConfigMap %s: %s and %s",
					cmName, previous, allocation.NIUUID))
			}
			continue
		}
		niUUIDByCM[cmName] = allocation.NIUUID
		if desiredByCM[cmName] == nil {
			desiredByCM[cmName] = make(map[string]kubeAppNIAllocation)
		}
		desiredByCM[cmName][allocation.AppUUID] = allocation
	}

	selector := labels.Set{
		kubeAppAllocationManagedLabel: kubeAppAllocationManagedValue,
	}.AsSelector().String()
	existing, err := client.CoreV1().ConfigMaps(kubeapi.EVEKubeNameSpace).List(ctx,
		metav1.ListOptions{LabelSelector: selector})
	if err != nil {
		return fmt.Errorf("list NI allocation ConfigMaps: %w", err)
	}
	cmNames := make(map[string]struct{}, len(existing.Items)+len(desiredByCM))
	for _, cm := range existing.Items {
		cmNames[cm.Name] = struct{}{}
	}
	for cmName := range desiredByCM {
		cmNames[cmName] = struct{}{}
	}

	for cmName := range cmNames {
		niUUID, cmDesired := niUUIDByCM[cmName], desiredByCM[cmName]
		if _, isCollided := collided[cmName]; isCollided {
			// Publish nothing for an ambiguous NI, but still drop this node's
			// stale records written before the collision appeared.
			niUUID, cmDesired = "", nil
		}
		if err := reconcileNIAllocationConfigMap(ctx, client, cmName, nodeName,
			niUUID, cmDesired); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func reconcileNIAllocationConfigMap(ctx context.Context, client kubernetes.Interface,
	cmName, nodeName, desiredNIUUID string,
	desired map[string]kubeAppNIAllocation) error {
	cmAPI := client.CoreV1().ConfigMaps(kubeapi.EVEKubeNameSpace)
	return retryKubeAPIUpdate(ctx, true, func() error {
		cm, err := cmAPI.Get(ctx, cmName, metav1.GetOptions{})
		if k8serrors.IsNotFound(err) {
			if len(desired) == 0 {
				return nil
			}
			config := kubeAppNIAllocationConfig{
				Version: kubeAppAllocationCMVersion, Allocations: desired,
			}
			payload, err := json.Marshal(config)
			if err != nil {
				return err
			}
			_, err = cmAPI.Create(ctx, &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      cmName,
					Namespace: kubeapi.EVEKubeNameSpace,
					Labels: map[string]string{
						kubeAppAllocationManagedLabel: kubeAppAllocationManagedValue,
						kubeAppAllocationNILabel:      desiredNIUUID,
					},
				},
				Data: map[string]string{kubeAppAllocationCMKey: string(payload)},
			}, metav1.CreateOptions{})
			return err
		}
		if err != nil {
			return err
		}
		if cm.Labels[kubeAppAllocationManagedLabel] != kubeAppAllocationManagedValue {
			return fmt.Errorf("refusing to modify unmanaged ConfigMap %s/%s",
				kubeapi.EVEKubeNameSpace, cmName)
		}
		if existingNIUUID := cm.Labels[kubeAppAllocationNILabel]; desiredNIUUID != "" && existingNIUUID != "" && existingNIUUID != desiredNIUUID {
			return fmt.Errorf("NI display-name collision for ConfigMap %s: %s and %s",
				cmName, existingNIUUID, desiredNIUUID)
		}

		config := kubeAppNIAllocationConfig{
			Version:     kubeAppAllocationCMVersion,
			Allocations: make(map[string]kubeAppNIAllocation),
		}
		if raw := cm.Data[kubeAppAllocationCMKey]; raw != "" {
			if err := json.Unmarshal([]byte(raw), &config); err != nil {
				return fmt.Errorf("decode %s/%s: %w", kubeapi.EVEKubeNameSpace, cmName, err)
			}
			if config.Allocations == nil {
				config.Allocations = make(map[string]kubeAppNIAllocation)
			}
		}
		for appUUID, allocation := range config.Allocations {
			if allocation.NodeName == nodeName {
				delete(config.Allocations, appUUID)
			}
		}
		for appUUID, allocation := range desired {
			config.Allocations[appUUID] = allocation
		}
		config.Version = kubeAppAllocationCMVersion
		if len(config.Allocations) == 0 {
			// The resourceVersion precondition keeps a concurrent write from
			// another node from being deleted along with the empty map.
			err := cmAPI.Delete(ctx, cmName, metav1.DeleteOptions{
				Preconditions: &metav1.Preconditions{ResourceVersion: &cm.ResourceVersion},
			})
			if k8serrors.IsNotFound(err) {
				return nil
			}
			return err
		}
		payload, err := json.Marshal(config)
		if err != nil {
			return err
		}
		if cm.Data != nil && cm.Data[kubeAppAllocationCMKey] == string(payload) {
			return nil
		}
		if cm.Data == nil {
			cm.Data = make(map[string]string)
		}
		cm.Data[kubeAppAllocationCMKey] = string(payload)
		if cm.Labels == nil {
			cm.Labels = make(map[string]string)
		}
		if desiredNIUUID != "" {
			cm.Labels[kubeAppAllocationNILabel] = desiredNIUUID
		}
		_, err = cmAPI.Update(ctx, cm, metav1.UpdateOptions{})
		return err
	})
}

func listKubeAppNIAllocations(ctx context.Context,
	client kubernetes.Interface) ([]kubeAppNIAllocation, error) {
	selector := labels.Set{
		kubeAppAllocationManagedLabel: kubeAppAllocationManagedValue,
	}.AsSelector().String()
	configMaps, err := client.CoreV1().ConfigMaps(kubeapi.EVEKubeNameSpace).List(ctx,
		metav1.ListOptions{LabelSelector: selector})
	if err != nil {
		return nil, err
	}
	var allocations []kubeAppNIAllocation
	for _, cm := range configMaps.Items {
		raw := cm.Data[kubeAppAllocationCMKey]
		if raw == "" {
			continue
		}
		var config kubeAppNIAllocationConfig
		if err := json.Unmarshal([]byte(raw), &config); err != nil {
			return nil, fmt.Errorf("decode %s/%s: %w", cm.Namespace, cm.Name, err)
		}
		for _, allocation := range config.Allocations {
			allocations = append(allocations, allocation)
		}
	}
	return allocations, nil
}

// reconcileCoreDNS renders all per-NI allocation ConfigMaps into the single
// K3s coredns-custom key owned by zedkube and ensures the CoreDNS pod template
// carries the matching content hash. The hash makes retries idempotent and
// provides the requested rolling restart only when DNS content changes.
func reconcileCoreDNS(ctx context.Context,
	client kubernetes.Interface) (changed bool, err error) {
	allocations, err := listKubeAppNIAllocations(ctx, client)
	if err != nil {
		return false, fmt.Errorf("list NI DNS allocations: %w", err)
	}
	desired := renderKubeAppDNS(allocations)
	cmChanged, hadManagedKey, err := reconcileCoreDNSConfigMap(ctx, client, desired)
	if err != nil {
		return false, err
	}
	if desired == "" && !hadManagedKey {
		return cmChanged, nil
	}
	hash := fmt.Sprintf("%x", sha256.Sum256([]byte(desired)))
	rolloutChanged, err := ensureCoreDNSRolloutHash(ctx, client, hash)
	if err != nil {
		return false, err
	}
	return cmChanged || rolloutChanged, nil
}

func reconcileCoreDNSConfigMap(ctx context.Context, client kubernetes.Interface,
	desired string) (changed, hadManagedKey bool, err error) {
	cmAPI := client.CoreV1().ConfigMaps(coreDNSNamespace)
	err = retryKubeAPIUpdate(ctx, true, func() error {
		cm, getErr := cmAPI.Get(ctx, coreDNSCustomCMName, metav1.GetOptions{})
		if k8serrors.IsNotFound(getErr) {
			if desired == "" {
				return nil
			}
			_, createErr := cmAPI.Create(ctx, &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name: coreDNSCustomCMName, Namespace: coreDNSNamespace,
				},
				Data: map[string]string{coreDNSCustomKey: desired},
			}, metav1.CreateOptions{})
			if createErr == nil {
				changed = true
			}
			return createErr
		}
		if getErr != nil {
			return getErr
		}
		current, exists := cm.Data[coreDNSCustomKey]
		hadManagedKey = exists
		if exists && current == desired {
			return nil
		}
		if !exists && desired == "" {
			return nil
		}
		if cm.Data == nil {
			cm.Data = make(map[string]string)
		}
		if desired == "" {
			delete(cm.Data, coreDNSCustomKey)
		} else {
			cm.Data[coreDNSCustomKey] = desired
		}
		_, updateErr := cmAPI.Update(ctx, cm, metav1.UpdateOptions{})
		if updateErr == nil {
			changed = true
		}
		return updateErr
	})
	return changed, hadManagedKey, err
}

func ensureCoreDNSRolloutHash(ctx context.Context, client kubernetes.Interface,
	hash string) (changed bool, err error) {
	deployments := client.AppsV1().Deployments(coreDNSNamespace)
	err = retryKubeAPIUpdate(ctx, false, func() error {
		deployment, getErr := deployments.Get(ctx, coreDNSDeploymentName, metav1.GetOptions{})
		if getErr != nil {
			return getErr
		}
		if deployment.Spec.Template.Annotations[coreDNSRolloutHashAnnotation] == hash {
			return nil
		}
		if deployment.Spec.Template.Annotations == nil {
			deployment.Spec.Template.Annotations = make(map[string]string)
		}
		deployment.Spec.Template.Annotations[coreDNSRolloutHashAnnotation] = hash
		_, updateErr := deployments.Update(ctx, deployment, metav1.UpdateOptions{})
		if updateErr == nil {
			changed = true
		}
		return updateErr
	})
	return changed, err
}

// retryKubeAPIUpdate retries optimistic-concurrency conflicts with a short
// exponential backoff. The caller's kubeAPITimeout context remains the hard
// upper bound; AlreadyExists is retryable only for create-or-update flows.
func retryKubeAPIUpdate(ctx context.Context, retryAlreadyExists bool,
	operation func() error) error {
	const maxAttempts = 5
	for attempt := 0; attempt < maxAttempts; attempt++ {
		err := operation()
		if err == nil {
			return nil
		}
		retryable := k8serrors.IsConflict(err) ||
			(retryAlreadyExists && k8serrors.IsAlreadyExists(err))
		if !retryable || attempt == maxAttempts-1 {
			return err
		}
		delay := 10 * time.Millisecond * time.Duration(1<<attempt)
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return ctx.Err()
		case <-timer.C:
		}
	}
	return nil
}

func reconcileKubeAppDNSState(ctx context.Context, client kubernetes.Interface,
	clusterConfig types.EdgeNodeClusterConfig, isLeader bool, nodeName string,
	statuses []types.AppNetworkStatus, niNames map[uuid.UUID]string) error {
	if !clusterConfig.NativeK8sOrchestrationEnabled() {
		return nil
	}
	if nodeName == "" {
		return nil
	}
	var desired []kubeAppNIAllocation
	for _, status := range statuses {
		desired = append(desired, allocationsForStatus(status, niNames, nodeName)...)
	}
	if err := reconcileNodeNIAllocations(ctx, client, nodeName, desired); err != nil {
		return err
	}
	if !isLeader {
		return nil
	}
	_, err := reconcileCoreDNS(ctx, client)
	return err
}

func (z *zedkube) reconcileKubeAppDNS() {
	// Check the ENCC gate before acquiring a kube client or touching any
	// Kubernetes object. Disabled native orchestration is a strict no-op.
	if !z.clusterConfig.NativeK8sOrchestrationEnabled() {
		return
	}
	client, err := getKubeClientSet()
	if err != nil {
		log.Errorf("reconcileKubeAppDNS: get clientset: %v", err)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), kubeAPITimeout)
	defer cancel()

	niNames := make(map[uuid.UUID]string)
	for _, item := range z.subNetworkInstanceStatus.GetAll() {
		status := item.(types.NetworkInstanceStatus)
		niNames[status.UUIDandVersion.UUID] = status.DisplayName
	}
	statuses := make([]types.AppNetworkStatus, 0)
	for _, item := range z.subAppNetworkStatus.GetAll() {
		statuses = append(statuses, item.(types.AppNetworkStatus))
	}
	if err := reconcileKubeAppDNSState(ctx, client, z.clusterConfig,
		z.isStatsLeader(), z.nodeName, statuses, niNames); err != nil {
		log.Errorf("reconcileKubeAppDNS: %v", err)
	}
}

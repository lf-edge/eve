package zedkube

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	netattdefv1 "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/apis/k8s.cni.cncf.io/v1"
	"github.com/lf-edge/eve/pkg/pillar/types"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	metricsv "k8s.io/metrics/pkg/client/clientset/versioned"
)

func genAISpecCreate(ctx *zedkubeContext, aiConfig *types.AppInstanceConfig) error {

	if !aiConfig.KubeActivate {
		log.Noticef("genAISpecCreate: app instance not activated, exit")
		return nil
	}

	clientset, err := kubernetes.NewForConfig(ctx.config)
	if err != nil {
		log.Errorf("genAISpecCreate: can't get clientset %v", err)
		return err
	}

	ulConfig := aiConfig.UnderlayNetworkList
	var nadnames []string
	//var defNetName string
	var annotations map[string]string
	for _, ul := range ulConfig {
		nadname := lookupNIStatusForNAD(ctx, ul.Network.String())
		if nadname != "" {
			nadnames = append(nadnames, nadname)
		}
	}

	if len(aiConfig.VolumeRefConfigList) == 0 {
		err := fmt.Errorf("genAISpecCreate: no volume, return")
		return err
	}

	var ociName string
	sub := ctx.subContentTreeStatus
	items := sub.GetAll()
	for _, item := range items {
		ctStatus := item.(types.ContentTreeStatus)
		if ctStatus.OciImageName == "" {
			continue
		}
		if aiConfig.ContentID == ctStatus.ContentID.String() {
			ociName = ctStatus.OciImageName
			break
		}
	}
	if ociName == "" {
		err := fmt.Errorf("genAISpecCreate: no OCI name found, return")
		return err
	}
	log.Noticef("genAISpecCreate: found oci image name %v", ociName)

	if len(nadnames) > 0 {
		selections := make([]netattdefv1.NetworkSelectionElement, len(nadnames))
		for i, nad := range nadnames {
			if i > len(nadnames)-1 {
				err := fmt.Errorf("genAISpecCreate: no def local ni found, exit")
				return err
			}
			selections[i] = netattdefv1.NetworkSelectionElement{
				Name: nad,
			}
		}
		annotations = map[string]string{
			"k8s.v1.cni.cncf.io/networks": encodeSelections(selections),
		}
		log.Functionf("genAISpecCreate: annotations %+v", annotations)
	} else {
		err := fmt.Errorf("genAISpecCreate: no nadname, exit")
		return err
	}

	vcpus := strconv.Itoa(aiConfig.FixedResources.VCpus*1000) + "m"
	// FixedResources.Memory is in Kbytes
	memoryLimit := strconv.Itoa(aiConfig.FixedResources.Memory * 1000)
	memoryRequest := strconv.Itoa(aiConfig.FixedResources.Memory * 1000)

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:        strings.ToLower(aiConfig.DisplayName),
			Namespace:   eveNamespace,
			Annotations: annotations,
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{
					Name:            aiConfig.DisplayName,
					Image:           ociName,
					ImagePullPolicy: corev1.PullNever,
					SecurityContext: &corev1.SecurityContext{
						Privileged: &[]bool{true}[0],
					},
					Resources: corev1.ResourceRequirements{
						Limits: corev1.ResourceList{
							corev1.ResourceCPU:    resource.MustParse(vcpus),
							corev1.ResourceMemory: resource.MustParse(memoryLimit),
						},
						Requests: corev1.ResourceList{
							corev1.ResourceCPU:    resource.MustParse(vcpus),
							corev1.ResourceMemory: resource.MustParse(memoryRequest),
						},
					},
				},
			},
			DNSConfig: &corev1.PodDNSConfig{
				Nameservers: []string{"8.8.8.8", "1.1.1.1"}, // XXX, temp, Add your desired DNS servers here
			},
		},
	}

	updateAppNetConfig(ctx, aiConfig)

	_, err = clientset.CoreV1().Pods(eveNamespace).Create(context.TODO(), pod, metav1.CreateOptions{})
	if err != nil {
		log.Errorf("genAISpecCreate: pod create filed: %v", err)
		return err
	}

	log.Noticef("genAISpecCreate: Pod %s created with nad %+v", aiConfig.DisplayName, pod.Annotations)
	return nil
}

func aiSpecDelete(ctx *zedkubeContext, aiConfig *types.AppInstanceConfig) {

	if !aiConfig.KubeActivate {
		log.Noticef("aiSpecDelete: app instance not activated")
		return
	}

	clientset, err := kubernetes.NewForConfig(ctx.config)
	if err != nil {
		log.Errorf("aiSpecDelete: can't get clientset %v", err)
		return
	}

	podName := strings.ToLower(aiConfig.DisplayName)
	err = clientset.CoreV1().Pods(eveNamespace).Delete(context.TODO(), podName, metav1.DeleteOptions{})
	if err != nil {
		// Handle error
		log.Errorf("aiSpecDelete: deleting pod: %v", err)
		return
	}

	// or do this in eve-bridge notify?
	//updateAppNetConfig(ctx, aiConfig)
	log.Noticef("aiSpecDelete: Pod %s deleted", podName)
}

func encodeSelections(selections []netattdefv1.NetworkSelectionElement) string {
	bytes, err := json.Marshal(selections)
	if err != nil {
		log.Fatal(err)
	}
	return string(bytes)
}

func updateAppNetConfig(ctx *zedkubeContext, aiConfig *types.AppInstanceConfig) {
	aiName := strings.ToLower(aiConfig.DisplayName)
	if _, ok := ctx.appNetConfig[aiName]; !ok {
		ctx.appNetConfig[aiName] = &types.AppNetworkConfig{
			UUIDandVersion:    aiConfig.UUIDandVersion,
			DisplayName:       aiConfig.DisplayName,
			Activate:          false,
			CloudInitUserData: aiConfig.CloudInitUserData,
		}
		ulcount := len(aiConfig.UnderlayNetworkList)
		ctx.appNetConfig[aiName].UnderlayNetworkList = make([]types.UnderlayNetworkConfig, ulcount)
		for i := range aiConfig.UnderlayNetworkList {
			ctx.appNetConfig[aiName].UnderlayNetworkList[i] =
				aiConfig.UnderlayNetworkList[i]
		}
		log.Functionf("updateAppNetConfig: ulcount %d, for %s, appnetconfig %+v", ulcount, aiName, ctx.appNetConfig[aiName])
	}
}

func publishAppNetConfig(ctx *zedkubeContext, ebStatus *EveClusterInstStatus) {
	status := lookupNIStatusFromName(ctx, ebStatus.BridgeConfig)
	if status == nil {
		log.Errorf("publishAppNetConfig: can't find NI status for %s", ebStatus.BridgeConfig)
		return
	}

	log.Noticef("publishAppNetConfig: for eve-bridge %v, ni-status %v, nistatus uuid %v, appnet len %d",
		ebStatus, status, status.UUIDandVersion.UUID, len(ctx.appNetConfig))
	for _, aiCfg := range ctx.appNetConfig {
		var found bool
		log.Noticef("publishAppNetConfig: aiCfg.UnderlayNetworkList size %d", len(aiCfg.UnderlayNetworkList))
		for _, ulcfg := range aiCfg.UnderlayNetworkList {
			log.Noticef("publishAppNetConfig: ulcfg network %v, list size %d, ulstatus size %d",
				ulcfg.Network, len(aiCfg.UnderlayNetworkList), len(aiCfg.ULNetworkStatusList))
			if ulcfg.Network.String() == status.UUIDandVersion.UUID.String() {
				found = true
				break
			}
		}
		if found {
			var foundUL bool
			for _, ulstatus := range aiCfg.ULNetworkStatusList {
				if ulstatus.Network.String() == status.UUIDandVersion.UUID.String() {
					foundUL = true
					break
				}
			}
			if !foundUL {
				ul := new(types.UnderlayNetworkStatus)
				ul.Name = ebStatus.PodIntfName
				ul.Network = status.UUIDandVersion.UUID
				ul.Vif = ebStatus.VifName
				var err error
				ul.Mac, err = net.ParseMAC(ebStatus.VifMAC)
				if err != nil {
					log.Errorf("publishAppNetConfig: parseMac %s, error %v", ebStatus.VifMAC, err)
				}
				ul.Bridge = ebStatus.BridgeName
				ul.AllocatedIPv4Addr = ebStatus.PodIntfPrefix.IP
				ul.IPv4Assigned = true
				ul.HostName = ebStatus.PodName

				aiCfg.ULNetworkStatusList = append(aiCfg.ULNetworkStatusList, *ul)
				log.Noticef("publishAppNetConfig: add ul status %+v", ul)
			}

			if len(aiCfg.UnderlayNetworkList) == len(aiCfg.ULNetworkStatusList) {
				// got all the NI items. publish
				key := aiCfg.UUIDandVersion.UUID.String()
				aiCfg.Activate = true
				ctx.pubAppNetworkConfig.Publish(key, *aiCfg)
			}
			break
		}
	}
}

func publishAppMetrics(ctx *zedkubeContext) {
	sub := ctx.subAppInstanceConfig
	items := sub.GetAll()
	if len(items) == 0 {
		return
	}

	pub := ctx.pubDomainMetric
	dmitems := pub.GetAll()

	podclientset, err := kubernetes.NewForConfig(ctx.config)
	clientset, err := metricsv.NewForConfig(ctx.config)
	if err != nil {
		log.Errorf("publishAppMetrics: can't get clientset %v", err)
		return
	}

	for _, item := range items {
		aiconfig := item.(types.AppInstanceConfig)
		aiName := strings.ToLower(aiconfig.DisplayName)
		pod, err := podclientset.CoreV1().Pods(eveNamespace).Get(context.TODO(), aiName, metav1.GetOptions{})
		if err != nil {
			log.Errorf("publishAppMetrics: get pod error %v", err)
			continue
		}
		if len(pod.Spec.Containers) == 0 {
			continue
		}
		memoryLimits := pod.Spec.Containers[0].Resources.Limits.Memory()

		metrics, err := clientset.MetricsV1beta1().PodMetricses(eveNamespace).Get(context.TODO(), aiName, metav1.GetOptions{})
		if err != nil {
			log.Errorf("publishAppMetrics: get pod metrics error %v", err)
			continue
		}

		var prevDm *types.DomainMetric
		for _, dmitem := range dmitems {
			dm := dmitem.(types.DomainMetric)
			if aiconfig.UUIDandVersion.UUID.String() == dm.UUIDandVersion.UUID.String() {
				prevDm = &dm
				break
			}
		}

		cpuTotalNs := metrics.Containers[0].Usage[corev1.ResourceCPU]
		cpuTotalNsAsFloat64 := cpuTotalNs.AsApproximateFloat64() * float64(time.Second) // get nanoseconds
		totalCpu := uint64(cpuTotalNsAsFloat64)
		vcpus := aiconfig.FixedResources.VCpus
		if vcpus > 0 {
			totalCpu = totalCpu / uint64(vcpus)
		}

		allocatedMemory := metrics.Containers[0].Usage[corev1.ResourceMemory]
		usedMemory := metrics.Containers[0].Usage[corev1.ResourceMemory]
		maxMemory := uint32(usedMemory.Value())

		// the kubernetes cpu stats collection is for a window with a start and end time, the metrics
		// returned will have the window duration and end time. the duration is not a fixed number, and
		// collection windows may not be continuous. So to build the total cpu count, needs to save the
		// previous window stats. If the current window start time is lager than the previous window's
		// start time, then add the previous cpu count into the total.
		var realTotalCPU uint64
		endTime := metrics.Timestamp.Time
		startTime := endTime.Add(-metrics.Window.Duration)
		if prevDm != nil {
			if prevDm.MaxUsedMemory > maxMemory {
				maxMemory = prevDm.MaxUsedMemory
			}
			realTotalCPU = prevDm.CPUTotalNs
			if startTime.After(prevDm.Prev.StartTime) { // we can conclude the stats of last window
				realTotalCPU += prevDm.Prev.CPUCountNs
			}
		}

		available := uint32(memoryLimits.Value())
		if uint32(usedMemory.Value()) < available {
			available = available - uint32(usedMemory.Value())
		}
		usedMemoryPercent := calculateMemoryUsagePercent(usedMemory.Value(), allocatedMemory.Value())
		BytesInMegabyte := uint32(1024 * 1024)
		dm := types.DomainMetric{
			UUIDandVersion:    aiconfig.UUIDandVersion,
			Activated:         true,
			CPUTotalNs:        realTotalCPU,
			CPUScaled:         uint32(aiconfig.FixedResources.VCpus),
			AllocatedMB:       uint32(memoryLimits.Value()) / BytesInMegabyte,
			UsedMemory:        uint32(usedMemory.Value()) / BytesInMegabyte,
			MaxUsedMemory:     maxMemory / BytesInMegabyte,
			AvailableMemory:   available / BytesInMegabyte,
			UsedMemoryPercent: usedMemoryPercent,
			LastHeard:         time.Now(),
		}

		log.Noticef("publishAppMetrics: pod metrics %+v, **dm %+v, totalCpu %v, vcpus %v, window %v, start %v, end %v, realtotal %v",
			metrics, dm, totalCpu, vcpus, metrics.Window.Duration, startTime, endTime, realTotalCPU)
		dm.Prev.CPUCountNs = totalCpu
		dm.Prev.StartTime = startTime
		ctx.pubDomainMetric.Publish(dm.Key(), dm)
	}
}

// Helper function to calculate the memory usage percentage
func calculateMemoryUsagePercent(usedMemory, allocatedMemory int64) float64 {
	if allocatedMemory > 0 {
		return float64(usedMemory) / float64(allocatedMemory) * 100.0
	}
	return 0.0
}

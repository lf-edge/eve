package zedkube

import (
	"bufio"
	"context"
	"io"
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/lf-edge/eve/pkg/pillar/kubeapi"
	"github.com/lf-edge/eve/pkg/pillar/types"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"
)

func check_ioAdapter_ethernet(ctx *zedkubeContext, aiConfig *types.AppInstanceConfig) error {
	updateAppKubeNetStatus(ctx, aiConfig)

	ioAdapter := aiConfig.IoAdapterList
	for _, io := range ioAdapter {
		if io.Type == types.IoNetEth {
			nadname := "host-" + io.Name
			_, ok := ctx.ioAdapterMap.Load(nadname)
			if !ok {
				bringupInterface(io.Name)
				err := ioEtherCreate(ctx, &io)
				if err != nil {
					log.Errorf("check_ioAdapter_ethernet: create io adapter error %v", err)
				}
				ctx.ioAdapterMap.Store(nadname, true)
				log.Noticef("check_ioAdapter_ethernet: nad created %v", nadname)
			} else {
				log.Noticef("check_ioAdapter_ethernet: nad already exist %v", nadname)
			}
		}
	}
	return nil
}

func check_del_ioAdpater_ethernet(ctx *zedkubeContext, aiConfig *types.AppInstanceConfig) {

	ioAdapter := aiConfig.IoAdapterList
	for _, io := range ioAdapter {
		if io.Type == types.IoNetEth {
			nadname := "host-" + io.Name
			_, ok := ctx.ioAdapterMap.Load(nadname)
			if ok {
				// remove the syncMap entry
				ctx.ioAdapterMap.Delete(nadname)
			}
			// delete the NAD in kubernetes
			kubeapi.DeleteNAD(log, nadname)
			log.Noticef("check_del_ioAdpater_ethernet: delete existing nad %v", nadname)
		}
	}
}

func updateAppKubeNetStatus(ctx *zedkubeContext, aiConfig *types.AppInstanceConfig) {
	aiName := strings.ToLower(aiConfig.DisplayName)
	if _, ok := ctx.appKubeNetStatus[aiName]; !ok {
		ctx.appKubeNetStatus[aiName] = &types.AppKubeNetworkStatus{
			UUIDandVersion: aiConfig.UUIDandVersion,
			DisplayName:    aiName,
		}
		ulcount := len(aiConfig.AppNetAdapterList)
		ctx.appKubeNetStatus[aiName].ULNetworkStatusList = make([]types.AppNetAdapterStatus, ulcount)
		for i := range aiConfig.AppNetAdapterList {
			ctx.appKubeNetStatus[aiName].ULNetworkStatusList[i].AppNetAdapterConfig =
				aiConfig.AppNetAdapterList[i]
			log.Noticef("updateAppKubeNetStatus: (%d)", i)
		}
		log.Functionf("updateAppKubeNetStatus: ulcount %d, for %s, appKubeNetStatus %+v", ulcount, aiName, ctx.appKubeNetStatus[aiName])
	}
}

func publishAppKubeNetStatus(ctx *zedkubeContext, ebStatus *EveClusterInstStatus) {
	status := lookupNIStatusFromName(ctx, ebStatus.BridgeConfig)
	if status == nil {
		log.Errorf("publishAppKubeNetStatus: can't find NI status for %s", ebStatus.BridgeConfig)
		return
	}

	log.Noticef("publishAppKubeNetStatus: for eve-bridge %v, ni-status %v, nistatus uuid %v, appnet len %d",
		ebStatus, status, status.UUIDandVersion.UUID, len(ctx.appKubeNetStatus))
	for ainame, akStatus := range ctx.appKubeNetStatus {
		log.Noticef("publishAppKubeNetStatus:(%s) akStatus size %d", ainame, len(akStatus.ULNetworkStatusList))
		for i, ulstatus := range akStatus.ULNetworkStatusList {
			log.Noticef("publishAppKubeNetStatus:(%d) ulcfg network %v", i, ulstatus.Network)
			if ulstatus.Network.String() == status.UUIDandVersion.UUID.String() {
				var err error
				ulx := ulstatus
				ulx.Vif = ebStatus.VifName
				ulx.Mac, err = net.ParseMAC(ebStatus.VifMAC)
				if err != nil {
					log.Errorf("publishAppKubeNetStatus: parseMac %s, error %v", ebStatus.VifMAC, err)
				}
				ulx.Bridge = ebStatus.BridgeName
				ulx.AllocatedIPv4Addr = ebStatus.PodIntfPrefix.IP
				ulx.IPv4Assigned = true
				ulx.HostName = ebStatus.PodName

				akStatus.ULNetworkStatusList[i] = ulx

				// got all the NI items. publish
				key := akStatus.UUIDandVersion.UUID.String()
				log.Noticef("publishAppKubeNetStatus: update ul key %s, status %+v", key, ulx)
				ctx.pubAppKubeNetworkStatus.Publish(key, *akStatus)
				akStatus.ContainerID = ebStatus.ContainerID
				ctx.appKubeNetStatus[ainame] = akStatus

				break
			}
		}
	}
}

func unpublishAppKubeNetStatus(ctx *zedkubeContext, filename string) {
	pub := ctx.pubAppKubeNetworkStatus
	items := pub.GetAll()
	for _, item := range items {
		akStatus := item.(types.AppKubeNetworkStatus)
		if strings.Contains(filename, akStatus.ContainerID) {
			key := akStatus.Key()
			log.Noticef("unpublishAppKubeNetStatus: key %s, filename %s", key, filename)
			pub.Unpublish(key)
			return
		}
	}
	log.Noticef("unpublishAppKubeNetStatus: not found %s", filename)
}

func collectAppLogs(ctx *zedkubeContext) {
	sub := ctx.subAppInstanceConfig
	items := sub.GetAll()
	if len(items) == 0 {
		return
	}

	clientset, err := kubernetes.NewForConfig(ctx.config)
	if err != nil {
		log.Errorf("collectAppLogs: can't get clientset %v", err)
		return
	}

	// "Thu Aug 17 05:39:04 UTC 2023"
	timestampRegex := regexp.MustCompile(`(\w{3} \w{3} \d{2} \d{2}:\d{2}:\d{2} \w+ \d{4})`)
	nowStr := time.Now().String()

	var sinceSec int64
	sinceSec = logcollectInterval
	for _, item := range items {
		aiconfig := item.(types.AppInstanceConfig)
		aiName := strings.ToLower(aiconfig.DisplayName)
		aiDispName := aiconfig.GetKubeDispName()

		opt := &corev1.PodLogOptions{}
		if ctx.appLogStarted {
			opt = &corev1.PodLogOptions{
				SinceSeconds: &sinceSec,
			}
		} else {
			ctx.appLogStarted = true
		}
		req := clientset.CoreV1().Pods(eveNamespace).GetLogs(aiDispName, opt)
		podLogs, err := req.Stream(context.Background())
		if err != nil {
			log.Errorf("collectAppLogs: pod %s, log error %v", aiDispName, err)
			continue
		}
		defer podLogs.Close()

		scanner := bufio.NewScanner(podLogs)
		for scanner.Scan() {
			logLine := scanner.Text()

			matches := timestampRegex.FindStringSubmatch(logLine)
			var timeStr string
			if len(matches) > 0 {
				timeStr = matches[0]
				ts := strings.Split(logLine, timeStr)
				if len(ts) > 1 {
					logLine = ts[0]
				}
			} else {
				timeStr = nowStr
			}
			// Process and print the log line here
			aiLogger := ctx.appContainerLogger.WithFields(logrus.Fields{
				"appuuid":       aiconfig.UUIDandVersion.UUID.String(),
				"containername": aiName,
				"eventtime":     timeStr,
			})
			aiLogger.Infof("%s", logLine)
		}
		if scanner.Err() != nil {
			if scanner.Err() == io.EOF {
				break // Break out of the loop when EOF is reached
			}
		}
	}
}

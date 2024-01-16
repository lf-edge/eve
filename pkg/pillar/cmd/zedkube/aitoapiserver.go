package zedkube

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/kubeapi"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"
)

func check_ioAdapter_ethernet(ctx *zedkubeContext, aiConfig *types.AppInstanceConfig) error {

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

func ioEtherCreate(ctx *zedkubeContext, ioAdapt *types.IoAdapter) error {
	name := ioAdapt.Name
	spec := fmt.Sprintf(
		`{
	"cniVersion": "0.3.1",
    "plugins": [
      {
        "type": "host-device",
        "device": "%s"
      }
    ]
}`, name)

	err := kubeapi.CreateOrUpdateNAD(log, "host-"+name, spec)
	if err != nil {
		log.Errorf("ioEtherCreate: spec, CreateOrUpdateNAD, error %v", err)
	} else {
		log.Noticef("ioEtherCreate: spec, CreateOrUpdateNAD, done")
	}
	return err
}

func bringupInterface(intfName string) {
	link, err := netlink.LinkByName(intfName)
	if err != nil {
		log.Errorf("bringupInterface: %v", err)
		return
	}

	// Set the IFF_UP flag to bring up the interface
	if err := netlink.LinkSetUp(link); err != nil {
		log.Errorf("bringupInterface: %v", err)
		return
	}
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
		contName := base.GetAppKubeName(aiconfig.DisplayName, aiconfig.UUIDandVersion.UUID)

		opt := &corev1.PodLogOptions{}
		if ctx.appLogStarted {
			opt = &corev1.PodLogOptions{
				SinceSeconds: &sinceSec,
			}
		} else {
			ctx.appLogStarted = true
		}
		req := clientset.CoreV1().Pods(types.EVEKubeNameSpace).GetLogs(contName, opt)
		podLogs, err := req.Stream(context.Background())
		if err != nil {
			log.Errorf("collectAppLogs: pod %s, log error %v", contName, err)
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
				"containername": contName,
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

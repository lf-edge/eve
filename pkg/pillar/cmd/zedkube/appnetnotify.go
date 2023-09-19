package zedkube

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/lf-edge/eve/pkg/pillar/types"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"kubevirt.io/client-go/kubecli"
)

const (
	eveBridgeStatusPath = "/run/k3s/eve-bridge"
)

// XXX copy those from pillar/k3s/eve-bridge
type EveClusterNIType uint32

const (
	ClusterNITypeNone EveClusterNIType = iota
	ClusterNIInternal
	ClusterNITypeLocal
	ClusterNITypeSwitch
)

type EVEClusterNIOp uint32

const (
	ClusterOPNone EVEClusterNIOp = iota
	ClusterOPAdd
	ClusterOPDel
)

type EveClusterInstStatus struct {
	ContainerID string         `json:"containerID"`
	CNIOp       EVEClusterNIOp `json:"cniOp"`

	K8Snamespace string           `json:"k8sNamespace,omitempty"`
	BridgeConfig string           `json:"bridgeConfig,omitempty"`
	NIType       EveClusterNIType `json:"niType,omitempty"`
	LogicalLabel string           `json:"logicalLabel,omitempty"`

	BridgeName string `json:"bridgeName,omitempty"`
	BridgeMAC  string `json:"bridgeMac,omitempty"`

	PodName      string `json:"podName,omitempty"`
	PodNameSpace string `json:"podNamespace,omitempty"`
	PodIntfName  string `json:"podIntfName,omitempty"`
	PodIntfMAC   string `json:"podIntfMac,omitempty"`

	PodIntfPrefix net.IPNet `json:"podIntfPrefix,omitempty"`
	PodIntfGW     net.IP    `json:"podIntfGw,omitempty"`

	VifName string `json:"vifName,omitempty"`
	VifMAC  string `json:"vifMac,omitempty"`
}

func appNetStatusNotify(ctx *zedkubeContext) {

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Errorf("appNetStatusNotify: fsnotify %v", err)
		return
	}
	defer watcher.Close()

	checkDirTimer := time.NewTimer(5 * time.Second)
	for {
		select {
		case <-checkDirTimer.C:
			if _, err := os.Stat(eveBridgeStatusPath); os.IsNotExist(err) {
				checkDirTimer = time.NewTimer(5 * time.Second)
			} else {
				log.Noticef("appNetStatusNotify: add watcher")
				err = watcher.Add(eveBridgeStatusPath)
				if err != nil {
					log.Errorf("appNetStatusNotify: filepath watch add error %v", err)
				}

				// read in the json files first time if it's already there
				fileInfos, err := os.ReadDir(eveBridgeStatusPath)
				if err == nil {
					log.Noticef("appNetStatusNotify: file info %s", fileInfos)
					for _, fileInfo := range fileInfos {
						processEbStatus(ctx, fileInfo.Name())
					}
				}
			}

		case event, ok := <-watcher.Events:
			if !ok {
				return
			}
			// XXX need to handle remove also
			if event.Op&fsnotify.Write == fsnotify.Write || event.Op&fsnotify.Create == fsnotify.Create || event.Op&fsnotify.Remove == fsnotify.Remove {
				processEbStatus(ctx, event.Name)
			}
		case err, ok := <-watcher.Errors:
			if !ok {
				log.Errorf("appNetStatusNotify: watcher error %v, not ok, exit", err)
				return
			}
			log.Errorf("appNetStatusNotify: watcher error %v", err)
		}
	}
}

func processEbStatus(ctx *zedkubeContext, fileName string) {
	var eveBridgeStatus EveClusterInstStatus
	fileContent, err := os.ReadFile(fileName)
	if err != nil {
		log.Errorf("processEbStatus: readfile error %v", err)
		unpublishAppKubeNetStatus(ctx, fileName)
	} else {
		log.Noticef("processEbStatus: filename %s has changed, content %s", fileName, fileContent)

		err = json.Unmarshal(fileContent, &eveBridgeStatus)
		if err != nil {
			log.Errorf("processEbStatus: json unmarshal error %v", err)
		} else {
			publishAppKubeNetStatus(ctx, &eveBridgeStatus)
		}
	}
}

func runAppVNC(ctx *zedkubeContext, config *types.AppInstanceConfig) {
	vmconfig := config.FixedResources

	//vmiName := findXenCfgName(config.UUIDandVersion.UUID.String())
	var vmiName string
	i := 5
	for {
		var err error
		vmiName, err = getVMIdomainName(ctx, config.UUIDandVersion.UUID.String())
		if err != nil {
			log.Noticef("runAppVNC: get vmi domainname error %v", err)
			if i >= 0 {
				time.Sleep(3 * time.Second)
				continue
			}
		} else {
			break
		}
		i = i - 1
	}
	if vmiName == "" {
		log.Noticef("runAppVNC: can not find vmiName")
		return
	}
	vncPort := vmconfig.VncDisplay + 5900
	port := strconv.Itoa(int(vncPort))

	//args := []string{"vnc", vmiName, "-n", "eveNamespace", "--kubeconfig",
	//	"/run/.kube/k3s/k3s.yaml", "--port", port, "--proxy-only"}
	if config.RemoteConsole {
		content := fmt.Sprintf("VMINAME:%s\nVNCPORT:%s\n", vmiName, port)
		err := os.WriteFile(vmiVNCFileName, []byte(content), 0644)
		if err != nil {
			log.Errorf("runAppVNC: Error creating file: %v", err)
			return
		}
		log.Noticef("runAppVNC: vmiName %s, port %s, vmiVNC file created", vmiName, port)
	} else {
		if _, err := os.Stat(vmiVNCFileName); err == nil {
			err = os.Remove(vmiVNCFileName)
			if err != nil {
				log.Errorf("runAppVNC: Error remove file %v", err)
				return
			}
		}
	}
	log.Noticef("runAppVNC: done")
}

func getVMIdomainName(ctx *zedkubeContext, appuuid string) (string, error) {
	virtClient, err := kubecli.GetKubevirtClientFromRESTConfig(ctx.config)
	if err != nil {
		log.Errorf("getVMIs: get virtclient error %v", err)
		return "", err
	}

	var domainName string
	vmis, err := virtClient.VirtualMachineInstance(eveNamespace).List(context.Background(), &metav1.ListOptions{})
	if err != nil {
		log.Errorf("getVMIs: get VMI list error %v", err)
		return "", err
	}

	for _, vmi := range vmis.Items {
		if !strings.Contains(vmi.ObjectMeta.Name, appuuid) {
			continue
		}
		domainName = vmi.ObjectMeta.Name
		break
	}

	return domainName, nil
}

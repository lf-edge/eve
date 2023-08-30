package zedkube

import (
	"encoding/json"
	"net"
	"os"
	"time"

	"github.com/fsnotify/fsnotify"
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

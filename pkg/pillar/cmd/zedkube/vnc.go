package zedkube

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/types"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"kubevirt.io/client-go/kubecli"
)

func runAppVNC(ctx *zedkubeContext, config *types.AppInstanceConfig) {
	vmconfig := config.FixedResources

	//vmiName := findXenCfgName(config.UUIDandVersion.UUID.String())
	var vmiName string
	i := 5
	for {
		var err error
		vmiName, err = getVMIdomainName(ctx, config)
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
	log.Noticef("runAppVNC: %v, done", vmiName)
}

func getVMIdomainName(ctx *zedkubeContext, config *types.AppInstanceConfig) (string, error) {
	virtClient, err := kubecli.GetKubevirtClientFromRESTConfig(ctx.config)
	if err != nil {
		log.Errorf("getVMIs: get virtclient error %v", err)
		return "", err
	}

	DispName := config.GetKubeDispName()
	var domainName string
	vmis, err := virtClient.VirtualMachineInstance(eveNamespace).List(context.Background(), &metav1.ListOptions{})
	if err != nil {
		log.Errorf("getVMIs: get VMI list error %v", err)
		return "", err
	}

	for _, vmi := range vmis.Items {
		if !strings.Contains(vmi.ObjectMeta.Name, DispName) {
			continue
		}
		domainName = vmi.ObjectMeta.Name
		break
	}

	return domainName, nil
}

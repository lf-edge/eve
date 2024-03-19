// Copyright (c) 2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build kubevirt

package zedkube

import (
	"fmt"

	"github.com/lf-edge/eve/pkg/pillar/kubeapi"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/vishvananda/netlink"
)

// checkIoAdapterEthernet - check and create NAD for direct-attached ethernet
func checkIoAdapterEthernet(ctx *zedkubeContext, aiConfig *types.AppInstanceConfig) error {

	if aiConfig.FixedResources.VirtualizationMode != types.NOHYPER {
		return nil
	}
	ioAdapter := aiConfig.IoAdapterList
	for _, io := range ioAdapter {
		if io.Type == types.IoNetEth {
			nadname := "host-" + io.Name
			_, ok := ctx.networkInstanceStatusMap.Load(nadname)
			if !ok {
				bringupInterface(io.Name)
				err := ioEtherCreate(ctx, &io)
				if err != nil {
					log.Errorf("checkIoAdapterEthernet: create io adapter error %v", err)
				}
				ctx.ioAdapterMap.Store(nadname, true)
				log.Functionf("ccheckIoAdapterEthernet: nad created %v", nadname)
			} else {
				log.Functionf("checkIoAdapterEthernet: nad already exist %v", nadname)
			}
		}
	}
	return nil
}

func checkDelIoAdapterEthernet(ctx *zedkubeContext, aiConfig *types.AppInstanceConfig) {

	if aiConfig.FixedResources.VirtualizationMode != types.NOHYPER {
		return
	}
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
			log.Functionf("checkDelIoAdapterEthernet: delete existing nad %v", nadname)
		}
	}
}

// ioEtherCreate - create and send NAD for direct-attached ethernet
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
		log.Functionf("ioEtherCreate: spec, CreateOrUpdateNAD, done")
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

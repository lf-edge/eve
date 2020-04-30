// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/lf-edge/eden/pkg/controller"
	"github.com/lf-edge/eden/pkg/utils"
	"github.com/lf-edge/eve/api/go/config"
	"github.com/lf-edge/eve/api/go/evecommon"
	"os"
	"path"
	"path/filepath"
)

type netInst struct {
	networkInstanceID   string
	networkInstanceName string
	networkInstanceType config.ZNetworkInstType
	ipSpec              *config.Ipspec
}

type appInstLocal struct {
	dataStoreID        string
	imageID            string
	imageFormat        config.Format
	appID              string
	appName            string
	imageFileName      string
	memory             uint32
	vcpu               uint32
	eveIP              string
	accessPortExternal string
	accessPortInternal string
}

var eServerDataStoreID = "eab8761b-5f89-4e0b-b757-4b87a9fa93ec"

var eServerURL = "http://mydomain.adam:8888"

var (
	networkInstanceLocal = &netInst{"eab8761b-5f89-4e0b-b757-4b87a9fa93e1",
		"test-local", config.ZNetworkInstType_ZnetInstLocal, &config.Ipspec{
			Subnet:  "10.1.0.0/24",
			Gateway: "10.1.0.1",
			Dns:     []string{"10.1.0.1"},
			DhcpRange: &config.IpRange{
				Start: "10.1.0.2",
				End:   "10.1.0.254",
			},
		}}
	networkInstanceLocalSecond = &netInst{"eab8761b-5f89-4e0b-b757-4b87a9fa93e2",
		"test-local-second", config.ZNetworkInstType_ZnetInstLocal, &config.Ipspec{
			Subnet:  "10.2.0.0/24",
			Gateway: "10.2.0.1",
			Dns:     []string{"10.2.0.1"},
			DhcpRange: &config.IpRange{
				Start: "10.2.0.2",
				End:   "10.2.0.254",
			},
		}}
	networkInstanceSwitch = &netInst{"eab8761b-5f89-4e0b-b757-4b87a9fa93e3",
		"test-switch", config.ZNetworkInstType_ZnetInstSwitch, nil}
	networkInstanceCloud = &netInst{"eab8761b-5f89-4e0b-b757-4b87a9fa93e4",
		"test-cloud", config.ZNetworkInstType_ZnetInstCloud, &config.Ipspec{
			Dhcp:    config.DHCPType_DHCPNone,
			Subnet:  "30.1.0.0/24",
			Gateway: "30.1.0.1",
			Dns:     []string{"30.1.0.1"},
			DhcpRange: &config.IpRange{
				Start: "30.1.0.2",
				End:   "30.1.0.254",
			},
		}}
)

var (
	appInstanceLocalVM = &appInstLocal{eServerDataStoreID,

		"1ab8761b-5f89-4e0b-b757-4b87a9fa93e1",
		config.Format_QCOW2,

		"22b8761b-5f89-4e0b-b757-4b87a9fa93e1",
		"test-alpine-vm",

		"alpine.qcow2",
		1024 * 1024,
		1,
		"127.0.0.1",
		"8027",
		"80",
	}
	appInstanceLocalContainer = &appInstLocal{eServerDataStoreID,

		"1ab8761b-5f89-4e0b-b757-4b87a9fa93e2",
		config.Format_CONTAINER,

		"22b8761b-5f89-4e0b-b757-4b87a9fa93e2",
		"test-alpine-container",

		"alpine.tar",
		1024 * 1024,
		1,
		"127.0.0.1",
		"8028",
		"80",
	}
)

var checkLogs = false

func prepareImageLocal(ctx controller.Cloud, dataStoreID string, imageID string, imageFormat config.Format, imageFileName string, isBaseOS bool) (*config.Image, error) {
	dataStore, err := ctx.GetDataStore(dataStoreID)
	if dataStore == nil {
		dataStore = &config.DatastoreConfig{
			Id:       dataStoreID,
			DType:    config.DsType_DsHttp,
			Fqdn:     eServerURL,
			ApiKey:   "",
			Password: "",
			Dpath:    "",
			Region:   "",
		}
	}

	imageFullPath := path.Join(filepath.Dir(ctx.GetDir()), "images", "vm", imageFileName)
	imageDSPath := fmt.Sprintf("vm/%s", imageFileName)

	if imageFormat == config.Format_CONTAINER {
		imageFullPath = path.Join(filepath.Dir(ctx.GetDir()), "images", "docker", imageFileName)
		imageDSPath = fmt.Sprintf("docker/%s", imageFileName)
	}

	if isBaseOS {
		imageFullPath = path.Join(filepath.Dir(ctx.GetDir()), "images", "baseos", imageFileName)
		imageDSPath = fmt.Sprintf("baseos/%s", imageFileName)
	}
	fi, err := os.Stat(imageFullPath)
	if err != nil {
		return nil, err
	}
	size := fi.Size()

	sha256sum := ""
	if imageFormat != config.Format_CONTAINER {
		sha256sum, err = utils.SHA256SUM(imageFullPath)
		if err != nil {
			return nil, err
		}
	}
	img := &config.Image{
		Uuidandversion: &config.UUIDandVersion{
			Uuid:    imageID,
			Version: "4",
		},
		Name:      imageDSPath,
		Sha256:    sha256sum,
		Iformat:   imageFormat,
		DsId:      dataStoreID,
		SizeBytes: size,
		Siginfo: &config.SignatureInfo{
			Intercertsurl: "",
			Signercerturl: "",
			Signature:     nil,
		},
	}
	if ds, _ := ctx.GetDataStore(dataStoreID); ds == nil {
		err = ctx.AddDataStore(dataStore)
		if err != nil {
			return nil, err
		}
	}
	err = ctx.AddImage(img)
	if err != nil {
		return nil, err
	}
	return img, nil
}

func prepareApplicationLocal(ctx controller.Cloud, appDefinition *appInstLocal, userData string, vncDisplay uint32, networkAdapters []*config.NetworkAdapter) error {
	img, err := prepareImageLocal(ctx, appDefinition.dataStoreID, appDefinition.imageID, appDefinition.imageFormat, appDefinition.imageFileName, false)
	if err != nil {
		return err
	}
	var drive = &config.Drive{
		Image:    img,
		Readonly: false,
		Preserve: false,
		Drvtype:  config.DriveType_HDD,
		Target:   config.Target_Disk,
	}
	err = ctx.AddApplicationInstanceConfig(&config.AppInstanceConfig{
		Uuidandversion: &config.UUIDandVersion{
			Uuid:    appDefinition.appID,
			Version: "4",
		},
		Displayname: appDefinition.appName,
		Fixedresources: &config.VmConfig{
			Kernel:             "",
			Ramdisk:            "",
			Memory:             appDefinition.memory,
			Maxmem:             appDefinition.memory,
			Vcpus:              appDefinition.vcpu,
			Maxcpus:            0,
			Rootdev:            "/dev/xvda1",
			Extraargs:          "",
			Bootloader:         "/usr/bin/pygrub",
			Cpus:               "",
			Devicetree:         "",
			Dtdev:              nil,
			Irqs:               nil,
			Iomem:              nil,
			VirtualizationMode: config.VmMode_HVM,
			EnableVnc:          true,
			VncDisplay:         vncDisplay,
			VncPasswd:          "",
		},
		Drives:        []*config.Drive{drive},
		Activate:      true,
		Interfaces:    networkAdapters,
		Adapters:      nil,
		Restart:       nil,
		Purge:         nil,
		UserData:      base64.StdEncoding.EncodeToString([]byte(userData)),
		RemoteConsole: false,
	})
	if err != nil {
		return err
	}
	return nil
}

func prepareBaseImageLocal(ctx controller.Cloud, dataStoreID string, imageID string, baseID string, imageFileName string, imageFormat config.Format, baseOSVersion string) error {
	img, err := prepareImageLocal(ctx, dataStoreID, imageID, imageFormat, imageFileName, true)
	if err != nil {
		return err
	}
	err = ctx.AddBaseOsConfig(&config.BaseOSConfig{
		Uuidandversion: &config.UUIDandVersion{
			Uuid:    baseID,
			Version: "4",
		},
		Drives: []*config.Drive{{
			Image:        img,
			Readonly:     false,
			Preserve:     false,
			Drvtype:      config.DriveType_Unclassified,
			Target:       config.Target_TgtUnknown,
			Maxsizebytes: img.SizeBytes,
		}},
		Activate:      true,
		BaseOSVersion: baseOSVersion,
		BaseOSDetails: nil,
	})
	if err != nil {
		return err
	}
	return nil
}

func cloudOConfig(subnet string) string {
	return `{ "VpnRole": "onPremClient",
  "VpnGatewayIpAddr": "192.168.254.51",
  "VpnSubnetBlock": "20.1.0.0/24",
  "ClientConfigList": [{"IpAddr": "%any", "PreSharedKey": "0sjVzONCF02ncsgiSlmIXeqhGN", "SubnetBlock": "` + subnet + `"}]
}`
}
func prepareNetworkInstance(ctx controller.Cloud, networkInstanceInput *netInst, model *controller.DevModel) error {
	uid := config.UUIDandVersion{
		Uuid:    networkInstanceInput.networkInstanceID,
		Version: "4",
	}
	networkInstance := config.NetworkInstanceConfig{
		Uuidandversion: &uid,
		Displayname:    networkInstanceInput.networkInstanceName,
		InstType:       networkInstanceInput.networkInstanceType,
		Activate:       true,
		Port:           nil,
		Cfg:            nil,
		IpType:         config.AddressType_First,
		Ip:             nil,
	}
	switch networkInstanceInput.networkInstanceType {
	case config.ZNetworkInstType_ZnetInstSwitch:
		networkInstance.Port = &config.Adapter{
			Name: model.GetFirstAdapterForSwitches(),
		}
		networkInstance.Cfg = &config.NetworkInstanceOpaqueConfig{}
	case config.ZNetworkInstType_ZnetInstLocal:
		if networkInstanceInput.ipSpec == nil {
			return errors.New("cannot use with nil ipSpec")
		}
		networkInstance.IpType = config.AddressType_IPV4
		networkInstance.Port = &config.Adapter{
			Name: "uplink",
		}
		networkInstance.Ip = networkInstanceInput.ipSpec
		networkInstance.Cfg = &config.NetworkInstanceOpaqueConfig{}
	case config.ZNetworkInstType_ZnetInstCloud:
		if networkInstanceInput.ipSpec == nil {
			return errors.New("cannot use with nil ipSpec")
		}
		networkInstance.IpType = config.AddressType_IPV4
		networkInstance.Port = &config.Adapter{
			Type: evecommon.PhyIoType_PhyIoNoop,
			Name: "uplink",
		}
		networkInstance.Ip = networkInstanceInput.ipSpec
		networkInstance.Cfg = &config.NetworkInstanceOpaqueConfig{
			Oconfig:    cloudOConfig(networkInstanceInput.ipSpec.Subnet),
			LispConfig: nil,
			Type:       config.ZNetworkOpaqueConfigType_ZNetOConfigVPN,
		}
	default:
		return errors.New("not implemented type")
	}
	return ctx.AddNetworkInstanceConfig(&networkInstance)
}

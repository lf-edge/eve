package main

import (
	"log"
	"io/ioutil"
	"encoding/json"
	"github.com/satori/go.uuid"
	"github.com/zededa/go-provision/types"
	"shared/proto/zconfig"
)

func parseConfig(config *zconfig.EdgeDevConfig) {
	var appInstance = types.AppInstanceConfig{}

	for _,cfgApp :=	range config.Apps {

		appInstance.UUIDandVersion.UUID,_		= uuid.FromString(cfgApp.Uuidandversion.Uuid)
		appInstance.UUIDandVersion.Version		= cfgApp.Uuidandversion.Version
		appInstance.DisplayName					= cfgApp.Displayname
		appInstance.Activate					= cfgApp.Activate

		appInstance.FixedResources.Kernel		= cfgApp.Fixedresources.Kernel
		appInstance.FixedResources.Ramdisk		= cfgApp.Fixedresources.Ramdisk
		appInstance.FixedResources.BootLoader	= cfgApp.Fixedresources.Bootloader
		appInstance.FixedResources.MaxMem		= int(cfgApp.Fixedresources.Maxmem)
		appInstance.FixedResources.Memory		= int(cfgApp.Fixedresources.Memory)
		appInstance.FixedResources.RootDev		= cfgApp.Fixedresources.Rootdev
		appInstance.FixedResources.VCpus		= int(cfgApp.Fixedresources.Vcpus)

		appInstance.StorageConfigList = make([]types.StorageConfig,len(cfgApp.Drives))

		var idx int = 0
		for _,drive :=	range cfgApp.Drives {

			image := new(types.StorageConfig)
			for _, ds :=	range config.Datastores {

				if drive.Image.Id	== ds.Id {

					image.DownloadURL		= ds.Fqdn
					//image.TransportMethod	= zconfig.DsType_name [ds.DType]
					image.TransportMethod	= ds.DType.String()
					break
				}
			}
			image.Format			= drive.Image.Iformat.String()
			image.ImageSignature	= drive.Image.Siginfo.Signature
			image.ImageSha256		= drive.Image.Sha256
			image.MaxSize			= uint(drive.Maxsize)
			image.ReadOnly			= drive.Readonly
			image.Preserve			= drive.Preserve
			image.Target			= drive.Target.String()
			image.Devtype			= drive.Drvtype.String()

			appInstance.StorageConfigList[idx] = *image
			idx++
		}

		appFilename := cfgApp.Uuidandversion.Uuid
		writeAppInstance (appInstance, appFilename)
	}
}

func writeAppInstance (appInstance types.AppInstanceConfig, appFilename string) {

	log.Printf("%T\n",appInstance)
	bytes, err := json.Marshal(appInstance)
	if err != nil {
		log.Fatal(err, "json Marshal VerifyImageStatus")
	}
	err = ioutil.WriteFile(zedmanagerConfigDirname+ "/" + appFilename+".json", bytes, 0644)
	if err != nil {
		log.Fatal(err)
	}
}

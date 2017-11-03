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

	Apps := config.GetApps()

	for _,cfgApp :=	range Apps {

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

				if drive.Image.DsId	== ds.Id {

					image.DownloadURL		= ds.Fqdn
					image.TransportMethod	= ds.DType.String()
					image.ApiKey			= ds.ApiKey
					image.Password			= ds.Password
					image.Dpath				= ds.Dpath
					break
				}
			}

			image.CertificateChain	= make([]string, 1)
			image.Format			= drive.Image.Iformat.String()
			image.ImageSignature	= drive.Image.Siginfo.Signature
			image.SignatureKey		= drive.Image.Siginfo.Signercerturl
			image.CertificateChain[0]	= drive.Image.Siginfo.Intercertsurl
			image.ImageSha256		= drive.Image.Sha256
			image.MaxSize			= uint(drive.Maxsize)
			image.ReadOnly			= drive.Readonly
			image.Preserve			= drive.Preserve
			image.Target			= drive.Target.String()
			image.Devtype			= drive.Drvtype.String()

			appInstance.StorageConfigList[idx] = *image
			idx++
		}

		var netx int = 0
		appInstance.UnderlayNetworkList = make([]types.UnderlayNetworkConfig,len(cfgApp.Interfaces))
			for _,interfaces := range cfgApp.Interfaces {
				underlayNetworkDetails := new(types.UnderlayNetworkConfig)
				for _,networks := range config.Networks {

					if interfaces.NetworkId == networks.Id {

						underlayNetworkDetails.ACLs = make([]types.ACE,len(interfaces.Acls))
						var acx int = 0
						for _,acl := range interfaces.Acls {

							aceDetails := new(types.ACE)
							aceDetails.Matches =  make([]types.ACEMatch,len(acl.Matches))
							aceDetails.Actions = make([]types.ACEAction,len(acl.Actions))
							var matx int = 0
							for _,match := range acl.Matches {
								aceMatchDetails := new(types.ACEMatch)
								aceMatchDetails.Type = match.Type
								aceMatchDetails.Value = match.Value
								aceDetails.Matches[matx] = *aceMatchDetails
								matx ++
							}
							var actx int = 0
							for _,action := range acl.Actions {
								aceActionDetails := new(types.ACEAction)
								aceActionDetails.Limit = action.Limit
								aceActionDetails.LimitRate =  int(action.Limitrate)
								aceActionDetails.LimitUnit =  action.Limitunit
								aceActionDetails.LimitBurst = int(action.Limitburst)
								//aceActionDetails.Drop =
								aceDetails.Actions[actx] = *aceActionDetails
								actx ++
							}
							underlayNetworkDetails.ACLs[acx] =  *aceDetails
							acx ++
						}
				}
			}
			appInstance.UnderlayNetworkList[netx] = *underlayNetworkDetails
			netx ++
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

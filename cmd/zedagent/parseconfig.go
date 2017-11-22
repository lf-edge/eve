package main

import (
	"fmt"
	"log"
	"strings"
	"io/ioutil"
	"encoding/json"
	"github.com/satori/go.uuid"
	"github.com/zededa/go-provision/types"
	"github.com/zededa/api/zconfig"
)

const (
	certBaseDirname = "/var/tmp/downloader/cert.obj"
	certRunDirname = "/var/run/downloader/cert.obj"
	certConfigDirname = certBaseDirname + "/config"
	certStatusDirname = certRunDirname + "/status"
	imgCatalogDirname = "/var/tmp/zedmanager/downloads"
	pendingDirname = imgCatalogDirname + "/pending"
	verifierDirname = imgCatalogDirname + "/verifier"
	finalDirname = imgCatalogDirname + "/verified"
	certsDownloadDirname = imgCatalogDirname + "/certs" // XXX vs. cert.obj?
	certificateDirname = "/var/tmp/zedmanager/certs"
)

func parseConfig(config *zconfig.EdgeDevConfig) {

	var appInstance = types.AppInstanceConfig{}

	log.Println("Applying new config")

	Apps := config.GetApps()


	for _,cfgApp :=	range Apps {


		log.Printf("%v\n", cfgApp)

		appInstance.UUIDandVersion.UUID,_		= uuid.FromString(cfgApp.Uuidandversion.Uuid)
		appInstance.UUIDandVersion.Version		= cfgApp.Uuidandversion.Version
		appInstance.DisplayName					= cfgApp.Displayname
		appInstance.Activate					= cfgApp.Activate

		appInstance.FixedResources.Kernel		= cfgApp.Fixedresources.Kernel
		appInstance.FixedResources.Ramdisk		= cfgApp.Fixedresources.Ramdisk
		appInstance.FixedResources.MaxMem		= int(cfgApp.Fixedresources.Maxmem)
		appInstance.FixedResources.Memory		= int(cfgApp.Fixedresources.Memory)
		appInstance.FixedResources.RootDev		= cfgApp.Fixedresources.Rootdev
		appInstance.FixedResources.VCpus		= int(cfgApp.Fixedresources.Vcpus)

		appInstance.StorageConfigList = make([]types.StorageConfig,len(cfgApp.Drives))

		var idx int = 0

		for _,drive :=	range cfgApp.Drives {

			found := false

			image := new(types.StorageConfig)
			for _, ds :=	range config.Datastores {

				if drive.Image != nil &&
					drive.Image.DsId == ds.Id {

					found					= true
					image.DownloadURL		= ds.Fqdn+"/"+ds.Dpath+"/"+drive.Image.Name
					image.TransportMethod	= ds.DType.String()
					image.ApiKey			= ds.ApiKey
					image.Password			= ds.Password
					image.Dpath				= ds.Dpath
					break
				}
			}

			if found == false { continue }

			// XXX:FIXME certificate should be of variable length
			// depending on the number of certificates in the chain
			// this list, currently contains the certUrls
			// should be the sha/uuid of cert filenames
			//  proper DataStore Entries

			image.CertificateChain	= make([]string, 1)
			image.Format			= strings.ToLower(drive.Image.Iformat.String())
			image.ImageSignature	= drive.Image.Siginfo.Signature
			image.SignatureKey		= drive.Image.Siginfo.Signercerturl
			image.CertificateChain[0]	= drive.Image.Siginfo.Intercertsurl
			image.ImageSha256		= drive.Image.Sha256
			image.MaxSize			= uint(drive.Maxsize)
			image.ReadOnly			= drive.Readonly
			image.Preserve			= drive.Preserve
			image.Target			= strings.ToLower(drive.Target.String())
			image.Devtype			= strings.ToLower(drive.Drvtype.String())

			// XXX:FIXME, to be decided after consulting with erik
			if image.Target == "disk" {
				appInstance.FixedResources.BootLoader	= "/usr/lib/xen-4.6/bin/pygrub"
			}
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
						aceDetails.Matches = make([]types.ACEMatch,len(acl.Matches))
						aceDetails.Actions = make([]types.ACEAction,len(acl.Actions))
						var matx int = 0
						for _,match := range acl.Matches {
							aceMatchDetails := new(types.ACEMatch)
							aceMatchDetails.Type		= match.Type
							aceMatchDetails.Value		= match.Value
							aceDetails.Matches[matx]	= *aceMatchDetails
							matx ++
						}
						var actx int = 0
						for _,action := range acl.Actions {
							aceActionDetails := new(types.ACEAction)
							aceActionDetails.Limit		= action.Limit
							aceActionDetails.LimitRate	=  int(action.Limitrate)
							aceActionDetails.LimitUnit	=  action.Limitunit
							aceActionDetails.LimitBurst	= int(action.Limitburst)
							// XXX:FIXME aceActionDetails.Drop = <TBD>
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

// XXX:FIXME will enable after testing
/*
		var ovnetx int = 0
		appInstance.OverlayNetworkList = make([]types.EIDOverlayConfig,len(cfgApp.Interfaces))
		for _,interfaces := range cfgApp.Interfaces {
			overlayNetworkDetails := new(types.EIDOverlayConfig)
			for _,networks := range config.Networks {

				if interfaces.NetworkId == networks.Id {

					overlayNetworkDetails.ACLs = make([]types.ACE,len(interfaces.Acls))
					var ovacx int = 0
					for _,acl := range interfaces.Acls {

						aceDetails := new(types.ACE)
						aceDetails.Matches =  make([]types.ACEMatch,len(acl.Matches))
						aceDetails.Actions = make([]types.ACEAction,len(acl.Actions))
						var ovmatx int = 0
						for _,match := range acl.Matches {
							aceMatchDetails := new(types.ACEMatch)
							aceMatchDetails.Type = match.Type
							aceMatchDetails.Value = match.Value
							aceDetails.Matches[ovmatx] = *aceMatchDetails
							ovmatx ++
						}
						var ovactx int = 0
						for _,action := range acl.Actions {
							aceActionDetails := new(types.ACEAction)
							aceActionDetails.Limit = action.Limit
							aceActionDetails.LimitRate =  int(action.Limitrate)
							aceActionDetails.LimitUnit =  action.Limitunit
							aceActionDetails.LimitBurst = int(action.Limitburst)
							aceDetails.Actions[ovactx] = *aceActionDetails
							ovactx ++
						}
						overlayNetworkDetails.ACLs[ovacx] =  *aceDetails
						ovacx ++
					}
				}
			}
			appInstance.OverlayNetworkList[ovnetx] = *overlayNetworkDetails
			ovnetx ++
		}
*/

		// get the certs for image sha verification
		getCerts (appInstance)

		// write to zedmanager config directory
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

func getCerts (appInstance types.AppInstanceConfig) {

	for _,image := range appInstance.StorageConfigList {

		writeCertConfig (image, image.SignatureKey)

		for _, certUrl := range image.CertificateChain {
			writeCertConfig (image, certUrl)
		}
	}
}

func writeCertConfig (image types.StorageConfig, certUrl string) {

	var baseCertDirname		= "/var/tmp/downloader/cert.obj"
	var configCertDirname	= baseCertDirname + "/config"

	var safename = types.UrlToSafename(certUrl, "")

	// XXX:FIXME dpath/key/pwd from image storage
	// should be coming from Drive
	// also the sha for the cert should be set
	var config = &types.DownloaderConfig {
			Safename:			safename,
			DownloadURL:		certUrl,
			MaxSize:			image.MaxSize,
			TransportMethod:	image.TransportMethod,
			Dpath:				"zededa-cert-repo",
			ApiKey:				image.ApiKey,
			Password:			image.Password,
			ImageSha256:		"",
			DownloadObjDir:		certsDownloadDirname,
			VerifiedObjDir:		certificateDirname,
			RefCount:		1,
		}

	bytes, err := json.Marshal(config)
	if err != nil {
		log.Fatal(err, "json Marshal certConfig")
	}

	configFilename := fmt.Sprintf("%s/%s.json", configCertDirname, safename)
	err = ioutil.WriteFile(configFilename, bytes, 0644)
	if err != nil {
		log.Fatal(err)
	}
}

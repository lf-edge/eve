package main

import (
	"fmt"
	"log"
	"io/ioutil"
	"encoding/json"
	"github.com/satori/go.uuid"
	"github.com/zededa/go-provision/types"
	"shared/proto/zconfig"
	"strings"
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

			// XXX:FIXME certificate should be of variable length
			// depending on the number of certifications in the chain
			// this listcurrently contains the certUrls
			// should be the sha/uuid of cert filenames

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

	var safename = urlToSafename(certUrl, "")

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
			DownloadObjDir:		"/var/tmp/zedmanager/certs",
			RefCount:			1,
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

func urlToSafename(url string, sha string) string {

	var safename string

	if sha != "" {
		safename = strings.Replace(url, "/", "_", -1) + "." + sha
	} else {
		names := strings.Split(url, "/")
	        for _, name := range names {
		    safename = name
		}
	}
    return safename
}

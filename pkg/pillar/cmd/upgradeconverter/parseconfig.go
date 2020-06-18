// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package upgradeconverter

// Parse the checkpointed protobuf file to determine the relationship between
// app instances and their drives and the volumes

import (
	"io/ioutil"

	"github.com/golang/protobuf/proto"
	zconfig "github.com/lf-edge/eve/api/go/config"
	uuid "github.com/satori/go.uuid"
	log "github.com/sirupsen/logrus"
)

type parseResult struct {
	volumes      []volumeInfo
	appInsts     []driveAndVolumeRef
	contentTrees []contentTree
}

func parseConfig(checkpointFile string) (parseResult, error) {
	res := parseResult{}
	config, err := readSavedProtoMessage(checkpointFile)
	if err != nil {
		return res, err
	}
	cts, err := parseContentTrees(config)
	if err != nil {
		return res, err
	}
	for i, ct := range cts {
		log.Debugf("content tree[%d] ctID %s displayName %s relativeURL %s sha256 %s gc %d",
			i, ct.contentTreeID, ct.displayName, ct.relativeURL,
			ct.sha256, ct.generationCounter)
	}
	res.contentTrees = cts
	volumes, err := parseVolumes(config)
	if err != nil {
		return res, err
	}
	for i, vi := range volumes {
		log.Debugf("volume[%d] volumeID %s ctID %s imageURL %s sha256 %s gc %d",
			i, vi.volumeID, vi.contentTreeID, vi.imageURL, vi.sha256,
			vi.generationCounter)
	}
	res.volumes = volumes
	appInsts, err := parseAppInstances(config)
	if err != nil {
		return res, err
	}
	for i, ai := range appInsts {
		log.Debugf("app inst[%d] appInstID %s imageID %s imageName %s sha256 %s purgeCounter %d volumeID %s gc %d",
			i, ai.appInstID, ai.imageID, ai.imageName, ai.sha256,
			ai.purgeCounter, ai.volumeID, ai.generationCounter)
	}
	res.appInsts = appInsts

	return res, nil
}

func readSavedProtoMessage(filename string) (*zconfig.EdgeDevConfig, error) {
	contents, err := ioutil.ReadFile(filename)
	if err != nil {
		log.Errorln("readSavedProtoMessage", err)
		return nil, err
	}
	var configResponse = &zconfig.ConfigResponse{}
	err = proto.Unmarshal(contents, configResponse)
	if err != nil {
		log.Errorf("readSavedProtoMessage Unmarshalling failed: %v",
			err)
		return nil, err
	}
	config := configResponse.GetConfig()
	return config, nil
}

func parseAppInstances(config *zconfig.EdgeDevConfig) ([]driveAndVolumeRef, error) {
	var appInsts []driveAndVolumeRef

	apps := config.GetApps()
	log.Debugf("parseAppInstances %d apps", len(apps))
	for i, cfgApp := range apps {
		appInstID, _ := uuid.FromString(cfgApp.Uuidandversion.Uuid)
		drives := cfgApp.GetDrives()
		volumeRefs := cfgApp.GetVolumeRefList()

		var purgeCounter uint32
		cmd := cfgApp.GetPurge()
		if cmd != nil {
			purgeCounter = cmd.Counter
		}
		log.Infof("parseAppInstances[%d] %d drives %d volumeRefs",
			i, len(drives), len(volumeRefs))

		davr := make([]driveAndVolumeRef, len(drives))
		for i, drive := range drives {
			image := drive.GetImage()
			imageID, _ := uuid.FromString(image.Uuidandversion.Uuid)
			davr[i].appInstID = appInstID
			davr[i].imageID = imageID
			davr[i].imageName = image.Name
			davr[i].sha256 = image.Sha256
			// Just like zedagent we apply the purgeCounter to the
			// first disk
			if i == 0 && purgeCounter != 0 {
				log.Infof("parseAppInstances setting purgeCounter to %d  for appInstID %s imageID %s",
					purgeCounter, appInstID, imageID)
				davr[i].purgeCounter = purgeCounter
			}
			if len(volumeRefs) > i {
				volumeID, _ := uuid.FromString(volumeRefs[i].Uuid)
				davr[i].volumeID = volumeID
				davr[i].generationCounter = volumeRefs[i].GenerationCount
			}
		}
		appInsts = append(appInsts, davr...)
	}
	return appInsts, nil
}

func parseVolumes(config *zconfig.EdgeDevConfig) ([]volumeInfo, error) {

	var volumes []volumeInfo
	vols := config.GetVolumes()
	log.Debugf("parseVolumes %d volumes", len(vols))
	for _, vol := range vols {
		volumeID, _ := uuid.FromString(vol.Uuid)
		vco := vol.GetOrigin()
		var ctID uuid.UUID
		if vco != nil {
			ctID, _ = uuid.FromString(vco.DownloadContentTreeID)
		}
		vi := volumeInfo{
			volumeID:      volumeID,
			contentTreeID: ctID,
		}
		volumes = append(volumes, vi)
	}
	return volumes, nil
}

func parseContentTrees(config *zconfig.EdgeDevConfig) ([]contentTree, error) {

	var cts []contentTree
	zcts := config.GetContentInfo()
	log.Debugf("parseContentTrees %d contentTrees", len(zcts))
	for _, zct := range zcts {
		ctID, _ := uuid.FromString(zct.Uuid)
		ct := contentTree{
			contentTreeID:     ctID,
			relativeURL:       zct.GetURL(),
			sha256:            zct.GetSha256(),
			displayName:       zct.GetDisplayName(),
			generationCounter: zct.GetGenerationCount(),
		}
		cts = append(cts, ct)
	}
	return cts, nil
}

// lookupContentTree returns nil if not found
func (pr parseResult) lookupContentTree(ctID uuid.UUID) *contentTree {
	for i := range pr.contentTrees {
		ct := &pr.contentTrees[i]
		if ct.contentTreeID == ctID {
			log.Debugf("lookupContentTree found %s", ctID)
			return ct
		}
	}
	log.Errorf("lookupContentTree NOT found %s", ctID)
	return nil
}

// lookupDriveAndVolumeRef returns nil if not found
func (pr parseResult) lookupDriveAndVolumeRef(appInstID uuid.UUID, sha256 string) *driveAndVolumeRef {
	for i := range pr.appInsts {
		dlvr := &pr.appInsts[i]
		if dlvr.appInstID == appInstID && dlvr.sha256 == sha256 {
			log.Debugf("lookupAppInst found %s sha %s",
				appInstID, sha256)
			return dlvr
		}
	}
	log.Errorf("lookupAppInst NOT found %s", appInstID)
	return nil
}

// lookupVolume returns nil if not found
// Note that we don't think we need compare on generationCounter, since
// we will have different UUIDs when the generation changes for the time being.
// Thus for the upgradeconversion we match without the generationCounter
// but log the difference.
func (pr parseResult) lookupVolume(volumeID uuid.UUID, generationCounter int64) *volumeInfo {
	for i := range pr.volumes {
		vi := &pr.volumes[i]
		if vi.volumeID == volumeID {
			if vi.generationCounter == generationCounter {
				log.Infof("lookupVolume found %s#%d",
					volumeID, generationCounter)
			} else {
				log.Infof("lookupVolume almost found %s#%d: gc %d",
					volumeID, generationCounter,
					vi.generationCounter)
			}
			return vi
		}
	}
	log.Errorf("lookupVolume NOT found %s#%d", volumeID, generationCounter)
	return nil
}

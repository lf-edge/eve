package volumemgr

import (
	"io/ioutil"
	"os"

	"github.com/lf-edge/eve/pkg/pillar/types"
	log "github.com/sirupsen/logrus"
)

// Publish PersistImageStatus for verified objects as types.VERIFIED
// Publish as PersistImageStatus for our internal use and
// to later signal to verifier by deleting an PersistImageStatus
func populatePersistImageStatus(ctx *volumemgrContext) {

	objTypes := []string{types.AppImgObj, types.BaseOsObj}
	for _, objType := range objTypes {
		verifiedDirname := types.DownloadDirname + "/" + objType + "/verified"
		if _, err := os.Stat(verifiedDirname); err == nil {
			populatePersistImageStatusDir(ctx, objType, verifiedDirname)
		}
	}
}

// Scanning for verified objects to create the PersistImageStatus
func populatePersistImageStatusDir(ctx *volumemgrContext, objType string, objDirname string) {

	log.Infof("populatePersistImageStatusDir(%s, %s)", objType, objDirname)
	locations, err := ioutil.ReadDir(objDirname)
	if err != nil {
		log.Fatal(err)
	}

	log.Debugf("populatePersistImageStatusDir: processing locations %v",
		locations)
	for _, location := range locations {
		pathname := objDirname + "/" + location.Name()
		filename := location.Name()
		sha256 := location.Name() // XXX ToLower?
		if location.IsDir() {
			// Directory name is the sha; file in directory is the filename
			locations, err := ioutil.ReadDir(pathname)
			if err != nil {
				log.Error(err)
				continue
			}
			// XXX Assume one file per directory; ignore if none
			if len(locations) == 0 {
				log.Warnf("Empty directory ignored: %s", pathname)
				continue
			}
			if len(locations) > 1 {
				log.Warnf("Large directory with %d files using first: %s",
					len(locations), pathname)
			}
			filename = locations[0].Name()
			pathname = pathname + "/" + filename
		}
		info, err := os.Stat(pathname)
		if err != nil {
			// XXX Delete file?
			log.Error(err)
			continue
		}
		size := info.Size()
		log.Infof("populatePersistImageStatusDir: Processing %s: %d Mbytes",
			pathname, size/(1024*1024))
		status := persistImageStatusFromVerifiedFile(objType, filename,
			sha256, size, pathname)
		if status != nil {
			publishPersistImageStatus(ctx, status)
		}
	}
}

func persistImageStatusFromVerifiedFile(objType, imageFileName, sha256 string,
	size int64, pathname string) *types.PersistImageStatus {

	status := types.PersistImageStatus{
		VerifyStatus: types.VerifyStatus{
			Name:         imageFileName,
			ObjType:      objType,
			FileLocation: pathname,
			ImageSha256:  sha256,
			Size:         size,
		},
		RefCount: 0,
	}
	return &status
}

func lookupPersistImageStatus(ctx *volumemgrContext, objType string,
	imageSha string) *types.PersistImageStatus {

	if imageSha == "" {
		return nil
	}
	pub := ctx.publication(types.PersistImageStatus{}, objType)
	s, _ := pub.Get(imageSha)
	if s == nil {
		log.Infof("lookupPersistImageStatus(%s) not found for %s", imageSha, objType)
		return nil
	}
	status := s.(types.PersistImageStatus)
	return &status
}

func publishPersistImageStatus(ctx *volumemgrContext,
	status *types.PersistImageStatus) {
	log.Debugf("publishPersistImageStatus(%s, %s)",
		status.ObjType, status.ImageSha256)

	pub := ctx.publication(types.PersistImageStatus{}, status.ObjType)
	key := status.Key()
	pub.Publish(key, *status)
}

func unpublishPersistImageStatus(ctx *volumemgrContext,
	status *types.PersistImageStatus) {

	log.Debugf("publishPersistImageStatus(%s, %s)",
		status.ObjType, status.ImageSha256)

	pub := ctx.publication(types.PersistImageStatus{}, status.ObjType)
	key := status.Key()
	st, _ := pub.Get(key)
	if st == nil {
		log.Errorf("unpublishPersistImageStatus(%s) not found", key)
		return
	}
	pub.Unpublish(key)
}

//AddOrRefCountPersistImageStatus increments refcount of a PersistImageStatus if already exists for the imageSha.
//Creates a PersistImageStatus with refcount = 1 if there is no PersistImageStatus found for the imageSha.
func AddOrRefCountPersistImageStatus(ctx *volumemgrContext, name, objType, fileLocation, imageSha string, size int64) {
	log.Infof("AddOrRefCountPersistImageStatus: for PersistImageStatus: %s", imageSha)

	persistImageStatus := lookupPersistImageStatus(ctx, objType, imageSha)
	if persistImageStatus != nil {
		persistImageStatus.RefCount++
		log.Infof("AddOrRefCountPersistImageStatus: RefCount to %d for %s",
			persistImageStatus.RefCount, imageSha)
	} else {
		log.Infof("AddOrRefCountPersistImageStatus: Adding new PersistImageStatus for: %s", imageSha)
		persistImageStatus = &types.PersistImageStatus{
			VerifyStatus: types.VerifyStatus{
				Name:         name,
				ObjType:      objType,
				FileLocation: fileLocation,
				ImageSha256:  imageSha,
				Size:         size,
			},
			RefCount: 1,
		}
	}
	publishPersistImageStatus(ctx, persistImageStatus)
	log.Infof("AddOrRefCountPersistImageStatus: done for PersistImageStatus: %s", imageSha)
}

// ReduceRefCountPersistImageStatus decreases the refcount and if it
// reaches zero then volumemgr will tell the verifier to delete the file
// by unpublishing.
func ReduceRefCountPersistImageStatus(ctx *volumemgrContext, objType, imageSha string) {

	log.Infof("ReduceRefCountPersistImageStatus(%s) for %s", imageSha, objType)

	persistImageStatus := lookupPersistImageStatus(ctx, objType, imageSha)
	if persistImageStatus == nil {
		log.Infof("ReduceRefCountPersistImageStatus: status missing for %s", imageSha)
		return
	}
	if persistImageStatus.RefCount == 0 {
		log.Errorf("ReduceRefCountPersistImageStatus: Attempting to reduce "+
			"0 RefCount. Status Details - Name: %s, ImageSha256:%s",
			persistImageStatus.Name, persistImageStatus.ImageSha256)
		return
	}
	persistImageStatus.RefCount--
	log.Infof("ReduceRefCountPersistImageStatus: RefCount to %d for %s",
		persistImageStatus.RefCount, imageSha)

	if persistImageStatus.RefCount == 0 {
		unpublishPersistImageStatus(ctx, persistImageStatus)
	} else {
		publishPersistImageStatus(ctx, persistImageStatus)
	}
}

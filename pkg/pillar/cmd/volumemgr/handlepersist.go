package volumemgr

import (
	"github.com/lf-edge/eve/pkg/pillar/types"
	log "github.com/sirupsen/logrus"
	"time"
)

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
			LastUse:  time.Now(),
			RefCount: 1,
		}
	}
	publishPersistImageStatus(ctx, persistImageStatus)
	log.Infof("AddOrRefCountPersistImageStatus: done for PersistImageStatus: %s", imageSha)
}

// ReduceRefCountPersistImageStatus decreases the refcount and if it
// reaches zero the volumeMgr might start a GC and will inform verifier to delete the verified file.
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
		// GC timer will clean up by marking status Expired
		// and some point in time.
		// Then verifier will delete status.
		persistImageStatus.LastUse = time.Now()
		return
	}
	persistImageStatus.RefCount--
	log.Infof("ReduceRefCountPersistImageStatus: RefCount to %d for %s",
		persistImageStatus.RefCount, imageSha)

	if persistImageStatus.RefCount == 0 {
		// GC timer will clean up by marking status Expired
		// and some point in time.
		// Then verifier will delete status.
		persistImageStatus.LastUse = time.Now()
	}
	publishPersistImageStatus(ctx, persistImageStatus)
}

func handlePersistImageStatusCreate(ctxArg interface{}, key string,
	statusArg interface{}) {
	status := statusArg.(types.PersistImageStatus)
	ctx := ctxArg.(*volumemgrContext)
	log.Infof("handlePersistImageStatusCreate for %s refcount %d expired %t",
		key, status.RefCount, status.Expired)
	publishPersistImageStatus(ctx, &status)
}

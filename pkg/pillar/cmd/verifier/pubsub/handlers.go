// Copyright (c) 2019-2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package pubsub

import (
	"encoding/hex"
	"flag"
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/lf-edge/eve/pkg/pillar/agentlog"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
	fileutils "github.com/lf-edge/eve/pkg/pillar/utils/file"
	uuid "github.com/satori/go.uuid"
)

// Notify simple struct to pass notification messages
type Notify struct{}

// Wrappers around handleCreate, handleModify, and handleDelete

// Determine whether it is an create or modify
func (v *VerifierContext) modify(_ interface{},
	key string, configArg interface{}, _ interface{}) {

	typeName := pubsub.TypeToName(configArg)
	handlerKey := fmt.Sprintf("%s+%s", typeName, key)
	v.log.Functionf("verifyHandler.modify(%s)", handlerKey)
	h, ok := v.handlers[handlerKey]
	if !ok {
		v.log.Fatalf("verifyHandler.modify called on config that does not exist")
	}
	select {
	case h <- Notify{}:
		v.log.Functionf("verifyHandler.modify(%s) sent notify", handlerKey)
	default:
		// handler is slow
		v.log.Warnf("verifyHandler.modify(%s) NOT sent notify. Slow handler?", handlerKey)
	}
	v.log.Functionf("verifyHandler.modify(%s) done", handlerKey)
}

func (v *VerifierContext) create(ctxArg interface{},
	key string, configArg interface{}) {

	typeName := pubsub.TypeToName(configArg)
	handlerKey := fmt.Sprintf("%s+%s", typeName, key)
	v.log.Functionf("verifyHandler.create(%s)", handlerKey)
	ctx, ok := ctxArg.(*VerifierContext)
	if !ok {
		v.log.Fatalf("verifyHandler.create: ctxArg is not a VerifierContext")
	}
	if _, ok := v.handlers[handlerKey]; ok {
		v.log.Fatalf("verifyHandler.create called on config that already exists")
	}
	h1 := make(chan Notify, 1)
	v.handlers[handlerKey] = h1
	switch typeName {
	case "VerifyImageConfig":
		v.log.Functionf("Creating %s at %s", "processSingleImage",
			agentlog.GetMyStack())
		// when it receives a VerifyImageConfig, start a goroutine to handle it, passing it a
		// channel for notifications. processSingleImage will check if it is a new one or an existing one.
		go processSingleImage(ctx, key, h1)
	default:
		v.log.Fatalf("Unknown type %s", typeName)
	}
	h := h1
	select {
	case h <- Notify{}:
		v.log.Functionf("verifyHandler.create(%s) sent notify", handlerKey)
	default:
		// Shouldn't happen since we just created channel
		v.log.Fatalf("verifyHandler.create(%s) NOT sent notify", handlerKey)
	}
	v.log.Functionf("verifyHandler.create(%s) done", handlerKey)
}

func (v *VerifierContext) delete(_ interface{}, key string,
	configArg interface{}) {

	typeName := pubsub.TypeToName(configArg)
	handlerKey := fmt.Sprintf("%s+%s", typeName, key)
	v.log.Functionf("verifyHandler.delete(%s)", handlerKey)
	// Do we have a channel/goroutine?
	h, ok := v.handlers[handlerKey]
	if ok {
		v.log.Tracef("Closing channel")
		close(h)
		delete(v.handlers, handlerKey)
	} else {
		v.log.Tracef("verifyHandler.delete: unknown %s", handlerKey)
		return
	}
	v.log.Functionf("verifyHandler.delete(%s) done", handlerKey)
}

func handleCreate(ctx *VerifierContext,
	config *types.VerifyImageConfig) {

	ctx.log.Functionf("handleCreate(%s) for %s", config.ImageSha256, config.Name)

	status := types.VerifyImageStatus{
		Name:        config.Name,
		ImageSha256: config.ImageSha256,
		MediaType:   config.MediaType,
		PendingAdd:  true,
		State:       types.VERIFYING,
		RefCount:    config.RefCount,
	}
	publishVerifyImageStatus(ctx, &status)

	if config.FileLocation == "" {
		err := fmt.Errorf("handleCreate: verifyImageConfig: %s has empty fileLocation", config.ImageSha256)
		ctx.log.Error(err.Error())
		cerr := fmt.Sprintf("%v", err)
		updateVerifyErrStatus(ctx, &status, cerr)
		return
	}

	// We generate a temporary UUID to avoid conflicts
	// where multiple different objects can have a different claimed sha256
	// Of course, only one of those will pass the verification.
	tmpID, err := uuid.NewV4()
	if err != nil {
		ctx.log.Errorf("NewV4 failed: %v", err)
		return
	}
	size, verifyingLocation, err := v.MarkObjectAsVerifying(config.FileLocation, config.ImageSha256, config.MediaType, tmpID)
	if err != nil {
		cerr := fmt.Sprintf("%v", err)
		updateVerifyErrStatus(ctx, &status, cerr)
		ctx.log.Errorf("handleCreate: markObjectAsVerifying failed for %s", config.Name)
		return
	}
	status.FileLocation = verifyingLocation
	status.Size = size
	publishVerifyImageStatus(ctx, &status)

	if err := v.VerifyObjectSha(status.FileLocation, config.Name, config.ImageSha256); err != nil {
		cerr := fmt.Sprintf("%v", err)
		updateVerifyErrStatus(ctx, &status, cerr)
		ctx.log.Errorf("verifyObjectSha %s failed %s", config.Name, cerr)
		return
	}
	publishVerifyImageStatus(ctx, &status)

	verifiedFilename, err := v.MarkObjectAsVerified(config.FileLocation, config.ImageSha256, config.MediaType, tmpID)
	if err != nil {
		ctx.log.Fatal(err)
	}
	status.FileLocation = verifiedFilename
	if status.FileLocation == "" {
		ctx.log.Fatalf("handleCreate: Verified but no FileLocation for %s", status.Key())
	}

	status.PendingAdd = false
	status.State = types.VERIFIED
	publishVerifyImageStatus(ctx, &status)
	ctx.log.Functionf("handleCreate done for %s", config.Name)
}

// This merely updates the RefCount and Expired in the status
// Note that verifier will retain the file even if RefCount in VerifyImageConfig
// is set to zero.
func handleModify(ctx *VerifierContext, config *types.VerifyImageConfig,
	status *types.VerifyImageStatus) {

	// Note no comparison on version
	changed := false

	ctx.log.Functionf("handleModify(%s) for %s, config.RefCount: %d, "+
		"status.RefCount: %d",
		status.ImageSha256, config.Name, config.RefCount,
		status.RefCount)

	// Always update RefCount and Expired
	if status.RefCount != config.RefCount {
		ctx.log.Functionf("handleModify RefCount change %s from %d to %d",
			config.Name, status.RefCount, config.RefCount)
		status.RefCount = config.RefCount
		changed = true
	}
	if status.Expired != config.Expired {
		ctx.log.Functionf("handleModify Expired change %s from %t to %t",
			config.Name, status.Expired, config.Expired)
		status.Expired = config.Expired
		changed = true
	}

	if changed {
		publishVerifyImageStatus(ctx, status)
	}
	ctx.log.Functionf("handleModify done for %s. Status.RefCount=%d, Config.RefCount:%d",
		config.Name, status.RefCount, config.RefCount)
}

// handleDelete means volumemgr wants us to delete the file.
// Note that verifier will retain the file even if RefCount in VerifyImageConfig
// is set to zero.
func handleDelete(ctx *VerifierContext, status *types.VerifyImageStatus) {

	ctx.log.Functionf("handleDelete(%s) refcount %d",
		status.ImageSha256, status.RefCount)

	if _, err := os.Stat(status.FileLocation); err == nil {
		ctx.log.Functionf("handleDelete removing %s",
			status.FileLocation)
		if err := os.RemoveAll(status.FileLocation); err != nil {
			ctx.log.Fatal(err)
		}
	} else {
		ctx.log.Warnf("handleDelete: Unable to delete %s:  %s",
			status.FileLocation, err)
	}

	unpublishVerifyImageStatus(ctx, status)
	ctx.log.Functionf("handleDelete done for %s", status.ImageSha256)
}

func (v *VerifierContext) handleGlobalConfigCreate(ctxArg interface{}, key string,
	statusArg interface{}) {
	v.handleGlobalConfigImpl(ctxArg, key, statusArg)
}

func (v *VerifierContext) handleGlobalConfigModify(ctxArg interface{}, key string,
	statusArg interface{}, _ interface{}) {
	v.handleGlobalConfigImpl(ctxArg, key, statusArg)
}

func (v *VerifierContext) handleGlobalConfigImpl(ctxArg interface{}, key string,
	_ interface{}) {

	ctx, ok := ctxArg.(*VerifierContext)
	if !ok {
		ctx.log.Fatalf("handleGlobalConfigImpl: ctxArg is not a VerifierContext")
	}
	if key != "global" {
		ctx.log.Functionf("handleGlobalConfigImpl: ignoring %s", key)
		return
	}
	ctx.log.Functionf("handleGlobalConfigImpl for %s", key)
	gcp := agentlog.HandleGlobalConfig(ctx.log, ctx.subGlobalConfig, agentName,
		ctx.CLIParams().DebugOverride, ctx.logger)
	if gcp != nil {
		ctx.GCInitialized = true
	}
	ctx.log.Functionf("handleGlobalConfigImpl done for %s", key)
}

func (v *VerifierContext) handleGlobalConfigDelete(ctxArg interface{}, key string,
	_ interface{}) {

	ctx, ok := ctxArg.(*VerifierContext)
	if !ok {
		ctx.log.Fatalf("handleGlobalConfigDelete: ctxArg is not a VerifierContext")
	}
	if key != "global" {
		ctx.log.Functionf("handleGlobalConfigDelete: ignoring %s", key)
		return
	}
	ctx.log.Functionf("handleGlobalConfigDelete for %s", key)
	agentlog.HandleGlobalConfig(ctx.log, ctx.subGlobalConfig, agentName,
		ctx.CLIParams().DebugOverride, ctx.logger)
	ctx.log.Functionf("handleGlobalConfigDelete done for %s", key)
}

// Recreate VerifyImageStatus for verified files as types.VERIFIED
func handleInitVerifiedObjects(ctx *VerifierContext) {

	verifiedDirname := v.GetVerifiedDir()
	if _, err := os.Stat(verifiedDirname); err == nil {
		populateInitialStatusFromVerified(ctx, verifiedDirname, "")
	}
}

// Server for each VerifyImageConfig
func processSingleImage(ctx *VerifierContext, key string, c <-chan Notify) {

	ctx.log.Functionf("processSingleImage starting")

	closed := false
	for !closed {
		_, ok := <-c
		if ok {
			sub := ctx.subVerifyImageConfig
			c, err := sub.Get(key)
			if err != nil {
				ctx.log.Errorf("processSingleImage no config for %s", key)
				continue
			}
			config, ok := c.(types.VerifyImageConfig)
			if !ok {
				ctx.log.Errorf("processSingleImage not a VerifyImageConfig for %s", key)
				continue
			}
			status := lookupVerifyImageStatus(ctx, key)
			if status == nil {
				handleCreate(ctx, &config)
			} else {
				handleModify(ctx, &config, status)
			}
		} else {
			// Closed
			status := lookupVerifyImageStatus(ctx, key)
			if status != nil {
				handleDelete(ctx, status)
			}
			closed = true
		}
	}
	ctx.log.Functionf("processSingleImage(%s) DONE", key)
}

// AddAgentSpecificCLIFlags adds CLI options
func (v *VerifierContext) AddAgentSpecificCLIFlags(flagSet *flag.FlagSet) {
	v.versionPtr = flagSet.Bool("v", false, "Version")
}

func updateVerifyErrStatus(ctx *VerifierContext,
	status *types.VerifyImageStatus, lastErr string) {

	status.SetErrorNow(lastErr)
	status.PendingAdd = false
	publishVerifyImageStatus(ctx, status)
}

func publishVerifyImageStatus(ctx *VerifierContext,
	status *types.VerifyImageStatus) {

	ctx.log.Tracef("publishVerifyImageStatus(%s)", status.ImageSha256)

	pub := ctx.pubVerifyImageStatus
	key := status.Key()
	_ = pub.Publish(key, *status)
}

func unpublishVerifyImageStatus(ctx *VerifierContext,
	status *types.VerifyImageStatus) {

	ctx.log.Tracef("publishVerifyImageStatus(%s)", status.ImageSha256)

	pub := ctx.pubVerifyImageStatus
	key := status.Key()
	st, _ := pub.Get(key)
	if st == nil {
		ctx.log.Errorf("unpublishVerifyImageStatus(%s) not found", key)
		return
	}
	_ = pub.Unpublish(key)
}

// Callers must be careful to publish any changes to VerifyImageStatus
func lookupVerifyImageStatus(ctx *VerifierContext,
	key string) *types.VerifyImageStatus {

	pub := ctx.pubVerifyImageStatus
	st, _ := pub.Get(key)
	if st == nil {
		ctx.log.Functionf("lookupVerifyImageStatus(%s) not found", key)
		return nil
	}
	status, ok := st.(types.VerifyImageStatus)
	if !ok {
		ctx.log.Errorf("lookupVerifyImageStatus(%s) not a VerifyImageStatus", key)
		return nil
	}
	return &status
}

// Recursive scanning for verified objects,
// to recreate the VerifyImageStatus.
func populateInitialStatusFromVerified(ctx *VerifierContext,
	objDirname string, parentDirname string) {

	ctx.log.Functionf("populateInitialStatusFromVerified(%s, %s)", objDirname,
		parentDirname)

	locations, err := os.ReadDir(objDirname)

	if err != nil {
		ctx.log.Fatal(err)
	}

	ctx.log.Tracef("populateInitialStatusFromVerified: processing locations %v", locations)

	for _, location := range locations {

		pathname := objDirname + "/" + location.Name()

		if location.IsDir() {
			ctx.log.Tracef("populateInitialStatusFromVerified: Recursively looking in %s",
				pathname)
			if _, err := os.Stat(pathname); err == nil {
				populateInitialStatusFromVerified(ctx,
					pathname, location.Name())
			}
		} else {
			size := int64(0)
			info, err := os.Stat(pathname)
			if err != nil {
				// XXX Delete file?
				ctx.log.Error(err)
			} else {
				size = info.Size()
			}
			ctx.log.Tracef("populateInitialStatusFromVerified: Processing %s: %d Mbytes",
				pathname, size/(1024*1024))
			status := verifyImageStatusFromVerifiedImageFile(
				location.Name(), size, pathname, ctx.log)
			if status == nil {
				ctx.log.Warnf("populateInitialStatusFromVerified: cannot create status for %s", location.Name())
				// If the file exists, but we cannot create a status from it, consider it as corrupted and remove it
				_, err := os.Stat(pathname)
				if err != nil {
					// file does not exist, nothing to do
					continue
				}
				ctx.log.Tracef("populateInitialStatusFromVerified: removing corrupted file %s", pathname)
				err = os.Remove(pathname)
				if err != nil {
					ctx.log.Errorf("populateInitialStatusFromVerified: cannot remove broken file: %v", err)
				}
			} else {
				imageHash, err := fileutils.ComputeShaFile(pathname)
				if err != nil {
					ctx.log.Errorf("populateInitialStatusFromVerified: cannot compute sha: %v", err)
					err = os.Remove(pathname)
					if err != nil {
						ctx.log.Errorf("populateInitialStatusFromVerified: cannot remove broken file: %v", err)
					}
					continue
				}
				formattedHash := hex.EncodeToString(imageHash)
				if formattedHash != status.ImageSha256 {
					ctx.log.Errorf("populateInitialStatusFromVerified: calculated sha %s is not the same as provided %s",
						formattedHash, status.ImageSha256)
					err = os.Remove(pathname)
					if err != nil {
						ctx.log.Errorf("populateInitialStatusFromVerified: cannot remove broken file: %v", err)
					}
					continue
				}
				publishVerifyImageStatus(ctx, status)
			}
		}
	}
}

// verifyImageStatusFromVerifiedImageFile given a verified image file,
// return a VerifyImageStatus. Note that this is for a verified file, not a
// verifying file.
func verifyImageStatusFromVerifiedImageFile(imageFileName string,
	size int64, pathname string, log *base.LogObject) *types.VerifyImageStatus {

	// filename might have two parts, separated by '.': digest and PathEscape(mediaType)
	var (
		mediaType string
		digest    string
	)
	parts := strings.SplitN(imageFileName, ".", 2)
	digest = parts[0]
	if len(parts) == 2 {
		// just ignore the error and treat mediaType as empty
		mediaType, _ = url.PathUnescape(parts[1])
		log.Tracef("verifyImageStatusFromVerifiedImageFile: mediaType %s recovered from %s", mediaType, imageFileName)
	} else {
		// if there is no mediaType, we force the redownload process by returning nil
		log.Warnf("verifyImageStatusFromVerifiedImageFile: no mediaType in %s", imageFileName)
		return nil
	}
	status := types.VerifyImageStatus{
		Name:         imageFileName,
		FileLocation: pathname,
		ImageSha256:  digest,
		MediaType:    mediaType,
		Size:         size,
		State:        types.VERIFIED,
		RefCount:     0,
	}
	return &status
}

// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"

	"github.com/lf-edge/eve/evetest/broker/provider"
	api "github.com/lf-edge/eve/evetest/grpcapi/go"
	"github.com/lf-edge/eve/evetest/utils"
	"github.com/lf-edge/eve/pkg/pillar/utils/generics"
)

// localImageRequest is the locally built image a BuildImageRequest asks for --
// a live image, or an installer image -- reduced to what the template path
// needs, which is the same for both.
type localImageRequest struct {
	// sha256 is the content hash of the image the template is installed from.
	sha256 string
	// installer is set for an installer image: the template is keyed as an
	// installer, and the device boots it once, as its first disk, to install
	// EVE onto a blank target disk.
	installer bool
	// media is the installer's medium; INSTALLER_MEDIA_UNSPECIFIED for a live
	// image.
	media api.InstallerMedia
	// source is where the client's files are, if it said. A raw installer
	// arrives as the same three kinds of file as a live image -- a qcow2 disk,
	// config.img and the firmware -- so it takes the live source's shape, and
	// one reader serves both.
	source *api.LocalLiveImageSource
}

// templateKeyParams is the cache key of the template this request installs.
func (r *localImageRequest) templateKeyParams(
	arch api.ArchType, diskSize uint64) templateKeyParams {
	return localTemplateKeyParams(r.sha256, arch, diskSize, r.installer)
}

// supportedLocalInstallerMedia lists the installer media this broker builds a
// device from, given its provider's disk image strategy. It is what the broker
// advertises (one CAPABILITY_LOCAL_INSTALLER_* per medium) and what
// parseLocalImageRequest accepts, so the two cannot disagree.
//
// A local image needs a provider that consumes a template rather than building
// every device from the EVE container, exactly as a local live image does.
// Only the raw medium is implemented; an ISO needs a provider CD-ROM and a
// config.img written into the ISO, and a netboot bundle needs its own
// template, so neither is advertised yet.
func supportedLocalInstallerMedia(strategy provider.DiskImageStrategy) []api.InstallerMedia {
	if strategy == provider.DiskImageLegacyBuild {
		return nil
	}
	return []api.InstallerMedia{api.InstallerMedia_INSTALLER_MEDIA_RAW}
}

// installerDiskMedia is how a provider presents an installer on the given
// medium: an ISO is a CD-ROM, anything else a plain disk (including an
// installer built from the EVE container, whose medium is unspecified).
func installerDiskMedia(media api.InstallerMedia) provider.DiskImageMedia {
	if media == api.InstallerMedia_INSTALLER_MEDIA_ISO {
		return provider.DiskImageMediaCdrom
	}
	return provider.DiskImageMediaDisk
}

// checkInstallerMedia validates a request's installer_media against the flags
// that say how its device installs EVE, so that the medium a broker builds is
// never a different one from the medium the client named. Unspecified keeps
// the meaning those flags have always had.
func checkInstallerMedia(req *api.BuildImageRequest) error {
	media := req.GetInstallerMedia()
	switch media {
	case api.InstallerMedia_INSTALLER_MEDIA_UNSPECIFIED:
		return nil
	case api.InstallerMedia_INSTALLER_MEDIA_RAW, api.InstallerMedia_INSTALLER_MEDIA_ISO:
		if !req.MakeInstaller || req.NetworkBoot {
			return fmt.Errorf("device %q: a %s installer needs make_installer and "+
				"no network_boot", req.DeviceName, utils.InstallerMediaName(media))
		}
	case api.InstallerMedia_INSTALLER_MEDIA_NET:
		if !req.NetworkBoot || req.MakeInstaller {
			return fmt.Errorf("device %q: a NET installer needs network_boot and "+
				"no make_installer", req.DeviceName)
		}
	default:
		return fmt.Errorf("device %q: unknown installer medium %v", req.DeviceName, media)
	}
	if media == api.InstallerMedia_INSTALLER_MEDIA_ISO &&
		req.GetLiveImage() == nil && req.GetLocalInstallerImage() == nil {
		return fmt.Errorf("device %q: an installer ISO cannot be built from the "+
			"EVE container image yet", req.DeviceName)
	}
	return nil
}

// parseLocalImageRequest validates the local image a BuildImageRequest asks
// for. It returns (nil, nil) for a request built from the EVE container image.
//
// Every refusal here is final, never a fallback to the container image: the
// client asked for the bits of its own build, and building the device from
// anything else would test a different EVE than the one it is reporting on.
func parseLocalImageRequest(req *api.BuildImageRequest,
	strategy provider.DiskImageStrategy, prov provider.DeviceProvider) (
	*localImageRequest, error) {

	if err := checkInstallerMedia(req); err != nil {
		return nil, err
	}
	live := req.GetLiveImage()
	installer := req.GetLocalInstallerImage()
	if live != nil && installer != nil {
		return nil, fmt.Errorf(
			"device %q requests both a local live image and a local installer image; "+
				"a device boots one or the other", req.DeviceName)
	}
	if installer == nil && req.GetLocalInstallerSource() != nil {
		return nil, fmt.Errorf(
			"device %q sends a local installer source without a local installer image",
			req.DeviceName)
	}

	if live != nil {
		if req.MakeInstaller {
			// Only a harness that predates local installer images sends this: it
			// had no other way to say "installer" with the live transport on.
			return nil, fmt.Errorf(
				"device %q requests an installer image, which a local live image "+
					"cannot provide; update the evetest harness so it sends the local "+
					"installer image instead, or unset EVETEST_EVE_LIVE_IMAGE to use "+
					"the container path", req.DeviceName)
		}
		if strategy == provider.DiskImageLegacyBuild {
			return nil, fmt.Errorf(
				"device %q requests a local live image, but the %T provider still uses "+
					"the per-device container build path and cannot consume one; unset "+
					"EVETEST_EVE_LIVE_IMAGE to build from the EVE container image",
				req.DeviceName, prov)
		}
		if err := validLiveImageSHA256(live.GetSha256()); err != nil {
			return nil, err
		}
		return &localImageRequest{
			sha256: live.GetSha256(),
			source: req.GetLiveImageSource(),
		}, nil
	}

	if installer == nil {
		return nil, nil
	}
	media := req.GetInstallerMedia()
	if media == api.InstallerMedia_INSTALLER_MEDIA_UNSPECIFIED {
		return nil, fmt.Errorf(
			"device %q sends a local installer image without installer_media",
			req.DeviceName)
	}
	if !generics.ContainsItem(supportedLocalInstallerMedia(strategy), media) {
		reason := "it is not implemented yet"
		if strategy == provider.DiskImageLegacyBuild {
			reason = fmt.Sprintf("the %T provider still uses the per-device "+
				"container build path and cannot consume one", prov)
		}
		err := fmt.Errorf("device %q: broker does not support local %s installer "+
			"images (%s)", req.DeviceName, utils.InstallerMediaName(media), reason)
		if media == api.InstallerMedia_INSTALLER_MEDIA_ISO {
			// The container path cannot build an ISO either, so there is no
			// alternative to suggest.
			return nil, err
		}
		return nil, fmt.Errorf("%w; unset EVETEST_EVE_LIVE_IMAGE to build from "+
			"the EVE container image", err)
	}
	if err := validLiveImageSHA256(installer.GetSha256()); err != nil {
		return nil, err
	}

	parsed := &localImageRequest{
		sha256:    installer.GetSha256(),
		installer: true,
		media:     media,
	}
	src := req.GetLocalInstallerSource()
	if src == nil {
		return parsed, nil
	}
	// A negative size cannot describe any file, so the source is unusable --
	// which is benign: the broker then asks for the upload, as for any source
	// it cannot read.
	if src.GetImageBytes() >= 0 {
		parsed.source = &api.LocalLiveImageSource{
			DiskPath:      src.GetImagePath(),
			DiskBytes:     uint64(src.GetImageBytes()),
			ConfigImgPath: src.GetConfigImgPath(),
			FirmwareDir:   src.GetFirmwareDir(),
		}
	}
	return parsed, nil
}

// applyTo points a makeDeviceImage call at this request's local image: the
// image to install the template from, and whether it is an installer. The
// template key makeDeviceImage derives from these (deviceTemplateKeyParams) is
// therefore built from the same parsed request as BuildImage's miss check
// (templateKeyParams), never from the raw request flags.
func (r *localImageRequest) applyTo(params *makeDeviceImageParams, imageDir string) {
	params.liveImageSHA256 = r.sha256
	params.liveTarPath = liveUploadPath(imageDir, r.sha256)
	params.installer = r.installer
	params.installerMedia = r.media
}

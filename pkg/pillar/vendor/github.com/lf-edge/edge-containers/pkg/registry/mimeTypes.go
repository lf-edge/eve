package registry

import (
	"github.com/containerd/containerd/images"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

const (
	MimeTypeECIArtifact         = "application/vnd.lfedge.eci.v1+json"
	MimeTypeECIConfig           = "application/vnd.lfedge.eci.config.v1+json"
	MimeTypeECIKernel           = "application/vnd.lfedge.eci.kernel.layer.v1+kernel"
	MimeTypeECIInitrd           = "application/vnd.lfedge.eci.initrd.layer.v1+cpio"
	MimeTypeECIDiskRaw          = "application/vnd.lfedge.disk.layer.v1+raw"
	MimeTypeECIDiskVhd          = "application/vnd.lfedge.disk.layer.v1+vhd"
	MimeTypeECIDiskVmdk         = "application/vnd.lfedge.disk.layer.v1+vmdk"
	MimeTypeECIDiskISO          = "application/vnd.lfedge.disk.layer.v1+iso"
	MimeTypeECIDiskQcow         = "application/vnd.lfedge.disk.layer.v1+qcow"
	MimeTypeECIDiskQcow2        = "application/vnd.lfedge.disk.layer.v1+qcow2"
	MimeTypeECIDiskOva          = "application/vnd.lfedge.disk.layer.v1+ova"
	MimeTypeECIDiskVhdx         = "application/vnd.lfedge.disk.layer.v1+vhdx"
	MimeTypeECIOther            = "application/vnd.lfedge.eci.layer.v1"
	MimeTypeOCIImageConfig      = ocispec.MediaTypeImageConfig
	MimeTypeOCIImageLayer       = ocispec.MediaTypeImageLayer
	MimeTypeOCIImageLayerGzip   = ocispec.MediaTypeImageLayerGzip
	MimeTypeOCIImageManifest    = ocispec.MediaTypeImageManifest
	MimeTypeOCIImageIndex       = ocispec.MediaTypeImageIndex
	MimeTypeDockerImageConfig   = images.MediaTypeDockerSchema2Config
	MimeTypeDockerImageManifest = images.MediaTypeDockerSchema2Manifest
	MimeTypeDockerImageIndex    = images.MediaTypeDockerSchema2ManifestList
	MimeTypeDockerLayerTarGzip  = images.MediaTypeDockerSchema2LayerGzip
	MimeTypeDockerLayerTar      = images.MediaTypeDockerSchema2Layer
)

var allTypes = []string{
	MimeTypeECIArtifact,
	MimeTypeECIConfig,
	MimeTypeECIKernel,
	MimeTypeECIInitrd,
	MimeTypeECIDiskRaw,
	MimeTypeECIDiskVhd,
	MimeTypeECIDiskVmdk,
	MimeTypeECIDiskISO,
	MimeTypeECIDiskQcow,
	MimeTypeECIDiskQcow2,
	MimeTypeECIDiskOva,
	MimeTypeECIDiskVhdx,
	MimeTypeECIOther,
	MimeTypeOCIImageConfig,
	MimeTypeOCIImageLayer,
	MimeTypeOCIImageLayerGzip,
	MimeTypeOCIImageManifest,
	MimeTypeOCIImageIndex,
	MimeTypeDockerImageConfig,
	MimeTypeDockerImageManifest,
	MimeTypeDockerImageIndex,
	MimeTypeDockerLayerTarGzip,
	MimeTypeDockerLayerTar,
}

func AllMimeTypes() []string {
	return allTypes[:]
}

func GetLayerMediaType(actualType string, format Format) string {
	var t string
	switch format {
	case FormatArtifacts:
		t = actualType
	case FormatLegacy:
		t = MimeTypeOCIImageLayerGzip
	}
	return t
}
func GetConfigMediaType(actualType string, format Format) string {
	if format == FormatArtifacts {
		return actualType
	}
	return MimeTypeOCIImageConfig
}
func GetArtifactMediaType(actualType string, format Format) string {
	if format == FormatArtifacts {
		return actualType
	}
	return MimeTypeOCIImageManifest
}

func IsConfigType(mediaType string) bool {
	switch mediaType {
	case MimeTypeECIConfig, MimeTypeOCIImageConfig, MimeTypeDockerImageConfig:
		return true
	}
	return false
}

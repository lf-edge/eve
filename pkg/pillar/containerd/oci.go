// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0
//
// This is basically re-implementation of:
//    https://github.com/opencontainers/runtime-tools/blob/master/generate/generate.go
// The reason we're not using it verbatim is that we only need a tiny
// subset of its functionality AND we are paranoid about being compatible
// with containerd defaults. Should containerd itself migrate to using
// OCI runtime-tools library -- we'd gladly switch

package containerd

import (
	"encoding/json"
	"fmt"
	"github.com/containerd/containerd"
	"github.com/containerd/containerd/containers"
	"github.com/containerd/containerd/oci"
	zconfig "github.com/lf-edge/eve/api/go/config"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/opencontainers/runtime-spec/specs-go"
	"os"
	"path"
)

const eveScript = "/bin/eve"

var vethScript = []string{"eve", "exec", "pillar", "/opt/zededa/bin/veth.sh"}

// ociSpec is kept private (with all the actions done by getters and setters
// This is because we expect the implementation to still evolve quite a bit
// for all the different task usecases
type ociSpec struct {
	specs.Spec
	name         string
	exposedPorts map[string]struct{}
	volumes      map[string]struct{}
	labels       map[string]string
	stopSignal   string
}

// OCISpec provides methods to manipulate OCI runtime specifications and create containers based on them
type OCISpec interface {
	Get() *specs.Spec
	Save(*os.File) error
	Load(*os.File) error
	CreateContainer(bool) error
	AdjustMemLimit(types.DomainConfig, int64)
	UpdateVifList(types.DomainConfig)
	UpdateFromDomain(types.DomainConfig)
	UpdateFromVolume(string) error
	UpdateMounts([]types.DiskStatus)
	UpdateMountsNested([]types.DiskStatus)
	UpdateEnvVar(map[string]string)
}

// NewOciSpec returns a default oci spec from the containerd point of view
func NewOciSpec(name string) (OCISpec, error) {
	s := &ociSpec{name: name}
	// we need a dummy container object to trick containerd
	// initialization functions into filling out defaults
	dummy := containers.Container{ID: s.name}

	if err := oci.WithDefaultSpec()(ctrdCtx, CtrdClient, &dummy, &s.Spec); err != nil {
		return nil, err
	}
	if s.Process == nil {
		s.Process = &specs.Process{}
	}
	s.Root.Path = "/"
	return s, nil
}

// Get simply returns an underlying OCI runtime spec
func (s *ociSpec) Get() *specs.Spec {
	return &s.Spec
}

// Save stores json representation of the oci spec in a file
func (s *ociSpec) Save(file *os.File) error {
	b, err := json.MarshalIndent(s.Spec, "", "    ")
	if err != nil {
		return fmt.Errorf("failed to serialize JSON spec %v", err)
	}

	if r, err := file.Write(b); err != nil || r != len(b) {
		return fmt.Errorf("failed to write %d bytes to file %s (%v)", len(b), file.Name(), err)
	}
	return nil
}

// Load loads json representation of the oci spec from file
func (s *ociSpec) Load(file *os.File) error {
	var ns *specs.Spec
	if err := json.NewDecoder(file).Decode(&ns); err != nil {
		return err
	}
	s.Spec = *ns
	return nil
}

// CreateContainer starts an OCI container based on the spec
func (s *ociSpec) CreateContainer(removeExisting bool) error {
	_, err := CtrdClient.NewContainer(ctrdCtx, s.name, containerd.WithSpec(&s.Spec))
	// if container exists, is stopped and we are asked to remove existing - try that
	if err != nil && removeExisting {
		_ = CtrDeleteContainer(s.name)
		_, err = CtrdClient.NewContainer(ctrdCtx, s.name, containerd.WithSpec(&s.Spec))
	}
	return err
}

// AdjustMemLimit adds Memory Resources of the spec with given number
func (s *ociSpec) AdjustMemLimit(dom types.DomainConfig, addMemory int64) {
	// update cgroup resource constraints for CPU and memory
	if s.Linux != nil {
		m := int64(dom.Memory*1024) + addMemory
		s.Linux.Resources.Memory.Limit = &m
	}
}

// UpdateVifList creates VIF management hooks in OCI spec
func (s *ociSpec) UpdateVifList(dom types.DomainConfig) {
	// use pre-start and post-stop hooks for networking
	if s.Hooks == nil {
		s.Hooks = &specs.Hooks{}
	}
	timeout := 60
	for _, v := range dom.VifList {
		vifSpec := []string{"VIF_NAME=" + v.Vif, "VIF_BRIDGE=" + v.Bridge, "VIF_MAC=" + v.Mac}
		s.Hooks.Prestart = append(s.Hooks.Prestart, specs.Hook{
			Env:     vifSpec,
			Path:    eveScript,
			Args:    append(vethScript, "up", v.Vif, v.Bridge, v.Mac),
			Timeout: &timeout,
		})
		s.Hooks.Poststop = append(s.Hooks.Poststop, specs.Hook{
			Env:     vifSpec,
			Path:    eveScript,
			Args:    append(vethScript, "down", v.Vif),
			Timeout: &timeout,
		})
	}
}

// UpdateFromDomain updates values in the OCI spec based on EVE DomainConfig settings
func (s *ociSpec) UpdateFromDomain(dom types.DomainConfig) {
	// update cgroup resource constraints for CPU and memory
	if s.Linux != nil {
		if s.Linux.Resources == nil {
			s.Linux.Resources = &specs.LinuxResources{}
		}
		if s.Linux.Resources.Memory == nil {
			s.Linux.Resources.Memory = &specs.LinuxMemory{}
		}
		if s.Linux.Resources.CPU == nil {
			s.Linux.Resources.CPU = &specs.LinuxCPU{}
		}

		m := int64(dom.Memory * 1024)
		p := uint64(100000)
		q := int64(100000 * dom.VCpus)
		s.Linux.Resources.Memory.Limit = &m
		s.Linux.Resources.CPU.Period = &p
		s.Linux.Resources.CPU.Quota = &q
	}
}

// UpdateFromVolume updates values in the OCI spec based on the location
// of an EVE volume. EVE volume's are expected to be structured as directories
// in the filesystem with a json file containing the corresponding Image
// manifest and a rootfs subfolder with a full rootfs filesystem
func (s *ociSpec) UpdateFromVolume(volume string) error {
	imgInfo, err := getSavedImageInfo(volume)
	if err != nil {
		return fmt.Errorf("couldn't load saved image config from %s", volume)
	}

	if err = s.updateFromImageConfig(imgInfo.Config); err == nil {
		s.Root.Path = volume + "/rootfs"
	}

	return err
}

// UpdateFromImageConfig updates values in the OCI spec based
// on the values provided in the Image Config section as per:
//    https://github.com/opencontainers/image-spec/blob/master/config.md
func (s *ociSpec) updateFromImageConfig(config v1.ImageConfig) error {
	// the following gets into our extensions of the Spec, these
	// values will be missing if we serialize the spec into JSON and
	// read it back: these don't map to OCI runtime spec
	s.exposedPorts = config.ExposedPorts
	s.volumes = config.Volumes
	s.labels = config.Labels
	s.stopSignal = config.StopSignal

	// we need a dummy container object to trick containerd
	// initialization functions into filling out defaults
	dummy := containers.Container{ID: s.name}

	if len(config.Env) == 0 {
		_ = oci.WithDefaultPathEnv(ctrdCtx, CtrdClient, &dummy, &s.Spec)
	} else {
		s.Process.Env = config.Env
	}
	s.Process.Args = append(config.Entrypoint, config.Cmd...)

	cwd := config.WorkingDir
	if cwd == "" {
		cwd = "/"
	}
	s.Process.Cwd = cwd
	if config.User != "" {
		if err := oci.WithUser(config.User)(ctrdCtx, CtrdClient, &dummy, &s.Spec); err != nil {
			return err
		}
		if err := oci.WithAdditionalGIDs(fmt.Sprintf("%d", s.Process.User.UID))(ctrdCtx, CtrdClient, &dummy, &s.Spec); err != nil {
			return err
		}
	}
	return oci.WithAdditionalGIDs("root")(ctrdCtx, CtrdClient, &dummy, &s.Spec)
}

func (s *ociSpec) updateMounts(disks []types.DiskStatus, nested bool) {
	ociVolumeData := "rootfs"
	root := ""
	mounts := []specs.Mount{}
	rootMount := specs.Mount{Type: "bind"}

	if nested {
		rootMount.Destination = "/mnt"
		root = path.Join(rootMount.Destination, ociVolumeData)
		mounts = append(mounts, specs.Mount{
			Type:        "tmpfs",
			Source:      "tmpfs",
			Destination: path.Join(root, "dev"),
			Options:     []string{"nosuid", "strictatime", "mode=755", "size=65536"},
		})
	}

	for id, disk := range disks {
		src := disk.FileLocation
		opts := []string{"rbind"}
		if disk.ReadOnly {
			opts = append(opts, "ro")
		} else {
			opts = append(opts, "rw")
		}

		// we may need additional filtering here, but for now assume that
		// we can bind mount anything aside from FmtUnknown
		switch disk.Format {
		case zconfig.Format_FmtUnknown:
			continue
		case zconfig.Format_CONTAINER:
			if path.Clean(disk.MountDir) == "/" {
				rootMount.Options = opts
				rootMount.Source = src
				continue
			} else {
				src = path.Join(src, ociVolumeData)
			}
		}

		dests := []string{fmt.Sprintf("/dev/eve/volumes/by-id/%d", id)}
		if disk.DisplayName != "" {
			dests = append(dests, "/dev/eve/volumes/by-name/"+disk.DisplayName)
		}
		if disk.MountDir != "" {
			dst := disk.MountDir
			if disk.Format != zconfig.Format_CONTAINER {
				// this is a bit of a hack: we assume that anything but
				// the container image has to be a file and thus make it
				// appear *under* destination directory as a file with ID
				dst = fmt.Sprintf("%s/%d", dst, id)
			}
			dests = append(dests, dst)
		}

		for _, dest := range dests {
			mounts = append(mounts, specs.Mount{
				Type:        "bind",
				Source:      src,
				Destination: path.Join(root, dest),
				Options:     opts,
			})
		}
	}

	if nested && rootMount.Source != "" {
		s.Mounts = append(s.Mounts, rootMount)
	}
	s.Mounts = append(s.Mounts, mounts...)
}

// UpdateMounts adds volume specification mount points to the OCI runtime spec
func (s *ociSpec) UpdateMounts(disks []types.DiskStatus) {
	s.updateMounts(disks, false)
}

// UpdateMountsNested adds volume specification mount points to the OCI runtime spec under a static root
func (s *ociSpec) UpdateMountsNested(disks []types.DiskStatus) {
	s.updateMounts(disks, true)
}

// UpdateEnvVar adds user specified env variables to the OCI spec.
func (s *ociSpec) UpdateEnvVar(envVars map[string]string) {
	for k, v := range envVars {
		s.Process.Env = append(s.Process.Env, fmt.Sprintf("%s=%s", k, v))
	}
}

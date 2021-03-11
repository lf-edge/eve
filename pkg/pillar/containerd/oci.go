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
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/containerd/containerd"
	"github.com/containerd/containerd/containers"
	"github.com/containerd/containerd/oci"
	zconfig "github.com/lf-edge/eve/api/go/config"
	"github.com/lf-edge/eve/pkg/pillar/types"
	v1 "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/opencontainers/runtime-spec/specs-go"
)

const eveScript = "/bin/eve"

var vethScript = []string{"eve", "exec", "pillar", "/opt/zededa/bin/veth.sh"}

// ociSpec is kept private (with all the actions done by getters and setters
// This is because we expect the implementation to still evolve quite a bit
// for all the different task usecases
type ociSpec struct {
	specs.Spec
	name         string
	client       *Client
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
	AddLoader(string) error
	AdjustMemLimit(types.DomainConfig, int64)
	UpdateVifList([]types.VifInfo)
	UpdateFromDomain(*types.DomainConfig)
	UpdateFromVolume(string) error
	UpdateMounts([]types.DiskStatus) error
	UpdateEnvVar(map[string]string)
}

// NewOciSpec returns a default oci spec from the containerd point of view
func (client *Client) NewOciSpec(name string) (OCISpec, error) {
	s := &ociSpec{name: name, client: client}
	// we need a dummy container object to trick containerd
	// initialization functions into filling out defaults
	dummy := containers.Container{ID: s.name}
	ctrdCtx, done := client.CtrNewUserServicesCtx()
	defer done()
	if err := oci.WithDefaultSpec()(ctrdCtx, client.ctrdClient, &dummy, &s.Spec); err != nil {
		return nil, err
	}
	if s.Process == nil {
		s.Process = &specs.Process{}
	}
	if s.Annotations == nil {
		s.Annotations = map[string]string{}
	}
	// default OCI specs have all devices being denied by default,
	// we flip it back to all allow for now, but later on we may
	// need to get more fine-grained
	if s.Linux != nil && s.Linux.Resources != nil && s.Linux.Resources.Devices != nil {
		s.Linux.Resources.Devices = nil
	}
	s.Root.Path = "/"
	return s, nil
}

// AddLoader massages the spec so that entry point becomes the loader
func (s *ociSpec) AddLoader(volume string) error {
	spec := &ociSpec{name: s.name}
	f, err := os.Open(filepath.Join(volume, ociRuntimeSpecFilename))
	if err != nil {
		return err
	} else {
		defer f.Close()
	}
	if err := spec.Load(f); err != nil {
		return err
	}

	spec.Root = &specs.Root{Readonly: true, Path: filepath.Join(volume, "rootfs")}
	spec.Linux.Resources = s.Linux.Resources
	spec.Linux.CgroupsPath = s.Linux.CgroupsPath

	// for now, all tasks loaded with a loader get their OOM score reset
	if spec.Process.OOMScoreAdj == nil {
		spec.Process.OOMScoreAdj = new(int)
	}
	*spec.Process.OOMScoreAdj = 0

	// massages .Mounts
	if s.Root.Path != "/" { // FIXME-TASKS: it should be enough to give original OCI spec to a loader
		volumeRoot := path.Join(s.Root.Path, "..")
		// create full copy of our runtime spec
		f, err := os.Create(filepath.Join(volumeRoot, ociRuntimeSpecFilename))
		if err != nil {
			return err
		} else {
			defer f.Close()
		}
		if err = s.Save(f); err != nil {
			return err
		}

		// create mountpoints manifest
		if err := ioutil.WriteFile(filepath.Join(volumeRoot, "mountPoints"),
			[]byte(s.Annotations[eveOCIMountPointsLabel]), 0644); err != nil {
			return err
		}

		// create env manifest
		envPreservelist := make([]string, 0) //store envs for passing to sudo
		envContent := ""
		if s.Process.Cwd != "" {
			envContent = fmt.Sprintf("export WORKDIR=\"%s\"\n", s.Process.Cwd)
		}
		for _, e := range s.Process.Env {
			keyAndValueSlice := strings.SplitN(e, "=", 2)
			if len(keyAndValueSlice) == 2 {
				//handles Key=Value case
				envContent = envContent + fmt.Sprintf("export %s=\"%s\"\n", keyAndValueSlice[0], keyAndValueSlice[1])
				envPreservelist = append(envPreservelist, keyAndValueSlice[0])
			} else {
				//handles Key= case
				envContent = envContent + fmt.Sprintf("export %s\n", e)
				envPreservelist = append(envPreservelist, e)
			}
		}
		if err := ioutil.WriteFile(filepath.Join(volumeRoot, "environment"), []byte(envContent), 0644); err != nil {
			return err
		}

		envInsert := ""
		if len(envPreservelist) > 0 {
			envInsert = fmt.Sprintf("--preserve-env=%s", strings.Join(envPreservelist, ","))
		}

		// create cmdline manifest
		// each item needs to be independently quoted for initrd
		execpathQuoted := make([]string, 0)
		for _, s := range s.Process.Args {
			execpathQuoted = append(execpathQuoted, fmt.Sprintf("\"%s\"", s))
		}
		execpath := strings.Join(execpathQuoted, " ")
		// in case of non-zero UID we should use sudo inside cmdline
		if s.Process.User.UID != 0 {
			groupInsert := ""
			if s.Process.User.GID != 0 {
				groupInsert = fmt.Sprintf("-g '#%d'", s.Process.User.GID)
			}
			execpath = fmt.Sprintf("/usr/bin/sudo -u '#%d' %s %s %s", s.Process.User.UID, groupInsert, envInsert, execpath)
		}
		if err := ioutil.WriteFile(filepath.Join(volumeRoot, "cmdline"),
			[]byte(execpath), 0644); err != nil {
			return err
		}

		spec.Mounts = append(spec.Mounts, specs.Mount{
			Type:        "bind",
			Source:      volumeRoot,
			Destination: "/mnt",
			Options:     []string{"rbind", "rw"}})
	}
	for _, mount := range s.Mounts {
		// for now we're filtering anything that is not a bind-mount
		// since those mountpoints will be dealt with inside of the
		// launcher -- at some point we may need to be launcher specific
		// (at least when it comes to tmpfs)
		if mount.Type != "bind" {
			continue
		}
		mount.Destination = "/mnt/rootfs" + mount.Destination
		spec.Mounts = append(spec.Mounts, mount)
	}

	// delete unneeded annotation
	delete(s.Spec.Annotations, eveOCIMountPointsLabel)

	// pass annotations into spec
	spec.Spec.Annotations = s.Spec.Annotations

	// finally do a switcheroo
	s.Spec = spec.Spec

	return nil
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
	if s.Process == nil {
		s.Process = &specs.Process{}
	}
	if s.Annotations == nil {
		s.Annotations = map[string]string{}
	}
	return nil
}

// CreateContainer starts an OCI container based on the spec
func (s *ociSpec) CreateContainer(removeExisting bool) error {
	ctrdCtx, done := s.client.CtrNewUserServicesCtx()
	defer done()
	_, err := s.client.ctrdClient.NewContainer(ctrdCtx, s.name, containerd.WithSpec(&s.Spec))
	// if container exists, is stopped and we are asked to remove existing - try that
	if err != nil && removeExisting {
		_ = s.client.CtrDeleteContainer(ctrdCtx, s.name)
		_, err = s.client.ctrdClient.NewContainer(ctrdCtx, s.name, containerd.WithSpec(&s.Spec))
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
func (s *ociSpec) UpdateVifList(vifs []types.VifInfo) {
	// use pre-start and post-stop hooks for networking
	if s.Hooks == nil {
		s.Hooks = &specs.Hooks{}
	}
	timeout := 60
	for _, v := range vifs {
		vifSpec := []string{"VIF_NAME=" + v.Vif, "VIF_BRIDGE=" + v.Bridge, "VIF_MAC=" + v.Mac}
		s.Hooks.Prestart = append(s.Hooks.Prestart, specs.Hook{
			Env:     vifSpec,
			Path:    eveScript,
			Args:    append(vethScript, "up", s.name, v.Vif, v.Bridge, v.Mac),
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
func (s *ociSpec) UpdateFromDomain(dom *types.DomainConfig) {
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

		s.Linux.CgroupsPath = fmt.Sprintf("/%s/%s", ctrdServicesNamespace, dom.GetTaskName())
	}
	s.Annotations[EVEOCIVNCPasswordLabel] = dom.VncPasswd
}

// UpdateFromVolume updates values in the OCI spec based on the location
// of an EVE volume. EVE volume's are expected to be structured as directories
// in the filesystem with either config.json containing the full OCI runtime
// spec or at least image-config.json containing OCI Image manifest (full
// OCI runtime spec takes precedence). In addition to that each volume is
// expected to have rootfs subfolder with a full rootfs filesystem
func (s *ociSpec) UpdateFromVolume(volume string) error {
	if f, err := os.Open(filepath.Join(volume, ociRuntimeSpecFilename)); err == nil {
		defer f.Close()
		if err = s.Load(f); err != nil {
			return err
		}
		s.Root.Path = volume + "/rootfs"
	} else if imgInfo, err := getSavedImageInfo(volume); err == nil {
		s.Root.Path = volume + "/rootfs" // we need to set Root.Path before doing things with users/groups in spec
		if err = s.updateFromImageConfig(imgInfo.Config); err != nil {
			return err
		}
	}

	return nil
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
	ctrdCtx, done := s.client.CtrNewUserServicesCtx()
	defer done()

	if len(config.Env) == 0 {
		_ = oci.WithDefaultPathEnv(ctrdCtx, s.client.ctrdClient, &dummy, &s.Spec)
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
		if err := oci.WithUser(config.User)(ctrdCtx, s.client.ctrdClient, &dummy, &s.Spec); err != nil {
			return fmt.Errorf("WithUser error: %s", err.Error())
		}
		if err := oci.WithAdditionalGIDs(fmt.Sprintf("%d", s.Process.User.UID))(ctrdCtx, s.client.ctrdClient, &dummy, &s.Spec); err != nil {
			return fmt.Errorf("WithAdditionalGIDs error: %s", err.Error())
		}
		return nil
	}
	return oci.WithAdditionalGIDs("root")(ctrdCtx, s.client.ctrdClient, &dummy, &s.Spec)
}

// UpdateMounts adds volume specification mount points to the OCI runtime spec
func (s *ociSpec) UpdateMounts(disks []types.DiskStatus) error {
	ociVolumeData := "rootfs"
	blkMountPoints := ""

	for id, disk := range disks {
		dst := disk.MountDir
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
				// skipping root volumes for now
				continue
			} else {
				src = path.Join(src, ociVolumeData)
			}
		}

		dests := []string{fmt.Sprintf("/dev/eve/volumes/by-id/%d", id)}
		if disk.DisplayName != "" {
			dests = append(dests, "/dev/eve/volumes/by-name/"+disk.DisplayName)
		}
		if dst != "" {
			if disk.Format != zconfig.Format_CONTAINER {
				// this is a bit of a hack: we assume that anything but
				// the container image has to be a file and thus make it
				// appear *under* destination directory as a file with ID
				blkMountPoints = blkMountPoints + dst + "\n"
				dst = fmt.Sprintf("%s/%d", dst, id)
			}
			if !strings.HasPrefix(dst, "/") {
				return fmt.Errorf("updateMounts: targetPath %s should be absolute", dst)
			}
			dests = append(dests, dst)
		}

		for _, dest := range dests {
			s.Mounts = append(s.Mounts, specs.Mount{
				Type:        "bind",
				Source:      src,
				Destination: dest,
				Options:     opts,
			})
		}
	}

	s.Annotations[eveOCIMountPointsLabel] = blkMountPoints

	return nil
}

// UpdateEnvVar adds user specified env variables to the OCI spec.
func (s *ociSpec) UpdateEnvVar(envVars map[string]string) {
	for k, v := range envVars {
		s.Process.Env = append(s.Process.Env, fmt.Sprintf("%s=%s", k, v))
	}
}

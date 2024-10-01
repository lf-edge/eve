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
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/containerd/containerd"
	"github.com/containerd/containerd/containers"
	"github.com/containerd/containerd/oci"
	zconfig "github.com/lf-edge/eve-api/go/config"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/linuxkit/linuxkit/src/cmd/linuxkit/moby"
	v1 "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/opencontainers/runtime-spec/specs-go"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
	"tags.cncf.io/container-device-interface/pkg/cdi"
)

const eveScript = "/bin/eve"

// eveECOCMDOverride value overrides cmd if provided
const eveECOCMDOverride = "EVE_ECO_CMD"

var vethScript = []string{"eve", "exec", "pillar", "/opt/zededa/bin/veth.sh"}

var dhcpcdScript = []string{"eve", "exec", "pillar", "/opt/zededa/bin/dhcpcd.sh"}

// ociSpec is kept private (with all the actions done by getters and setters
// This is because we expect the implementation to still evolve quite a bit
// for all the different task usecases
type ociSpec struct {
	specs.Spec
	name          string
	client        *Client
	exposedPorts  map[string]struct{}
	volumes       map[string]struct{}
	labels        map[string]string
	stopSignal    string
	service       bool
	containerOpts []containerd.NewContainerOpts
}

// OCISpec provides methods to manipulate OCI runtime specifications and create containers based on them
type OCISpec interface {
	Get() *specs.Spec
	Save(*os.File) error
	Load(*os.File) error
	CreateContainer(bool) error
	AddLoader(string) error
	AdjustMemLimit(types.DomainConfig, int64)
	UpdateVifList([]types.VifConfig)
	UpdateFromDomain(dom *types.DomainConfig, status *types.DomainStatus)
	UpdateFromVolume(string) error
	UpdateMounts([]types.DiskStatus) error
	UpdateEnvVar(map[string]string)
	UpdateWithIoBundles(config *types.DomainConfig, aa *types.AssignableAdapters, domainID int) error
	GrantFullAccessToDevices()
}

// NewOciSpec returns a default oci spec from the containerd point of view
func (client *Client) NewOciSpec(name string, service bool) (OCISpec, error) {
	s := &ociSpec{name: name, client: client}
	// we need a dummy container object to trick containerd
	// initialization functions into filling out defaults
	dummy := containers.Container{ID: s.name}
	ctrdCtx, done := client.CtrNewUserServicesCtx()
	defer done()
	if err := oci.WithDefaultSpec()(ctrdCtx, client.ctrdClient, &dummy, &s.Spec); err != nil {
		logrus.Errorf("NewOciSpec: WithDefaultSpec error: %s", err.Error())
		return nil, err
	}
	if s.Process == nil {
		s.Process = &specs.Process{}
	}
	if s.Annotations == nil {
		s.Annotations = map[string]string{}
	}
	if s.Linux == nil {
		s.Linux = &specs.Linux{}
	}
	if s.Linux.Resources == nil {
		s.Linux.Resources = &specs.LinuxResources{}
	}

	s.Root.Path = "/"
	s.service = service
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

	// we're gonna use a little hack: since we already have the rootfs of a xen-tools container
	// laid out on disk, but don't have it in a form of a snapshot or an image, we're going to
	// create an empty snapshot and then overlay the rootfs on top of it - this way we can save
	// ourselves copying the rootfs around and still have the newest version of xen-tools on every
	// boot, while the original xen-tools rootfs stays read-only

	ctrdCtx, done := s.client.CtrNewUserServicesCtx()
	defer done()

	// create a clean snapshot
	snapshotName := s.name
	snapshotMount, err := s.client.CtrCreateEmptySnapshot(ctrdCtx, snapshotName)
	if err != nil {
		return err
	}

	// remove fs from the end of snapshotMount
	snapshotPath := strings.TrimSuffix(snapshotMount[0].Source, "/fs")
	logrus.Debugf("Snapshot path: %s", snapshotPath)

	xenToolsMount := specs.Mount{
		Type:        "overlay",
		Source:      "overlay",
		Destination: "/",
		Options: []string{
			"index=off",
			"workdir=" + snapshotPath + "/work",
			"upperdir=" + snapshotPath + "/fs",
			"lowerdir=" + volume + "/rootfs",
		}}

	// we need to prepend the loader mount to the existing mounts to make sure it's mounted first because it's the rootfs
	spec.Mounts = append([]specs.Mount{xenToolsMount}, spec.Mounts...)

	s.containerOpts = append(s.containerOpts, containerd.WithSnapshot(snapshotName))

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

		// TODO: work with saving of spec
		// In case of saving spec here we mistakenly preserve old mounts on purge and restart of app
		// due to re-loading of saved mounts (appended in UpdateMounts for the first boot of app)
		// inside UpdateFromVolume for the next boot on restart of app

		// create mountpoints manifest
		if err := os.WriteFile(filepath.Join(volumeRoot, "mountPoints"),
			[]byte(s.Annotations[eveOCIMountPointsLabel]), 0644); err != nil {
			return err
		}

		// create env manifest
		envContent := ""
		if s.Process.Cwd != "" {
			envContent = fmt.Sprintf("export WORKDIR=\"%s\"\n", s.Process.Cwd)
		}
		for _, e := range s.Process.Env {
			keyAndValueSlice := strings.SplitN(e, "=", 2)
			if len(keyAndValueSlice) == 2 {
				// handles Key=Value case
				envContent = envContent + fmt.Sprintf("export %s=\"%s\"\n", keyAndValueSlice[0], keyAndValueSlice[1])
			} else {
				// handles Key= case
				envContent = envContent + fmt.Sprintf("export %s\n", e)
			}
		}

		if err := os.WriteFile(filepath.Join(volumeRoot, "environment"), []byte(envContent), 0644); err != nil {
			return err
		}

		// create cmdline manifest
		// each item needs to be independently quoted for initrd
		execpathQuoted := make([]string, 0)
		for _, s := range s.Process.Args {
			execpathQuoted = append(execpathQuoted, fmt.Sprintf("\"%s\"", s))
		}
		execpath := strings.Join(execpathQuoted, " ")
		if err := os.WriteFile(filepath.Join(volumeRoot, "cmdline"),
			[]byte(execpath), 0644); err != nil {
			return err
		}

		ug := fmt.Sprintf("%d %d", s.Process.User.UID, s.Process.User.GID)
		if err := os.WriteFile(filepath.Join(volumeRoot, "ug"),
			[]byte(ug), 0644); err != nil {
			return err
		}

		spec.Mounts = append(spec.Mounts, specs.Mount{
			Type:        "bind",
			Source:      volumeRoot,
			Destination: "/mnt",
			Options:     []string{"rbind", "rw", "rslave"}})

		if err := os.MkdirAll(filepath.Join(volumeRoot, "modules"), 0600); err != nil {
			return err
		}

		spec.Mounts = append(spec.Mounts, specs.Mount{
			Type:        "bind",
			Source:      "/lib/modules",
			Destination: "/mnt/modules",
			Options:     []string{"rbind", "ro", "rslave"}})
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
		return fmt.Errorf("ociSpec.Load error: %s", err)
	}
	s.Spec = *ns
	if s.Process == nil {
		s.Process = &specs.Process{}
	}
	if s.Annotations == nil {
		s.Annotations = map[string]string{}
	}
	if s.Linux == nil {
		s.Linux = &specs.Linux{}
	}
	if s.Linux.Resources == nil {
		s.Linux.Resources = &specs.LinuxResources{}
	}
	return nil
}

// CreateContainer starts an OCI container based on the spec
func (s *ociSpec) CreateContainer(removeExisting bool) error {
	ctrdCtx, done := s.client.CtrNewUserServicesCtx()
	defer done()

	containerOpts := append(s.containerOpts, containerd.WithSpec(&s.Spec))

	_, err := s.client.ctrdClient.NewContainer(ctrdCtx, s.name, containerOpts...)
	// if container exists, is stopped and we are asked to remove existing - try that
	if err != nil && removeExisting {
		_ = s.client.CtrDeleteContainer(ctrdCtx, s.name)
		_, err = s.client.ctrdClient.NewContainer(ctrdCtx, s.name, containerOpts...)
	}
	return err
}

// AdjustMemLimit adds Memory Resources of the spec with given number
func (s *ociSpec) AdjustMemLimit(dom types.DomainConfig, addMemory int64) {
	// update cgroup resource constraints for CPU and memory
	if s.Linux != nil {
		m := int64(dom.Memory)*1024 + addMemory
		s.Linux.Resources.Memory.Limit = &m
	}
}

func getDeviceInfo(path string) (specs.LinuxDevice, error) {
	var statInfo unix.Stat_t
	var devType string
	ociDev := specs.LinuxDevice{}

	err := unix.Stat(path, &statInfo)
	if err != nil {
		return ociDev, err
	}

	switch statInfo.Mode & unix.S_IFMT {
	case unix.S_IFBLK:
		devType = "b"
	case unix.S_IFCHR:
		devType = "c"
	case unix.S_IFDIR:
		devType = "d"
	case unix.S_IFIFO:
		devType = "p"
	case unix.S_IFLNK:
		devType = "l"
	case unix.S_IFSOCK:
		devType = "s"
	}

	ociDev.Path = path
	ociDev.Type = devType
	ociDev.Major = int64(unix.Major(statInfo.Rdev))
	ociDev.Minor = int64(unix.Minor(statInfo.Rdev))
	return ociDev, nil
}

func (s *ociSpec) UpdateWithIoBundles(config *types.DomainConfig, aa *types.AssignableAdapters, domainID int) error {
	// Process I/O adapters
	devList := []string{}
	cdiList := []string{}
	for _, adapter := range config.IoAdapterList {
		logrus.Debugf("processing adapter %d %s\n", adapter.Type, adapter.Name)
		list := aa.LookupIoBundleAny(adapter.Name)

		if len(list) == 0 {
			// We reserved it in handleCreate so nobody could have stolen it
			logrus.Fatalf("IoBundle disappeared %d %s for %v\n",
				adapter.Type, adapter.Name, domainID)
		}
		for _, ib := range list {
			if ib == nil {
				continue
			}
			if ib.UsedByUUID != config.UUIDandVersion.UUID {
				logrus.Fatalf("IoBundle not ours %s: %d %s for %v\n",
					ib.UsedByUUID, adapter.Type, adapter.Name,
					domainID)
			}

			// Video devices
			if ib.Type == types.IoHDMI {
				// It's a CDI device?
				cdiDev := ib.Cbattr["cdi"]
				if cdiDev != "" {
					logrus.Infof("Adding CDI device %s\n", cdiDev)
					cdiList = append(cdiList, cdiDev)
				}
			}

			// Serial devices
			if ib.Type == types.IoCom && ib.Serial != "" {
				logrus.Infof("Adding serial %s\n", ib.Serial)
				devList = append(devList, ib.Serial)
			}

			// Generic devices
			if ib.Type == types.IoOther && ib.Ifname != "" {
				logrus.Infof("Adding generic device %s\n", ib.Ifname)
				devList = append(devList, ib.Ifname)
			}
		}
	}

	if s.Linux == nil {
		s.Linux = &specs.Linux{}
	}
	if s.Linux.Devices == nil {
		s.Linux.Devices = make([]specs.LinuxDevice, 0)
	}

	// Process CDI device list
	for _, dev := range cdiList {
		_, err := cdi.GetRegistry().InjectDevices(&s.Spec, dev)
		if err != nil {
			logrus.Errorf("could not resolve CDI device %s: %v", dev, err)
			return err
		}
	}

	// I/O Adapter device access
	for _, dev := range devList {
		// Get information about the file device (type, major and minor number)
		ociDev, err := getDeviceInfo(dev)
		if err != nil {
			logrus.Errorf("could not retrieve information about device file %s", dev)
			continue
		}
		s.Linux.Devices = append(s.Linux.Devices, ociDev)
	}
	return nil
}

// UpdateVifList creates VIF management hooks in OCI spec
func (s *ociSpec) UpdateVifList(vifs []types.VifConfig) {
	if s.service || len(vifs) == 0 {
		// we do not want to hook network for service or for containers
		// without any virtual interface
		return
	}
	// use pre-start and post-stop hooks for networking
	if s.Hooks == nil {
		s.Hooks = &specs.Hooks{}
	}
	timeout := 60
	s.Hooks.Poststop = append(s.Hooks.Poststop, specs.Hook{
		Path:    eveScript,
		Args:    append(dhcpcdScript, "down", s.name),
		Timeout: &timeout,
	})
	for _, v := range vifs {
		vifSpec := []string{"VIF_NAME=" + v.Vif, "VIF_BRIDGE=" + v.Bridge,
			"VIF_MAC=" + v.Mac.String()}
		s.Hooks.Prestart = append(s.Hooks.Prestart, specs.Hook{
			Env:     vifSpec,
			Path:    eveScript,
			Args:    append(vethScript, "up", v.Vif, v.Bridge, v.Mac.String()),
			Timeout: &timeout,
		})
		s.Hooks.Poststop = append(s.Hooks.Poststop, specs.Hook{
			Env:     vifSpec,
			Path:    eveScript,
			Args:    append(vethScript, "down", v.Vif),
			Timeout: &timeout,
		})
	}
	s.Hooks.Prestart = append(s.Hooks.Prestart, specs.Hook{
		Path:    eveScript,
		Args:    append(dhcpcdScript, "up", s.name),
		Timeout: &timeout,
	})
}

// UpdateFromDomain updates values in the OCI spec based on EVE DomainConfig settings
func (s *ociSpec) UpdateFromDomain(dom *types.DomainConfig, status *types.DomainStatus) {
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

		m := int64(dom.Memory) * 1024
		p := uint64(100000)
		q := int64(100000 * dom.VCpus)
		s.Linux.Resources.Memory.Limit = &m
		s.Linux.Resources.CPU.Period = &p
		s.Linux.Resources.CPU.Quota = &q
		if len(status.VmConfig.CPUs) != 0 {
			cpusAsString := make([]string, len(status.VmConfig.CPUs))
			for i, cpu := range status.VmConfig.CPUs {
				cpusAsString[i] = fmt.Sprintf("%d", cpu)
			}
			s.Linux.Resources.CPU.Cpus = strings.Join(cpusAsString, ",")
		}

		s.Linux.CgroupsPath = fmt.Sprintf("/%s/%s", ctrdServicesNamespace, dom.GetTaskName())
	}
	if !s.service {
		// not create uts namespace by default for MobyLabelConfigMode
		s.Hostname = dom.UUIDandVersion.UUID.String()
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
	//if not based on an OCI image, nothing to update here
	if volume == "" {
		return nil
	}
	if s.service {
		imgInfoConfig, err := getSavedImageInfo(volume)
		if err != nil {
			logrus.Errorf("updateFromVolume: service %v getSavedImageInfo error: %s", s.service, err.Error())
			return err
		}
		label := "org.mobyproject.config"
		labelString, ok := imgInfoConfig.Config.Labels[label]
		// if label not found than it was not prepared as expected
		if !ok {
			return fmt.Errorf("label %s not found, cannot run as service container", label)
		}
		imgInfo, err := moby.NewImage([]byte(labelString))
		if err != nil {
			logrus.Errorf("updateFromVolume: NewImage error: %s", err.Error())
			return err
		}

		s.Spec, _, err = moby.ConfigToOCI(&imgInfo, imgInfoConfig.Config, map[string]uint32{})
		if err != nil {
			logrus.Errorf("updateFromVolume: ConfigToOCI error: %s", err.Error())
			return err
		}
		s.Root.Path = volume + "/rootfs"
		return nil
	}
	if f, err := os.Open(filepath.Join(volume, ociRuntimeSpecFilename)); err == nil {
		defer f.Close()
		if err = s.Load(f); err != nil {
			logrus.Errorf("updateFromVolume: Load error: %s", err.Error())
			return err
		}
		s.Root.Path = volume + "/rootfs"
		return nil
	}
	imgInfo, err := getSavedImageInfo(volume)
	if err != nil {
		logrus.Errorf("updateFromVolume: service %v getSavedImageInfo error: %s", s.service, err.Error())
		return err
	}
	s.Root.Path = volume + "/rootfs" // we need to set Root.Path before doing things with users/groups in spec
	return s.updateFromImageConfig(imgInfo.Config)
}

// UpdateFromImageConfig updates values in the OCI spec based
// on the values provided in the Image Config section as per:
//
//	https://github.com/opencontainers/image-spec/blob/master/config.md
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
		switch k {
		case eveECOCMDOverride:
			if len(v) != 0 {
				// Command string might contain several parameters
				// separated by space. However, if the variable was defined
				// with quotation marks, it will split wrongly, so it must
				// be trimmed off first, i.e., remove leading and trailing
				// spaces and double quotes
				tstr := strings.Trim(v, " \"")
				s.Process.Args = strings.Fields(tstr)
			}
		}
	}
}

// GrantFullAccessToDevices grants full access to all file devices
func (s *ociSpec) GrantFullAccessToDevices() {
	// default OCI specs have all devices being denied by default,
	// we flip it back to all allow for now, but later on we may
	// need to get more fine-grained
	s.Linux.Resources.Devices = []specs.LinuxDeviceCgroup{{
		Type:   "a",
		Allow:  true,
		Access: "rwm",
	}}
}

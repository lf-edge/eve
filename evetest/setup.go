// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package evetest

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	eveconfig "github.com/lf-edge/eve-api/go/config"
	"github.com/lf-edge/eve/evetest/constants"
	api "github.com/lf-edge/eve/evetest/grpcapi/go"
	"github.com/lf-edge/eve/evetest/utils"
	pillartypes "github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/utils/generics"
	uuid "github.com/satori/go.uuid"
	"github.com/spf13/viper"
	"github.com/vishvananda/netlink"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/proto"
)

// prepareEVEDeviceForOnboarding generates serial number and onboarding certificates
// for the device.
func (th *TestHarness) prepareEVEDeviceForOnboarding(dev *deviceState) {
	var err error
	dev.serial, err = utils.RandomDeviceSerial(8)
	if err != nil {
		th.t.Fatalf("Failed to generate serial number for device %q: %v",
			dev.name, err)
	}
	onboardUUID := th.newUUID("onboarding certificate")
	dev.onboardCert, dev.onboardKey, err = utils.GenServerCertElliptic(
		th.caCert, th.caKey, big.NewInt(2), nil, nil, onboardUUID.String())
	if err != nil {
		th.t.Fatalf("Failed to generate onboarding certificate for device %s: %v",
			dev.name, err)
	}
}

// selectArch selects the CPU architecture for EVE devices based on the preferred
// architecture (EVETEST_PREFERRED_ARCH) and the architectures supported by
// the broker. If the preferred architecture is supported, it is used; otherwise
// the first supported architecture is selected as a fallback.
func (th *TestHarness) selectArch() api.ArchType {
	if len(th.brokerSupportedArchs) == 0 {
		th.t.Fatalf("Broker reports no supported CPU architectures")
	}
	preferred := strings.ToLower(
		viper.GetString(constants.PreferredArchEnv))
	var preferredArch api.ArchType
	switch preferred {
	case "amd64":
		preferredArch = api.ArchType_ARCH_AMD64
	case "arm64":
		preferredArch = api.ArchType_ARCH_ARM64
	default:
		th.t.Fatalf("Unsupported value %q for %s%s (use amd64 or arm64)",
			preferred, constants.EnvPrefix, constants.PreferredArchEnv)
	}
	if generics.ContainsItem(th.brokerSupportedArchs, preferredArch) {
		return preferredArch
	}
	fallback := th.brokerSupportedArchs[0]
	th.log.Warnf("Preferred architecture %s is not supported by the broker, "+
		"falling back to %s", preferredArch, fallback)
	return fallback
}

// prepareImageForEVEDevice prepares an EVE image reference for the given device
// and ensures that the corresponding EVE (live or installer) VM image is built
// on the broker.
//
// The method determines the EVE version and hypervisor to use (from the device
// requirements and environment), constructs an ImageRef, and requests the broker
// to build the image. If the broker reports that the required EVE container image
// is missing, the image is extracted from the local Docker daemon, pushed to the
// broker, and the build is retried.
//
// Any failure is considered fatal for the test and will terminate execution.
func (th *TestHarness) prepareImageForEVEDevice(dev *deviceState) {
	eveVersion := dev.requirement.WithEVEVersion
	if eveVersion == "" {
		eveVersion = viper.GetString(constants.EVEVersionEnv)
	}
	if eveVersion == "" {
		th.t.Fatalf("EVE version is not defined")
	}
	var err error
	var hypervisor api.HypervisorType
	switch dev.requirement.WithHypervisor {
	case HypervisorUndefined:
		// Use KVM by default.
		hypervisor = api.HypervisorType_HV_KVM
	case HypervisorKVM:
		hypervisor = api.HypervisorType_HV_KVM
	case HypervisorXen:
		hypervisor = api.HypervisorType_HV_XEN
	case HypervisorKubevirt:
		hypervisor = api.HypervisorType_HV_KUBEVIRT
	}
	arch := th.selectArch()
	dev.imageRef = &api.ImageRef{
		Repo:       viper.GetString(constants.EVERepoEnv),
		Version:    eveVersion,
		Hypervisor: hypervisor,
		Arch:       arch,
	}
	dev.imageName, err = utils.EVEDockerImageName(dev.imageRef)
	if err != nil {
		th.t.Fatalf("Invalid EVE image reference %v: %v", dev.imageRef, err)
	}

	diskSizeInMiB := dev.requirement.MinDiskSizeInMiB
	if diskSizeInMiB == 0 {
		diskSizeInMiB = constants.DefaultEVEDeviceDiskSizeInMiB
	}

	onboardKeyPEM, err := utils.ECDSAPrivateKeyToPEM(dev.onboardKey)
	if err != nil {
		th.t.Fatalf(
			"Failed to PEM-encode the onboarding certificate for device %s: %v",
			dev.name, err)
	}
	rootCert := utils.CertToPEM(th.caCert)

	grubOptions := dev.requirement.WithGrubOptions
	if dev.requirement.WithFilesystem == FilesystemZFS {
		const enableZFS = "eve_install_zfs_with_raid_level=none"
		grubOptions = append(grubOptions,
			fmt.Sprintf("set_global dom0_extra_args \"$dom0_extra_args %s \"", enableZFS))
	}
	if !dev.requirement.WithDirSync {
		grubOptions = append(grubOptions, "set_no_dirsync")
	}
	if dev.requirement.WithHypervisor == HypervisorXen {
		// XEN requires more memory for dom0 and pillar microservices than what EVE
		// provides by default. The minimum memory requirements have increased
		// somewhere between EVE versions 15.10 and 15.11 (we do not know at this
		// point the source of the extra memory pressure). So let's override default
		// values here in the test framework. Memory settings already present in
		// device requirements (WithGrubOptions) are not overridden.
		xenMemDefaults := []struct {
			varName string
			value   string
		}{
			{"hv_dom0_mem_settings", `dom0_mem=1024M,max:1536M`},
			{"hv_eve_mem_settings", `eve_mem=800M,max:1200M`},
			{"hv_ctrd_mem_settings", `ctrd_mem=400M,max:600M`},
		}
		for _, d := range xenMemDefaults {
			alreadySet := false
			for _, opt := range grubOptions {
				if strings.Contains(opt, d.varName) {
					alreadySet = true
					break
				}
			}
			if !alreadySet {
				grubOptions = append(grubOptions,
					fmt.Sprintf("set_global %s \"%s\"", d.varName, d.value))
			}
		}
	}

	var bootstrapConfigPb []byte
	withBoostrapConfig := dev.requirement.WithInjectedBootstrapConfig
	if withBoostrapConfig != nil {
		bootstrapConfig := withBoostrapConfig.MakeBootstrapConfig()
		bootstrapConfigPb, err = proto.Marshal(bootstrapConfig)
		if err != nil {
			th.t.Fatalf("Failed to marshal bootstrap config to protobuf: %v", err)
		}
	}

	var overrideJSON string
	withInjectedNetworkOverride := dev.requirement.WithInjectedNetworkOverride
	if withInjectedNetworkOverride != nil {
		overrideBytes, err := json.Marshal(withInjectedNetworkOverride)
		if err != nil {
			th.t.Fatalf("Failed to marshal network override to JSON: %v", err)
		}
		overrideJSON = string(overrideBytes)
	}

	// Make sure that already during onboarding we have debug logs and SSH access.
	globalProperties := pillartypes.NewConfigItemValueMap()
	globalProperties.SetGlobalValueString(pillartypes.DefaultLogLevel, "debug")
	globalProperties.SetGlobalValueString(pillartypes.DefaultRemoteLogLevel, "debug")
	globalProperties.SetGlobalValueString(
		pillartypes.SSHAuthorizedKeys, constants.EVESSHPublickKey)
	// The configuration options below reduce polling intervals to speed up test
	// execution.
	globalProperties.SetGlobalValueInt(pillartypes.ConfigInterval, 5)
	globalProperties.SetGlobalValueInt(pillartypes.MetricInterval, 20)
	globalProperties.SetGlobalValueInt(pillartypes.DevInfoInterval, 30)
	withInjectedConfigProperties := dev.requirement.WithInjectedConfigProperties
	if withInjectedConfigProperties != nil {
		globalProperties.UpdateItemValues(withInjectedConfigProperties)
	}
	globalPropertiesBytes, err := json.Marshal(globalProperties)
	if err != nil {
		th.t.Fatalf(
			"Failed to marshal global configuration properties to JSON: %v", err)
	}
	globalPropertiesJSON := string(globalPropertiesBytes)

	buildReq := &api.BuildImageRequest{
		ClientId:      th.brokerClientID,
		DeviceName:    dev.name,
		Image:         dev.imageRef,
		MakeInstaller: dev.requirement.DeviceReusePolicy == CreateFromScratchWithInstaller,
		DiskBytes:     uint64(diskSizeInMiB) << 20,
		Config: &api.EveConfig{
			ServerName:        fmt.Sprintf("%s:%d", GetControllerHostname(), GetControllerPort()),
			SoftSerial:        dev.requirement.WithSoftSerial,
			OnboardCertPem:    string(utils.CertToPEM(dev.onboardCert)),
			OnboardKeyPem:     string(onboardKeyPEM),
			V2TlsCertsPem:     []string{string(rootCert)},
			RootCertPem:       string(rootCert),
			GrubOptions:       grubOptions,
			BootstrapConfigPb: bootstrapConfigPb,
			OverrideJson:      overrideJSON,
			GlobalJson:        globalPropertiesJSON,
		},
	}
	ctx, cancel := context.WithTimeout(th.ctx, brokerBuildImageTimeout)
	buildResp, err := th.brokerClient.BuildImage(ctx, buildReq)
	cancel()
	if err != nil {
		th.t.Fatalf("BuildImage %q failed: %v", dev.imageName, err)
	}

	if buildResp.MissingEveContainerImage {
		th.log.Warn("Broker is missing EVE container image — pushing it now...")
		th.pushEVEImageToBroker(dev.imageRef)

		// Retry build
		ctx, cancel = context.WithTimeout(th.ctx, brokerBuildImageTimeout)
		buildResp, err = th.brokerClient.BuildImage(ctx, buildReq)
		cancel()
		if err != nil {
			th.t.Fatalf("BuildImage %q (retry) failed: %v", dev.imageName, err)
		}
		if buildResp.MissingEveContainerImage {
			th.t.Fatalf("Broker is missing EVE container image even after push.")
		}
		th.log.Infof("BuildImage %q succeeded after pushing image.",
			dev.imageName)
	} else {
		th.log.Infof("BuildImage %q succeeded (docker image was already present).",
			dev.imageName)
	}
}

// pushEVEImageToBroker streams a pre-built EVE container image to the broker
// using a client-side streaming gRPC call.
//
// The function first sends image metadata to initiate the upload, then streams
// the gzipped Docker image data in fixed-size chunks directly from the local
// Docker daemon. The image data is produced lazily and streamed without loading
// the entire image into memory.
//
// The upload is bounded by a timeout and relies on stream EOF to signal
// completion. On success, the broker responds indicating whether the image
// already existed or was newly uploaded. Any failure during streaming or upload
// results in a fatal error.
func (th *TestHarness) pushEVEImageToBroker(imageRef *api.ImageRef) {
	ctx, cancel := context.WithTimeout(th.ctx, brokerPushEVEImageTimeout)
	defer cancel()

	stream, err := th.brokerClient.PushEVEContainerImage(ctx)
	if err != nil {
		th.t.Fatalf("PushEVEContainerImage failed: %v", err)
	}

	// First message: metadata
	err = stream.Send(&api.PushImageChunk{
		Payload: &api.PushImageChunk_Request{
			Request: &api.PushImageRequest{
				ClientId: th.brokerClientID,
				Image:    imageRef,
			},
		},
	})
	if err != nil {
		th.t.Fatalf("failed to send image metadata: %v", err)
	}

	dockerImageName, err := utils.EVEDockerImageName(imageRef)
	if err != nil {
		th.t.Fatalf("invalid EVE image reference: %v", err)
	}

	imageSize, err := utils.GetDockerImageSizeBytes(ctx, dockerImageName)
	if err != nil {
		if utils.IsErrDockerImageNotFound(err) {
			th.t.Fatalf("EVE image %q is not available (neither locally nor on Docker Hub). "+
				"If running against the current HEAD (EVETEST_EVE_VERSION not explicitly set), "+
				"build the image first with: make eve", dockerImageName)
		}
		th.t.Fatalf("failed to get docker image size: %v", err)
	}

	imageReader, err := utils.StreamDockerImageGzip(ctx, dockerImageName)
	if err != nil {
		th.t.Fatalf("failed to stream docker image: %v", err)
	}
	defer imageReader.Close()

	var sentBytes int64
	nextLogPercent := int64(10)
	buf := make([]byte, 1024*1024) // 1MB chunks
	earlyClose := false

	for {
		n, readErr := imageReader.Read(buf)
		if n > 0 {
			sendErr := stream.Send(&api.PushImageChunk{
				Payload: &api.PushImageChunk_DataGzipChunk{
					DataGzipChunk: buf[:n],
				},
			})
			if sendErr != nil {
				// Server closed the stream early (e.g. image already exists
				// or is being uploaded by another client). Break out and
				// retrieve the server's response via CloseAndRecv.
				earlyClose = true
				break
			}
			sentBytes += int64(n)
			percent := sentBytes * 100 / imageSize
			if percent >= nextLogPercent {
				th.log.Infof("Pushing EVE image %q to broker: %d%% done",
					dockerImageName, nextLogPercent)
				nextLogPercent += 10
			}
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			th.t.Fatalf("failed to read image stream: %v", readErr)
		}
	}

	pushResp, err := stream.CloseAndRecv()
	if err != nil {
		th.t.Fatalf("PushEVEContainerImage failed: %v", err)
	}

	if earlyClose && !pushResp.AlreadyExists {
		th.t.Fatalf("Server closed image upload stream early " +
			"but did not report image as already existing")
	}
	if pushResp.AlreadyExists {
		th.log.Info("EVE container image already exists on broker.")
	} else {
		th.log.Info("EVE container image pushed successfully.")
	}
}

// setupEVEDevices requests the broker to provision and configure EVE devices
// according to the provided device requirements and network model.
//
// The method computes effective CPU and memory values (applying defaults if needed),
// maps SDN ports from the network model to EVE network interfaces, and submits a
// SetupDevices request to the broker. The request includes EVE VM parameters,
// TPM configuration, image reference, and SDN image details.
//
// On success, the function returns the list of SDN uplink IP addresses assigned
// from DHCP server during the SDN setup. Any failure is considered fatal for
// the test and will terminate execution.
func (th *TestHarness) setupEVEDevices(
	devices map[string]*deviceState, netModel *api.NetworkModel) (sdnUplinkIPs []string) {
	setupReq := &api.SetupDevicesRequest{
		ClientId: th.brokerClientID,
		SdnConfig: &api.SDNConfig{
			ImageRepo:    viper.GetString(constants.SDNRepoEnv),
			ImageVersion: viper.GetString(constants.SDNVersionEnv),
		},
	}

	var devNames []string
	for _, dev := range devices {
		devNames = append(devNames, dev.name)
		cpus := dev.requirement.MinCPUs
		if cpus == 0 {
			cpus = constants.DefaultEVEDeviceCPUs
		}
		memSizeInMiB := dev.requirement.MinRAMInMiB
		if memSizeInMiB == 0 {
			memSizeInMiB = constants.DefaultEVEDeviceRAMInMiB
		}
		var interfaces []*api.EVEInterface
		for i, port := range netModel.Ports {
			if port.EveDeviceName == dev.requirement.Name {
				interfaces = append(interfaces, &api.EVEInterface{
					Name:          fmt.Sprintf("eth%d", i),
					MacAddress:    port.EveMacAddress,
					SdnMacAddress: port.SdnMacAddress,
				})
			}
		}
		dev.spec = &api.EVEDevice{
			DeviceName:   dev.requirement.Name,
			Cpus:         uint32(cpus),
			MemoryBytes:  uint64(memSizeInMiB) << 20,
			SerialNumber: dev.serial,
			WithTpm:      dev.requirement.WithTPM,
			Image:        dev.imageRef,
			Interfaces:   interfaces,
		}
		setupReq.Devices = append(setupReq.Devices, dev.spec)
	}

	setupTimeout := brokerSetupDevicesTimeout
	for _, dev := range devices {
		if dev.requirement.DeviceReusePolicy == CreateFromScratchWithInstaller {
			setupTimeout += constants.EVEInstallationTimeout
			break
		}
	}
	ctx, cancel := context.WithTimeout(th.ctx, setupTimeout)
	th.log.Debugf("Submitting request to setup devices: %s", setupReq)
	setupResp, err := th.brokerClient.SetupDevices(ctx, setupReq)
	cancel()
	if err != nil {
		th.t.Fatalf("Failed to setup devices %v: %v", devNames, err)
	}
	th.log.Infof("Setup completed for devices %v", devNames)
	return setupResp.GetSdnUplinkIps()
}

// openTunnelToSDN establishes a point-to-point IP tunnel between the evetest
// container and the SDN service.
//
// The tunnel is used to route controller traffic through the SDN by:
//  1. Requesting a tunnel from the broker via gRPC.
//  2. Creating and configuring a local TUN interface.
//  3. Bridging packets between the TUN interface and the gRPC tunnel stream.
func (th *TestHarness) openTunnelToSDN() {
	// Send the initial connect request.
	var err error
	th.sdnTunStream, err = th.brokerClient.ConnectTunnelToSDN(th.ctx)
	if err != nil {
		th.t.Fatalf("Failed to connect an IP tunnel to SDN: %v", err)
	}
	connectReq := &api.ConnectTunnelToSDNRequest{
		Payload: &api.ConnectTunnelToSDNRequest_Connect{
			Connect: &api.SDNTunnel{
				ClientId: th.brokerClientID,
				IpAddresses: []string{
					sdnTunVMIPv4.String() + sdnTunIPv4Prefix,
					sdnTunVMIPv6.String() + sdnTunIPv6Prefix,
				},
				Mtu: sdnTunMTU,
				Routes: []*api.IPRoute{
					{
						DstNetwork: GetControllerIPv4().String() + "/32",
						Gateway:    sdnTunContainerIPv4.String(),
					},
					{
						DstNetwork: GetControllerIPv6().String() + "/128",
						Gateway:    sdnTunContainerIPv6.String(),
					},
					{
						DstNetwork: GetImageServerIPv4().String() + "/32",
						Gateway:    sdnTunContainerIPv4.String(),
					},
				},
			},
		},
	}
	if err := th.sdnTunStream.Send(connectReq); err != nil {
		th.t.Fatalf("Failed to send SDN tunnel connect request: %v", err)
	}

	// Receive initial response (tunnel properties, empty for now).
	_, err = th.sdnTunStream.Recv()
	if err != nil {
		th.t.Fatalf("Failed to receive SDN tunnel properties: %v", err)
	}

	// Create the tunnel interface.
	th.sdnTunIntf, err = utils.CreateTUN(sdnTunName)
	if err != nil {
		th.t.Fatalf("Failed to create TUN %q: %v", sdnTunName, err)
	}

	// Configure TUN interface
	link, err := netlink.LinkByName(sdnTunName)
	if err != nil {
		th.t.Fatalf("Failed to get link for %q: %v", sdnTunName, err)
	}
	if err = netlink.LinkSetMTU(link, sdnTunMTU); err != nil {
		th.t.Fatalf("Failed to set MTU %d on %q: %v", sdnTunMTU, sdnTunName, err)
	}
	if err := netlink.LinkSetUp(link); err != nil {
		th.t.Fatalf("Failed to bring up interface %q: %v", sdnTunName, err)
	}
	th.sdnTunIdx = link.Attrs().Index
	tunAddrs := []string{
		sdnTunContainerIPv4.String() + sdnTunIPv4Prefix,
		sdnTunContainerIPv6.String() + sdnTunIPv6Prefix,
	}
	for _, tunAddr := range tunAddrs {
		addr, err := netlink.ParseAddr(tunAddr)
		if err != nil {
			th.t.Fatalf("Invalid IP address %q: %v", tunAddr, err)
		}
		err = netlink.AddrAdd(link, addr)
		if err != nil && !os.IsExist(err) {
			th.t.Fatalf("Failed to add IP %q to %q: %v", tunAddr, sdnTunName, err)
		}
	}

	// Run tunnel proxy
	grpcPipe :=
		utils.GrpcClientPipe[api.ConnectTunnelToSDNRequest, api.ConnectTunnelToSDNResponse]{
			MakeRequest: func(data []byte) *api.ConnectTunnelToSDNRequest {
				return &api.ConnectTunnelToSDNRequest{
					Payload: &api.ConnectTunnelToSDNRequest_Data{
						Data: data,
					},
				}
			},
			Stream: th.sdnTunStream,
		}
	tunPipe := utils.ReadWriterPipe{
		PipeName: "tun device",
		RW:       th.sdnTunIntf,
		Buf:      make([]byte, os.Getpagesize()),
	}
	tunLog := th.log.WithField("component", "tun")
	th.sdnTunCtx, th.sdnTunCancel = context.WithCancel(th.ctx)
	th.wg.Add(1)
	th.sdnTunWG.Add(1)
	go func() {
		defer th.wg.Done()
		defer th.sdnTunWG.Done()
		utils.RunPipeProxy(th.sdnTunCtx, tunLog, "SDN tunnel", grpcPipe, tunPipe)
	}()
}

// Configure tunnel routes.
// These are the traffic flows that must be supported (initiator listed first):
//   - EVE <-> Controller
//   - EVE / App / Proxy <-> Internet
//   - Test <-> SDN
//   - Test <-> EVE / App
//   - Test <-> Internet
//
// And we must consider both cases of SDN running inside and outside the evetest
// container.
func (th *TestHarness) setupSDNTunnelRoutes(sdnUplinkIPs []string) {
	if len(sdnUplinkIPs) == 0 {
		th.t.Fatalf("SDN uplink IPs are empty")
	}
	sdnUplinkIP := net.ParseIP(sdnUplinkIPs[0])
	if sdnUplinkIP == nil {
		th.t.Fatalf("Invalid SDN uplink IP: %s", sdnUplinkIPs[0])
	}

	// By default, route traffic via the SDN tunnel
	// (connectivity between EVE/App/Proxy/SDN and evetest/controller).
	// IPv4
	_, anyV4, _ := net.ParseCIDR("0.0.0.0/0")
	defaultIPv4 := &netlink.Route{
		LinkIndex: th.sdnTunIdx,
		Dst:       anyV4,
		Gw:        sdnTunVMIPv4,
		Family:    netlink.FAMILY_V4,
	}
	if err := netlink.RouteReplace(defaultIPv4); err != nil {
		th.t.Fatalf("Failed to add default IPv4 route via tunnel: %v", err)
	}
	// IPv6
	_, anyV6, _ := net.ParseCIDR("::")
	defaultIPv6 := &netlink.Route{
		LinkIndex: th.sdnTunIdx,
		Dst:       anyV6,
		Gw:        sdnTunVMIPv6,
		Family:    netlink.FAMILY_V6,
	}
	if err := netlink.RouteReplace(defaultIPv6); err != nil {
		th.t.Fatalf("Failed to add default IPv6 route via tunnel: %v", err)
	}

	// Create dedicated routing table routing traffic via the docker network.
	const dockerTable = 100
	// IPv4
	if err := netlink.RouteAdd(&netlink.Route{
		LinkIndex: th.dockerIntfIdx,
		Dst:       anyV4,
		Gw:        th.dockerGwIPv4,
		Table:     dockerTable,
		Family:    netlink.FAMILY_V4,
	}); err != nil && !errors.Is(err, syscall.EEXIST) {
		th.t.Fatalf("Failed to add IPv4 default route for docker network: %v",
			err)
	}
	// IPv6
	if th.dockerGwIPv6 != nil {
		if err := netlink.RouteAdd(&netlink.Route{
			LinkIndex: th.dockerIntfIdx,
			Dst:       anyV6,
			Gw:        th.dockerGwIPv6,
			Table:     dockerTable,
			Family:    netlink.FAMILY_V6,
		}); err != nil && !errors.Is(err, syscall.EEXIST) {
			th.t.Fatalf("Failed to add IPv6 default route for docker table: %v",
				err)
		}
	}

	// Policy routing: traffic with src IP of the container → docker network
	// (used for Test <-> Internet)
	// IPv4
	ruleV4 := netlink.NewRule()
	ruleV4.Src = &net.IPNet{
		IP:   GetSrcIPv4ForInternetAccess(),
		Mask: net.CIDRMask(32, 32),
	}
	ruleV4.Table = dockerTable
	ruleV4.Priority = 500
	if err := netlink.RuleAdd(ruleV4); err != nil && !errors.Is(err, syscall.EEXIST) {
		th.t.Fatalf("Failed to add IPv4 container source rule: %v", err)
	}
	// IPv6
	if th.dockerGwIPv6 != nil {
		ruleV6 := netlink.NewRule()
		ruleV6.Src = &net.IPNet{
			IP:   GetSrcIPv6ForInternetAccess(),
			Mask: net.CIDRMask(128, 128),
		}
		ruleV6.Table = dockerTable
		ruleV6.Priority = 500
		if err := netlink.RuleAdd(ruleV6); err != nil && !errors.Is(err, syscall.EEXIST) {
			th.t.Fatalf("Failed to add IPv6 container source rule: %v", err)
		}
	}

	if !th.brokerInContainer {
		// No additional routing required if SDN is external
		return
	}

	// Determine SDN uplink interface
	sdnUplink, err := utils.GetEgressInterfaceForIP(sdnUplinkIP)
	if err != nil {
		th.t.Fatalf("Failed to determine SDN uplink interface: %v", err)
	}
	th.log.Debugf("SDN uplink interface: %s", sdnUplink)

	// Policy routing: traffic arriving from SDN uplink → docker network
	// (this is used for EVE / App / Proxy <-> Internet, when SDN is deployed inside
	// the container)
	// For both IPv4 and IPv6
	rule := netlink.NewRule()
	rule.IifName = sdnUplink
	rule.Table = dockerTable
	rule.Priority = 1000
	rule.Family = netlink.FAMILY_V4
	if err = netlink.RuleAdd(rule); err != nil && !errors.Is(err, syscall.EEXIST) {
		th.t.Fatalf("Failed to add SDN uplink IPv4 ingress rule: %v", err)
	}
	rule.Family = netlink.FAMILY_V6
	if err = netlink.RuleAdd(rule); err != nil && !errors.Is(err, syscall.EEXIST) {
		th.t.Fatalf("Failed to add SDN uplink IPv6 ingress rule: %v", err)
	}
}

// Onboard devices into Adam and potentially also apply the initial device configurations.
func (th *TestHarness) onboardEVEDevices() {
	th.devicesM.Lock()

	// Power-on EVE devices first.
	for _, dev := range th.devices {
		devCtrlReq := &api.DeviceControlRequest{
			ClientId:   th.brokerClientID,
			DeviceName: dev.name,
		}
		ctx, cancel := context.WithTimeout(th.ctx, brokerPowerOnEVEDeviceTimeout)
		_, err := th.brokerClient.PowerOnDevice(ctx, devCtrlReq)
		cancel()
		if err != nil {
			th.t.Fatalf("Failed to power on device %q: %v", dev.name, err)
		}
		th.log.Infof("Device %q powered on", dev.name)
	}

	// Perform onboarding in parallel.
	errCh := make(chan error, len(th.devices))
	for _, dev := range th.devices {
		go func(dev deviceState) {
			err := th.onboardEVEDevice(dev)
			errCh <- err
		}(*dev)
	}

	th.devicesM.Unlock()
	for range th.devices {
		err := <-errCh
		if err != nil {
			th.t.Fatal(err)
		}
	}
}

// onboardEVEDevice onboards a single EVE device into the Adam controller.
//
// It registers the device using its onboarding certificate and serial number,
// stores the assigned device UUID, and waits for the device to publish its
// ECDH certificate (required for encrypting parts of the device configuration).
//
// The provided deviceState is treated as read-only; shared state updates
// (UUID, ECDH certificate) are performed under devicesM lock.
func (th *TestHarness) onboardEVEDevice(dev deviceState) error {
	// Onboard device into Adam controller.
	ctx, cancel := context.WithTimeout(th.ctx, deviceOnboardTimeout)
	defer cancel()
	uuid, err := th.adamClient.OnboardDevice(ctx, dev.onboardCert, dev.serial)
	if err != nil {
		return fmt.Errorf("failed to onboard device %q: %v", dev.name, err)
	}

	// Input arg "dev" is intentionally read-only (not pointer).
	// Lock devicesM for a short moment and save the received device UUID.
	th.devicesM.Lock()
	th.devices[dev.name].ID = uuid
	th.devicesM.Unlock()
	th.log.Infof("Onboarded device %q (UUID: %s)", dev.name, uuid)

	// Subscribe to device info and request events to keep state up-to-date.
	th.startDeviceStateWatcher(dev.name, uuid)

	// Wait for the device to publish the ECDH certificate.
	// This might be later needed to encrypt cipher blocks inside the device
	// configuration.
	ecdhCert, err := th.waitForDeviceECDHCert(dev.name, uuid)
	if err != nil {
		return err
	}
	th.devicesM.Lock()
	th.devices[dev.name].ecdhCert = ecdhCert
	th.devicesM.Unlock()
	th.log.Infof("Device %q published ECDH certificate", dev.name)
	return nil
}

func (th *TestHarness) isDeviceOnboarded(devName string) bool {
	th.devicesM.Lock()
	defer th.devicesM.Unlock()
	devState, found := th.devices[devName]
	return found && devState.ID != uuid.Nil
}

// Wait for the device to publish its ECDH certificate to the controller.
func (th *TestHarness) waitForDeviceECDHCert(
	devName string, devUUID uuid.UUID) (*x509.Certificate, error) {
	ctx, cancel := context.WithTimeout(th.ctx, deviceAttestTimeout)
	defer cancel()

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	var errCount int

	for {
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("failed to get device %q ECDH certificate: %w",
				devName, ctx.Err())
		case <-ticker.C:
			cert, err := th.adamClient.GetDeviceECDHCert(ctx, devUUID)
			if err != nil {
				errCount++
				if errCount > 10 {
					return nil, fmt.Errorf(
						"failed to get device %q ECDH certificate: %w",
						devName, err)
				}
				th.log.Errorf("Temporary failure retrieving ECDH certificate "+
					"for device %q: %v; will retry", devName, err)
				continue
			}
			if cert != nil {
				return cert, nil
			}
			th.log.Infof("Waiting for device %q to publish ECDH certificate...",
				devName)
		}
	}
}

// If network model is not provided, generate default model
// with one interface per EVE node, all connected to the same network
// with DHCP enabled.
func (th *TestHarness) genDefaultNetworkModel(devNames []string) *api.NetworkModel {
	netModel := &api.NetworkModel{
		Bridges: []*api.Bridge{
			{
				LogicalLabel: "bridge",
			},
		},
		Networks: []*api.Network{
			{
				LogicalLabel: "network",
				Bridge:       "bridge",
				Ipv4: &api.NetworkIPConfig{
					Subnet: "172.20.20.0/24",
					GwIp:   "172.20.20.1",
					Dhcp: &api.DHCP{
						Enable:     true,
						DomainName: "evetest",
						Dns: &api.DNSClientConfig{
							PrivateDns: []string{"dns-server"},
						},
					},
				},
			},
		},
		Endpoints: &api.Endpoints{
			DnsServers: []*api.DNSServer{
				{
					Endpoint: &api.Endpoint{
						LogicalLabel: "dns-server",
						Fqdn:         "dns-server.test",
						Ipv4: &api.EndpointIPConfig{
							Subnet: "10.16.16.0/24",
							Ip:     "10.16.16.25",
						},
					},
					StaticEntries: []*api.DNSEntry{
						{
							FqdnSource: &api.DNSEntry_FqdnLiteral{
								FqdnLiteral: GetControllerHostname(),
							},
							IpSource: &api.DNSEntry_IpLiteral{
								IpLiteral: GetControllerIPv4().String(),
							},
						},
					},
					UpstreamServers: []string{"8.8.8.8", "1.1.1.1"},
				},
			},
		},
	}
	for _, devName := range devNames {
		portLabel := devName + "-eth0"
		eveMAC := utils.GenerateMAC(devName, portLabel)
		sdnMAC := utils.GenerateMAC(constants.SDNDeviceName, portLabel)
		netModel.Ports = append(netModel.Ports, &api.Port{
			LogicalLabel:  portLabel,
			EveDeviceName: devName,
			EveMacAddress: eveMAC.String(),
			SdnMacAddress: sdnMAC.String(),
			AdminUp:       true,
		})
		netModel.Bridges[0].Ports = append(netModel.Bridges[0].Ports, portLabel)
	}
	return netModel
}

// Connect to the SDN gRPC server.
func (th *TestHarness) connectToSDN(sdnUplinkIPs []string) {
	ctx, cancel := context.WithTimeout(th.ctx, sdnConnectTimeout)
	defer cancel()

	sdnGrpcPort := strconv.Itoa(int(viper.GetUint16(constants.SDNPortEnv)))
	retryInterval := 500 * time.Millisecond

	var lastErr error

	for {
		for _, sdnIP := range sdnUplinkIPs {
			select {
			case <-ctx.Done():
				// Timeout expired
				err := fmt.Errorf("unable to connect to SDN gRPC service "+
					"on any of the uplink IPs (%v): %w", sdnUplinkIPs, lastErr)
				th.t.Fatal(err)
				return
			default:
			}

			sdnAddr := net.JoinHostPort(sdnIP, sdnGrpcPort)
			// Note: no I/O is performed by grpc.NewClient, connection to SDN
			// is established with the first RPC call, which is GetStatus() -- see below.
			th.sdnConn, lastErr = grpc.NewClient(
				sdnAddr, grpc.WithTransportCredentials(insecure.NewCredentials()),
			)
			if lastErr == nil {
				th.sdnClient = api.NewSDNClient(th.sdnConn)
				var statusResp *api.SDNStatusResponse
				statusResp, lastErr = th.sdnClient.GetStatus(ctx, &api.SDNRequest{})
				if lastErr == nil {
					th.log.Infof("Connected to SDN gRPC at %s, SDN status: %s",
						sdnAddr, statusResp.String())
					return
				}
			}

			th.log.Warnf(
				"Failed to connect to SDN gRPC at %s (will retry): %v",
				sdnAddr, lastErr)
		}

		// Wait before the next retry round
		select {
		case <-ctx.Done():
			err := fmt.Errorf(
				"unable to connect to SDN gRPC service on any of the uplink IPs (%v): %w",
				sdnUplinkIPs, lastErr)
			th.t.Fatal(err)
			return
		case <-time.After(retryInterval):
		}
	}
}

// checkInternetConnectivity verifies that the test environment has the required
// Internet connectivity before running a test.
//
// It asks the SDN service to probe connectivity to a well-known external endpoint
// (currently www.google.com:443) and evaluates IPv4 and optionally IPv6 reachability.
// If the required connectivity is not available, the test is skipped rather than failed.
func (th *TestHarness) checkInternetConnectivity(req RequireInternetConnectivity) {
	ctx, cancel := context.WithTimeout(th.ctx, sdnTestInternetConnTimeout)
	th.log.Debug("Submitting request to test Internet connectivity")
	resp, err := th.sdnClient.CheckConnectivity(ctx, &api.SDNConnectivityRequest{
		Hostname: "www.google.com",
		Port:     443,
	})
	cancel()
	if err != nil {
		th.t.Fatal(err)
	}
	if !resp.ReachableOverIpv4 {
		th.t.Skipf("Test %q requires IPv4 Internet connectivity "+
			"which is (currently) not available", th.t.Name())
	}
	if !resp.ReachableOverIpv6 && req.RequireIPv6 {
		th.t.Skipf("Test %q requires IPv6 Internet connectivity "+
			"which is (currently) not available", th.t.Name())
	}
}

// Reuse devices if the requirements match the previous test
// and the reuse policy for this test allows it.
func (th *TestHarness) maybeReuseDevices(
	edgeDevReqs map[string]RequireEdgeDevice, netModel *api.NetworkModel) bool {
	// For simplicity, we will avoid reusing devices between tests when the network
	// model differs.
	th.netModelM.Lock()
	sameNetModel := proto.Equal(th.netModel, netModel)
	th.netModelM.Unlock()
	if !sameNetModel {
		return false
	}

	// Check if every edge device can be reused.
	th.devicesM.Lock()
	if len(th.devices) != len(edgeDevReqs) {
		th.devicesM.Unlock()
		return false
	}
	for devName, newReq := range edgeDevReqs {
		if newReq.DeviceReusePolicy == CreateFromScratchWithInstaller ||
			newReq.DeviceReusePolicy == CreateFromScratchWithLiveImage {
			th.devicesM.Unlock()
			return false
		}

		dev, devFound := th.devices[devName]
		if !devFound {
			th.devicesM.Unlock()
			return false
		}
		if dev.wasUpgraded {
			// EVE was upgraded on this device; the running version no longer
			// matches the original requirement, so reuse is not safe.
			th.devicesM.Unlock()
			return false
		}
		if dev.ID == NilUUID || dev.ecdhCert == nil {
			// Do not reuse the device unless it has been successfully onboarded
			// and has published its ECDH certificate.
			th.devicesM.Unlock()
			return false
		}
		// Cannot reuse device if requirements changed.
		prevReq := dev.requirement
		equalReqs := newReq.MinCPUs == prevReq.MinCPUs &&
			newReq.MinRAMInMiB == prevReq.MinRAMInMiB &&
			newReq.MinDiskSizeInMiB == prevReq.MinDiskSizeInMiB &&
			newReq.WithEVEVersion == prevReq.WithEVEVersion &&
			newReq.WithHypervisor == prevReq.WithHypervisor &&
			newReq.WithFilesystem == prevReq.WithFilesystem &&
			newReq.WithDirSync == prevReq.WithDirSync &&
			newReq.WithTPM == prevReq.WithTPM &&
			newReq.WithSoftSerial == prevReq.WithSoftSerial &&
			generics.EqualLists(newReq.WithGrubOptions, prevReq.WithGrubOptions) &&
			generics.EqualSets(newReq.WithUSBPassthrough, prevReq.WithUSBPassthrough) &&
			generics.EqualSets(newReq.WithPCIPassthrough, prevReq.WithPCIPassthrough)
		if !equalReqs {
			th.devicesM.Unlock()
			return false
		}
	}

	// Reuse every device in parallel.
	errCh := make(chan error, len(th.devices))
	for devName, devReq := range edgeDevReqs {
		dev := th.devices[devName]
		go func(dev deviceState, newReq RequireEdgeDevice) {
			err := th.reuseDevice(dev, devReq)
			errCh <- err
		}(*dev, devReq)
	}

	th.devicesM.Unlock()
	for range th.devices {
		err := <-errCh
		if err != nil {
			th.t.Fatal(err)
		}
	}
	return true
}

// reuseDevice attempts to reuse an existing device for a new test run
// according to the provided requirements and reuse policy.
//
// It performs any cleanup or lifecycle actions required by the reuse policy
// (e.g. clearing state, re-onboarding, rebooting), and ensures that the device
// is ready to fetch the latest configuration from the controller.
func (th *TestHarness) reuseDevice(dev deviceState, newReq RequireEdgeDevice) error {
	// Remove collect-info tarballs produced during the previous test.
	ctx, cancel := context.WithTimeout(th.ctx, 10*time.Second)
	err := th.runScriptOnEVEOverSSH(
		ctx, dev.name, "rm -rf /persist/eve-info/*", nil, nil, 0)
	cancel()
	if err != nil {
		// Just log warning and continue. This step is not crucial.
		th.log.Warnf("failed to clear /persist/eve-info for device %q: %v",
			dev.name, err)
	}

	if newReq.DeviceReusePolicy == UseAsIs {
		th.devicesM.Lock()
		th.devices[dev.name].rebootCount = 0
		th.devices[dev.name].expectedRebootCount = 0
		th.devicesM.Unlock()
		return nil
	}

	// Trigger device re-onboarding.
	if newReq.DeviceReusePolicy == ReonboardEdgeDevice {
		if err = th.forceDeviceReonboarding(dev); err != nil {
			return err
		}
	}

	// Snapshot the boot time before any reboot so we can later determine
	// whether the post-reboot info message has already been processed.
	th.devicesM.Lock()
	preReuseBootTime := th.devices[dev.name].lastBootTime
	th.devicesM.Unlock()
	rebooted := false

	// Reboot device.
	switch newReq.DeviceReusePolicy {
	case RebootEdgeDevice, ResetDeviceConfigAndReboot, ReonboardEdgeDevice:
		th.log.Infof("Rebooting device %q for reuse purposes.", dev.name)
		devCtrlReq := &api.DeviceControlRequest{
			ClientId:   th.brokerClientID,
			DeviceName: dev.name,
		}
		ctx, cancel := context.WithTimeout(th.ctx, brokerRebootEVEDeviceTimeout)
		_, err := th.brokerClient.RebootDevice(ctx, devCtrlReq)
		cancel()
		if err != nil {
			return fmt.Errorf("failed to reboot device %q: %v", dev.name, err)
		}
		rebooted = true
	}

	if newReq.DeviceReusePolicy == ReonboardEdgeDevice {
		// Wait for device to onboard.
		if err = th.onboardEVEDevice(dev); err != nil {
			return err
		}
	}

	// Reset the device configuration by clearing all application-related
	// settings while preserving the device network configuration.
	switch newReq.DeviceReusePolicy {
	case ResetDeviceConfig, ResetDeviceConfigAndReboot, ReonboardEdgeDevice:
		if err = th.resetDeviceConfig(dev); err != nil {
			return err
		}
	}

	// Wait for device to fetch the latest (potentially cleared) config.
	fetchConfigTimeout := deviceApplyConfigTimeout
	switch newReq.DeviceReusePolicy {
	case RebootEdgeDevice, ResetDeviceConfigAndReboot:
		fetchConfigTimeout += deviceRebootTimeout
	}
	th.log.Infof(
		"Waiting for (reused) device %q to fetch the latest config...",
		dev.name)
	ctx, cancel = context.WithTimeout(th.ctx, fetchConfigTimeout)
	err = th.adamClient.WaitUntilDevRequest(ctx, dev.ID, "/config")
	cancel()
	if err != nil {
		return fmt.Errorf(
			"reused device %q failed to fetch the latest config: %v",
			dev.name, err)
	}

	// For reset policies, wait until all apps and network instances are gone.
	switch newReq.DeviceReusePolicy {
	case ResetDeviceConfig, ResetDeviceConfigAndReboot:
		th.log.Infof(
			"Waiting for all apps and network instances on device %q to be removed...",
			dev.name)
		if err := th.waitUntilNoAppsOrNIs(dev.name); err != nil {
			return err
		}
	}

	// Reset reboot counters so the test body starts from a clean baseline.
	// When the reuse policy triggered a reboot, we must account for whether
	// the post-reboot info message (carrying the new BootTime) has already
	// been processed asynchronously:
	//   - If not yet processed (lastBootTime unchanged): set expectedRebootCount=1
	//     so the pending increment of rebootCount will match it.
	//   - If already processed (lastBootTime changed): both counters reset to 0.
	th.devicesM.Lock()
	currentDev := th.devices[dev.name]
	currentDev.rebootCount = 0
	if rebooted && currentDev.lastBootTime.Equal(preReuseBootTime) {
		currentDev.expectedRebootCount = 1
	} else {
		currentDev.expectedRebootCount = 0
	}
	th.devicesM.Unlock()
	return nil
}

// forceDeviceReonboarding prepares a device for re-onboarding by clearing all
// onboarding-related state both on the device and in the controller. On the device side
// it removes the onboarding status file, wipes device certificates from the config
// partition, and clears the TPM. On the controller side it removes the device record.
// The in-memory device state (UUID, EVE state, interfaces, deployed apps/NIs) is also
// reset so the harness treats the device as freshly seen. The caller is responsible for
// triggering a reboot and then waiting for the device to re-onboard via onboardEVEDevice.
func (th *TestHarness) forceDeviceReonboarding(dev deviceState) error {
	th.log.Infof("Re-onboarding device %q for reuse purposes.", dev.name)

	// Clear device onboarding state, remove device certificates and clear TPM.
	// TODO: handle device without TPM
	shellScript := "rm -rf /persist/status/zedclient/OnboardingStatus && " +
		"mkdir -p /mnt && " +
		"eve config mount /mnt && " +
		"rm -f /mnt/device.* && " +
		"eve config unmount && " +
		"eve enter vtpm && " +
		"tpm2 clear"
	ctx, cancel := context.WithTimeout(th.ctx, 10*time.Second)
	err := th.runScriptOnEVEOverSSH(
		ctx, dev.name, shellScript, nil, nil, 0)
	cancel()
	if err != nil {
		return fmt.Errorf("failed to clear device onboarding state: %v", err)
	}

	// Remove device from the controller.
	ctx, cancel = context.WithTimeout(th.ctx, deviceRemoveTimeout)
	err = th.adamClient.RemoveDevice(ctx, dev.ID)
	cancel()
	if err != nil {
		return fmt.Errorf("failed to remove device %q from the controller: %v",
			dev.name, err)
	}

	// Forget device UUID, state, and tracked deployments.
	th.devicesM.Lock()
	th.devices[dev.name].ID = NilUUID
	th.devices[dev.name].state = api.EVEDeviceState_EVE_DEVICE_STATE_UNDEFINED
	th.devices[dev.name].interfaces = nil
	th.devices[dev.name].deployedApps = nil
	th.devices[dev.name].deployedNIs = nil
	th.devicesM.Unlock()
	return nil
}

// resetDeviceConfig pushes a stripped-down configuration to the device that retains
// only the network settings. All application-level state (apps, network instances,
// datastores, content info, volumes, patch envelopes, profile settings, and config items)
// is cleared so the next test starts from a clean application baseline without disrupting
// the device's network connectivity. The new config is versioned, applied via the
// controller, and saved in the harness's in-memory device record.
func (th *TestHarness) resetDeviceConfig(dev deviceState) error {
	th.devicesM.Lock()
	if dev.config == nil {
		th.devicesM.Unlock()
		return nil
	}
	newConfig := dev.config.Clone()
	th.devicesM.Unlock()

	newConfig.ConfigItems = nil
	newConfig.setDefaultConfigProperties()
	newConfig.Apps = nil
	newConfig.NetworkInstances = nil
	newConfig.Datastores = nil
	newConfig.ContentInfo = nil
	newConfig.Volumes = nil
	newConfig.PatchEnvelopes = nil
	newConfig.LocalProfileServer = ""
	newConfig.GlobalProfile = ""
	newConfig.ProfileServerToken = ""

	// Set config ID.
	configVer := th.nextConfigVersion(newConfig)
	newConfig.Id = &eveconfig.UUIDandVersion{
		Uuid:    dev.ID.String(),
		Version: configVer,
	}

	ctx, cancel := context.WithTimeout(th.ctx, adamApplyConfigTimeout)
	err := th.adamClient.ApplyDeviceConfig(ctx, dev.ID, newConfig.EdgeDevConfig)
	cancel()
	if err != nil {
		return fmt.Errorf("failed to apply the new (cleared) configuration "+
			"(version %s) for device %q: %v", configVer, dev.name, err)
	}

	// Save the applied config.
	th.devicesM.Lock()
	th.devices[dev.name].config = newConfig
	th.devicesM.Unlock()
	return nil
}

// applyK3sRegistryMirrorIfConfigured configures containerd inside the kube
// container to use per-registry pull-through cache mirrors for every kubevirt device.
//
// EVE's K3s setup uses an externally-managed containerd (started by cluster-init.sh
// with --config /etc/containerd/config-k3s.toml, not by K3s itself), so K3s never
// processes registries.yaml. Instead we configure containerd directly by writing
// per-registry hosts.toml files and setting config_path in the containerd config.
// At the point this runs (right after onboarding) containerd is not yet running,
// so no restart is needed — it picks up the config when cluster-init.sh starts it.
//
// Note: This is a temporary workaround. Eventually EVE should be enhanced to
// allow configuring a registry mirror for K3s (containerd) through device config,
// so that evetest does not need to directly manipulate files on the EVE device.
func (th *TestHarness) applyK3sRegistryMirrorIfConfigured() {
	mirrors := constants.LoadRegistryMirrors()
	if len(mirrors) == 0 {
		return
	}

	th.devicesM.Lock()
	var kubevirtDevNames []string
	for _, dev := range th.devices {
		if dev.requirement.WithHypervisor == HypervisorKubevirt {
			kubevirtDevNames = append(kubevirtDevNames, dev.name)
		}
	}
	th.devicesM.Unlock()

	if len(kubevirtDevNames) == 0 {
		return
	}

	for _, devName := range kubevirtDevNames {
		th.configureContainerdRegistryMirror(devName, mirrors)
	}
}

// configureContainerdRegistryMirror writes per-registry hosts.toml files under
// /etc/containerd/certs.d/ inside the kube container and adds config_path to
// /etc/containerd/config-k3s.toml so containerd picks up the mirror on startup.
//
// /run is shared between EVE containers, so the script is staged there and then
// executed inside the kube container via "eve exec" (nsenter-based, no TTY needed).
func (th *TestHarness) configureContainerdRegistryMirror(
	devName string, mirrors map[string][]string) {
	const (
		certsD     = "/etc/containerd/certs.d"
		ctrdConfig = "/etc/containerd/config-k3s.toml"
		scriptPath = "/run/setup-containerd-mirror.sh"
	)

	var sb strings.Builder
	// Iterate in stable order using RegistryMirrorEntries.
	for _, e := range constants.RegistryMirrorEntries {
		addrs, ok := mirrors[e.Registry]
		if !ok {
			continue
		}
		mirrorURL, ok := constants.SelectRegistryMirror(addrs, th.ipv6OnlyRegistryMirrors)
		if !ok {
			continue
		}
		// Ensure the endpoint has a scheme; default to https://.
		endpoint := mirrorURL
		if !strings.Contains(mirrorURL, "://") {
			endpoint = "https://" + mirrorURL
		}
		// When the URL has a path component (e.g. a Harbor proxy-cache project),
		// containerd requires override_path = true and the path must start with /v2/.
		// Without override_path, containerd appends /v2/ after the path, producing
		// an invalid URL. See: https://github.com/containerd/containerd/discussions/11129
		overridePath := false
		if idx := strings.Index(endpoint, "://"); idx != -1 {
			hostAndRest := endpoint[idx+3:]
			if slashIdx := strings.Index(hostAndRest, "/"); slashIdx != -1 {
				// Path present: prepend /v2 and enable override_path.
				path := hostAndRest[slashIdx:]
				endpoint = endpoint[:idx+3] + hostAndRest[:slashIdx] + "/v2" + path
				overridePath = true
			}
		}
		fmt.Fprintf(&sb, "mkdir -p %s/%s\n", certsD, e.Registry)
		if overridePath {
			fmt.Fprintf(&sb,
				"printf '[host.\"%%s\"]\\n  capabilities = [\"pull\", \"resolve\"]\\n"+
					"  override_path = true\\n' %q > %s/%s/hosts.toml\n",
				endpoint, certsD, e.Registry)
		} else {
			fmt.Fprintf(&sb,
				"printf '[host.\"%%s\"]\\n  capabilities = [\"pull\", \"resolve\"]\\n'"+
					" %q > %s/%s/hosts.toml\n", endpoint, certsD, e.Registry)
		}
	}
	fmt.Fprintf(&sb,
		" printf '\\n[plugins.\"io.containerd.grpc.v1.cri\".registry]\\n"+
			"  config_path = \"%s\"\\n' >> %s\n", certsD, ctrdConfig)

	tmpFile, err := os.CreateTemp("", "setup-containerd-mirror-*.sh")
	if err != nil {
		th.t.Fatalf(
			"configureContainerdRegistryMirror: failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())
	if _, err = tmpFile.WriteString(sb.String()); err != nil {
		th.t.Fatalf(
			"configureContainerdRegistryMirror: failed to write temp file: %v", err)
	}
	tmpFile.Close()

	ctx, cancel := context.WithTimeout(th.ctx, fileTransferTimeout)
	err = th.scpToEVE(ctx, devName, tmpFile.Name(), scriptPath, false)
	cancel()
	if err != nil {
		th.t.Fatalf("configureContainerdRegistryMirror: failed to scp script to %q: %v",
			devName, err)
	}

	ctx, cancel = context.WithTimeout(th.ctx, quickSSHCommandTimeout)
	err = th.runScriptOnEVEOverSSH(ctx, devName,
		"eve exec kube sh "+scriptPath, nil, nil, 0)
	cancel()
	if err != nil {
		th.t.Fatalf("configureContainerdRegistryMirror: script failed on %q: %v",
			devName, err)
	}
	th.log.Infof("Containerd registry mirrors configured on device %q", devName)
}

func (th *TestHarness) nextConfigVersion(currentConfig *EdgeDeviceConfig) string {
	var err error
	var configVer int
	if currentConfig != nil && currentConfig.GetId().GetVersion() != "" {
		configVer, err = strconv.Atoi(currentConfig.GetId().GetVersion())
		if err != nil {
			th.t.Fatalf("Failed to convert config version to integer: %v", err)
		}
	}
	configVer++
	return strconv.Itoa(configVer)
}

// waitUntilNoAppsOrNIs waits until there are no deployed applications or
// network instances on the given device. It uses the deployCond condition
// variable to be notified of changes by handleDeviceInfoEvent.
func (th *TestHarness) waitUntilNoAppsOrNIs(devName string) error {
	th.devicesM.Lock()
	defer th.devicesM.Unlock()
	dev, ok := th.devices[devName]
	if !ok {
		return fmt.Errorf("unknown device %q", devName)
	}
	if dev.deployCond == nil {
		dev.deployCond = sync.NewCond(&th.devicesM)
	}
	// Use a timer goroutine to unblock the cond wait on timeout.
	timeout := deviceApplyConfigTimeout
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-time.After(timeout):
			dev.deployCond.Broadcast()
		case <-th.ctx.Done():
			dev.deployCond.Broadcast()
		case <-done:
		}
	}()
	deadline := time.Now().Add(timeout)
	for len(dev.deployedApps) > 0 || len(dev.deployedNIs) > 0 {
		if time.Now().After(deadline) || th.ctx.Err() != nil {
			return fmt.Errorf(
				"timed out waiting for apps/NIs to be removed from device %q "+
					"(apps: %d, NIs: %d)", devName,
				len(dev.deployedApps), len(dev.deployedNIs))
		}
		dev.deployCond.Wait()
	}
	return nil
}

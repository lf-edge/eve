// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package evetest

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"testing"
	"time"

	eveinfo "github.com/lf-edge/eve-api/go/info"
	"github.com/lf-edge/eve/evetest/constants"
	"github.com/lf-edge/eve/evetest/controller"
	api "github.com/lf-edge/eve/evetest/grpcapi/go"
	"github.com/lf-edge/eve/evetest/logger"
	"github.com/lf-edge/eve/evetest/utils"
	"github.com/lf-edge/eve/pkg/pillar/utils/generics"
	uuid "github.com/satori/go.uuid"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"github.com/vishvananda/netlink"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/proto"
)

const (
	// Timeout for establishing a connection to the Broker gRPC service.
	brokerConnectTimeout = 5 * time.Minute

	// Timeout for closing a broker connection, including tearing down
	// all resources associated with the client.
	brokerCloseTimeout = time.Minute

	// Timeout for the broker to build an EVE VM image.
	brokerBuildImageTimeout = 5 * time.Minute

	// Timeout for uploading an EVE Docker image to the broker.
	brokerPushEVEImageTimeout = 10 * time.Minute

	// Timeout for the broker to set up requested devices.
	// This includes building a disk image for every requested EVE device
	// (with the libvirt provider, a multi-device cluster can spend well over
	// a minute per device on this alone), starting the SDN VM and waiting
	// for it to acquire IP addresses via DHCP.
	brokerSetupDevicesTimeout = 15 * time.Minute

	// Timeout for powering on an EVE VM (not for waiting for it to boot).
	brokerPowerOnEVEDeviceTimeout = 20 * time.Second

	// Timeout for triggering an EVE VM reboot (not for waiting for it to boot).
	brokerRebootEVEDeviceTimeout = 20 * time.Second

	// Timeout for the broker to tear-down all devices.
	brokerTeardownDevicesTimeout = time.Minute

	// Timeout for retrieving the full console output for a single EVE device.
	brokerGetConsoleOutputTimeout = 30 * time.Second

	// Timeout for a device to boot and complete onboarding to the controller.
	deviceOnboardTimeout = 10 * time.Minute

	// Timeout for a device to attest (or at least to publish its certificates).
	deviceAttestTimeout = 2 * time.Minute

	// Timeout for a device to fetch the latest configuration from Adam.
	deviceApplyConfigTimeout = 2 * time.Minute

	// Timeout for a device to be removed from the Adam controller.
	deviceRemoveTimeout = 20 * time.Second

	// Timeout for EVE device to perform reboot.
	deviceRebootTimeout = 3 * time.Minute

	// Timeout for establishing a connection to the SDN gRPC service.
	sdnConnectTimeout = 5 * time.Minute

	// Timeout for SDN to test Internet connectivity.
	sdnTestInternetConnTimeout = time.Minute

	// Timeout for updating the SDN network model.
	sdnApplyNetModelTimeout = time.Minute

	// Timeout for submitting device configuration to Adam.
	adamApplyConfigTimeout = 20 * time.Second

	// Timeout for fetching all device logs.
	gatherLogsTimeout = 1 * time.Minute

	// Timeout for fetching all published device info messages.
	gatherInfoMsgsTimeout = 1 * time.Minute

	// Timeout for fetching all published device metrics messages.
	gatherMetricsMsgsTimeout = 1 * time.Minute

	// Timeout for automatically running collect-info.sh on an EVE device and
	// downloading the tarball. This does not apply to `evetest eve collect-info`,
	// where the user controls command termination.
	collectInfoTimeout = 5 * time.Minute

	// Timeout for collecting Go coverage profiles from a single EVE device,
	// including signalling zedbox, waiting for files to appear, and SCP transfer.
	collectCoverageTimeout = 2 * time.Minute

	// Timeout for SSH commands executed on the EVE device that are expected
	// to finish quickly.
	quickSSHCommandTimeout = 5 * time.Second

	// Timeout for file transfers from the EVE device initiated by tests
	// (see EdgeDevice.ReadFile).
	// These transfers are expected to involve reasonably sized files, not
	// extremely large datasets, but may still take longer than quick SSH
	// commands due to network latency or device load.
	fileTransferTimeout = time.Minute

	// If download progress does not advance for this long, WaitUntilAppIsRunning fails.
	downloadStalledTimeout = time.Minute

	// Timeout for pulling an EVE docker image and extracting its rootfs.
	eveImagePullTimeout = 15 * time.Minute

	// Timeout for an EVE device to complete an OS upgrade (download, install, reboot,
	// complete the testing period, and mark the new partition as active).
	eveUpgradeTimeout = 20 * time.Minute
)

const (
	controllerIntfName = "controller"
	imgServerIntfName  = "img-server"
	imgServerPort      = 80

	sdnTunName = "sdn-tun"
	sdnTunMTU  = 1500
)

// Used as constants.
var (
	// IPv4 addressing for the controller and the SDN tunnel uses subnets from
	// 240.0.0.0/4. This address space is reserved for future use and is not
	// routable on the public Internet. Using it avoids conflicts with commonly
	// used private IPv4 ranges (RFC 1918) that may already be present on the host
	// or within test environments.
	//
	// For IPv6, randomly generated Unique Local Address (ULA) subnets are used.
	// The probability of collisions with other ULA prefixes used across EVE
	// tests or on the host system is negligibly small.
	sdnTunContainerIPv4 = net.ParseIP("250.250.250.1").To4()
	sdnTunVMIPv4        = net.ParseIP("250.250.250.2").To4()

	sdnTunContainerIPv6 = net.ParseIP("fdd8:bec2:f2b1:1000::1").To16()
	sdnTunVMIPv6        = net.ParseIP("fdd8:bec2:f2b1:1000::2").To16()

	controllerIPv4 = net.ParseIP("245.245.245.245").To4()
	controllerIPv6 = net.ParseIP("fd24:1ac2:e355::1").To16()

	imgServerIPv4 = net.ParseIP("244.244.244.244").To4()
)

const (
	sdnTunIPv4Prefix = "/30"
	sdnTunIPv6Prefix = "/64"
)

// TestHarness is the central runtime state for executing tests and test suites.
// It owns the gRPC server lifecycle and tracks the currently executing test
// and optional test-suite context.
type TestHarness struct {
	api.UnimplementedEvetestServer

	t         *T
	log       *logrus.Logger
	userLog   *logrus.Logger
	brokerLog *logrus.Logger

	artifactDir string

	dockerIntf    string // typically eth0
	dockerIntfIdx int
	dockerGwIPv4  net.IP
	dockerGwIPv6  net.IP

	// Test being executed
	testM sync.Mutex
	test  testState
	suite *testSuiteState // nil if running a single test

	// Go routines management
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	// gRPC server
	grpcServer *grpc.Server
	listener   net.Listener

	// CA
	caCert *x509.Certificate
	caKey  *rsa.PrivateKey

	// Broker
	brokerInContainer    bool
	brokerConn           *grpc.ClientConn
	brokerClient         api.BrokerClient
	brokerClientID       string
	brokerSupportedArchs []api.ArchType

	// Controller
	adamClient   *controller.AdamClient
	adamStatusCh chan controller.AdamState

	// Image server (HTTP file server serving EVE and app images).
	imgServerListener net.Listener
	imgServerDir      string // temp dir under $HOME/.evetest; removed in Close()

	// SDN
	sdnConn   *grpc.ClientConn
	sdnClient api.SDNClient

	// Tunnel between SDN and the evetest container
	sdnTunCtx    context.Context
	sdnTunCancel context.CancelFunc
	sdnTunWG     sync.WaitGroup
	sdnTunStream grpc.BidiStreamingClient[
		api.ConnectTunnelToSDNRequest, api.ConnectTunnelToSDNResponse]
	sdnTunIntf *os.File
	sdnTunIdx  int

	// Network model.
	netModelM sync.Mutex
	netModel  *api.NetworkModel

	// EVE devices
	devicesM      sync.Mutex
	devices       map[string]*deviceState // key: device name
	deviceStateCh chan deviceStateEvent

	// Checkpoint / Failure
	checkpointM        sync.Mutex
	pauseAtCheckpoint  string
	pausedAtCheckpoint string
	pauseOnFailure     bool
	pausedOnFailure    string
	resume             chan struct{}
	exitCh             chan struct{}
	sigCh              chan os.Signal
}

// testState contains per-test execution state, including parameter
// definitions, resolved parameter values, and initialization tracking.
type testState struct {
	// name is the name of the currently executing test or variant.
	name string

	// paramDefs are the parameter definitions available to the test.
	paramDefs []TestParameterDefinition

	// paramVals are the concrete parameter values applied to the test.
	paramVals []TestParameterValue

	// Directory where artifacts specific to this test should be saved.
	artifactDir string

	// This channel is closed when the test is marked as failed.
	failedCh chan struct{}

	// initialized indicates whether Init has been called for this test.
	initialized bool

	// This is enabled after running RunTestSuite from inside the test.
	executedTestSuite bool
}

// testSuiteState contains shared state for a running test suite.
// It is nil when executing a standalone test.
type testSuiteState struct {
	// name is the name of the test suite.
	name string

	// paramDefs are parameter definitions shared across all tests in the suite.
	paramDefs []TestParameterDefinition
}

type deviceState struct {
	name         string
	requirement  RequireEdgeDevice
	imageRef     *api.ImageRef
	imageName    string
	spec         *api.EVEDevice
	ID           uuid.UUID
	onboardCert  *x509.Certificate
	onboardKey   *ecdsa.PrivateKey
	ecdhCert     *x509.Certificate
	serial       string
	config       *EdgeDeviceConfig
	consoleInUse bool

	unsubscribeInfo    func()
	unsubscribeReq     func()
	unsubscribeMetrics func()
	lastRequestAt      time.Time
	state              api.EVEDeviceState
	interfaces         []*api.EVEInterfaceStatus

	// Active Watch* subscriptions that haven't been stopped yet.
	// Protected by devicesM.
	watcherUnsubs map[*func()]func()

	// Tracked app and network instance states, updated from info messages.
	// Protected by devicesM.
	// Key is the object UUID string; value is the last reported state.
	deployedApps map[string]eveinfo.ZSwState
	deployedNIs  map[string]eveinfo.ZNetworkInstanceState
	// Signaled whenever deployedApps or deployedNIs changes.
	deployCond *sync.Cond

	// lastProcessedConfigTs is the timestamp of the most recently processed config,
	// as reported by EVE in DeviceMetric.LastProcessedConfig.
	// Protected by devicesM.
	lastProcessedConfigTs time.Time
	// configAppliedCond is signaled whenever lastProcessedConfigTs is updated.
	// Protected by devicesM (used as the locker).
	configAppliedCond *sync.Cond

	// Reboot detection.
	// lastBootTime is the most recently observed BootTime from ZInfoDevice messages.
	// rebootCount is incremented by processDeviceStateEvents on each observed reboot.
	// expectedRebootCount is incremented by RequestReboot, SoftReboot, HardReboot, etc.
	lastBootTime        time.Time
	rebootCount         int
	expectedRebootCount int

	// wasUpgraded is set to true once UpgradeEVE has applied an upgrade config.
	// Upgraded devices must not be reused across tests.
	wasUpgraded bool
}

// Global test harness instance.
// It is initialized once per top-level test execution.
// Do not use directly, instead call getTestHarness().
var _globalTH *TestHarness

func getTestHarness() *TestHarness {
	if _globalTH == nil {
		panic(fmt.Sprintf("%s called before Init", utils.FuncNameFromStackTrace(1)))
	}
	return _globalTH
}

// Init initializes the test harness and must be called exactly once per test.
// When used inside a test suite, Init may be called multiple times, once per
// test case, but only a single harness instance will be created.
func Init(t *testing.T) *T {
	if _globalTH != nil {
		// Test harness already exists, meaning this test is likely running as part
		// of a test suite.
		th := _globalTH

		// If exit was requested (e.g. via CLI), skip all subsequent tests.
		select {
		case <-th.exitCh:
			t.Skip("Exit requested, skipping remaining tests")
		default:
		}

		th.testM.Lock()
		defer th.testM.Unlock()
		if th.test.initialized {
			th.t.Fatalf("Multiple Init calls detected")
		}
		th.test.artifactDir = filepath.Join(th.artifactDir, th.test.name)
		if err := os.MkdirAll(th.test.artifactDir, 0o755); err != nil {
			th.t.Fatalf("failed to create directory for test artifacts: %v", err)
		}
		th.test.failedCh = make(chan struct{})
		th.test.initialized = true
		th.t = &T{T: t, th: th}
		return th.t
	}

	constants.InitViperConfig()
	th := &TestHarness{}
	_globalTH = th
	th.t = &T{T: t, th: th}
	th.ctx, th.cancel = context.WithCancel(context.Background())
	th.artifactDir = viper.GetString(constants.InternalArtifactDirEnv)
	th.devices = make(map[string]*deviceState)
	th.deviceStateCh = make(chan deviceStateEvent, 64)
	th.pauseAtCheckpoint = viper.GetString(constants.PauseOnCheckpointEnv)
	th.pauseOnFailure = viper.GetBool(constants.PauseOnFailureEnv)
	th.resume = make(chan struct{})
	th.exitCh = make(chan struct{})
	th.sigCh = make(chan os.Signal, 1)
	signal.Notify(th.sigCh, syscall.SIGTERM, syscall.SIGINT)

	// Set the test name to the calling test function name.
	// Init is expected to be called directly from a TestXxx function.
	th.test.name = utils.FuncNameFromStackTrace(2)
	th.test.artifactDir = th.artifactDir
	if err := os.MkdirAll(th.test.artifactDir, 0o755); err != nil {
		th.t.Fatalf("failed to create directory for test artifacts: %v", err)
	}
	th.test.failedCh = make(chan struct{})
	th.test.initialized = true

	// Setup logging
	logLevelStr := viper.GetString(constants.LogLevelEnv)
	logLevel, err := logrus.ParseLevel(logLevelStr)
	if err != nil {
		th.t.Fatalf("Failed to parse log level %q: %v", logLevelStr, err)
	}
	th.log = logrus.New()
	th.log.SetFormatter(&logger.PrefixedFormatter{
		Prefix: "HARNESS ",
		Color:  logger.PrefixColorBlue,
	})
	th.log.SetLevel(logLevel)
	th.userLog = logrus.New()
	th.userLog.SetFormatter(&logger.PrefixedFormatter{
		Prefix: "TEST    ",
		Color:  logger.PrefixColorCyan,
	})
	th.userLog.SetLevel(logLevel)

	// Setup logging for logs coming from the broker.
	th.brokerLog = logrus.New()
	th.brokerLog.SetFormatter(&logger.PrefixedFormatter{
		Prefix: "BROKER  ",
		Color:  logger.PrefixColorPurple,
	})
	th.brokerLog.SetLevel(logLevel)

	// Determine the default IP gateway and the output interface name.
	gwIPv4, link, err := utils.GetDefaultGateway(netlink.FAMILY_V4)
	if err != nil {
		th.t.Fatalf("failed to get IPv4 default gateway: %v", err)
	}
	th.dockerIntf = link.Attrs().Name
	th.dockerIntfIdx = link.Attrs().Index
	th.dockerGwIPv4 = gwIPv4
	gwIPv6, _, err := utils.GetDefaultGateway(netlink.FAMILY_V6)
	if err != nil {
		// IPv6 connectivity is not available.
		// Just log warning and continue
		th.log.Warnf("failed to get IPv6 default gateway: %v", err)
	} else {
		th.dockerGwIPv6 = gwIPv6
	}

	// Generate CA root certificate.
	certDir := filepath.Join(th.artifactDir, "ca-cert")
	if err = os.MkdirAll(certDir, 0o755); err != nil {
		th.t.Fatalf("failed to create CA certificate directory: %v", err)
	}
	caCertPath := filepath.Join(certDir, "ca.pem")
	caKeyPath := filepath.Join(certDir, "ca-key.pem")
	th.caCert, th.caKey, err = utils.GenCARoot()
	if err != nil {
		th.t.Fatalf("failed to generate CA certificate/key: %v", err)
	}
	err = utils.OutputCertAndKey(th.caCert, th.caKey, caCertPath, caKeyPath)
	if err != nil {
		th.t.Fatalf("failed to output CA certificate/key: %v", err)
	}

	// Start TCP listener for the gRPC API.
	port := viper.GetInt(constants.APIPortEnv)
	listenAddr := fmt.Sprintf(":%d", port)
	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		th.t.Fatalf("Failed to start TCP listener: %v", err)
	}

	// Create and start gRPC server.
	server := grpc.NewServer()
	api.RegisterEvetestServer(server, th)

	th.grpcServer = server
	th.listener = listener

	th.log.Infof("Evetest gRPC server listening on %s", listenAddr)
	th.wg.Add(1)
	go func() {
		defer th.wg.Done()
		if err := server.Serve(listener); err != nil {
			th.log.Infof("Evetest gRPC server stopped: %v", err)
		}
	}()

	// Start the Adam controller, listening on a dedicated dummy interface.
	adamIPs := []net.IP{
		GetControllerIPv4(),
		GetControllerIPv6(),
	}
	adamIPNets := []net.IPNet{
		{IP: GetControllerIPv4(), Mask: net.CIDRMask(32, 32)},
		{IP: GetControllerIPv6(), Mask: net.CIDRMask(128, 128)},
	}
	th.adamStatusCh = make(chan controller.AdamState, 5)
	adamLog := th.log.WithField("component", "adam")
	err = utils.CreateDummyInterface(controllerIntfName, adamIPNets)
	if err != nil {
		th.t.Fatalf("failed to create controller interface: %v", err)
	}
	th.adamClient = controller.NewAdamClient(
		adamLog, th.artifactDir, GetControllerHostname(),
		adamIPs, GetControllerPort(), th.caCert, th.caKey, th.adamStatusCh)
	err = th.adamClient.Start()
	if err != nil {
		th.t.Fatalf("Failed to start Adam controller: %v", err)
	}
	th.wg.Add(1)
	go th.monitorAdam(adamLog)
	th.wg.Add(1)
	go th.processDeviceStateEvents()

	// Create the HTTP image server on a dedicated dummy interface.
	// The serving directory is a temp dir under EVETEST_HOME (= $HOME/.evetest on the
	// host), which is bind-mounted at the same path inside the container so that
	// Docker bind-mounts issued via RunDockerCommand resolve correctly on the host.
	imgCacheParent := viper.GetString(constants.HomeDirEnv)
	if err = os.MkdirAll(imgCacheParent, 0755); err != nil {
		th.t.Fatalf("failed to create image cache parent dir: %v", err)
	}
	th.imgServerDir, err = os.MkdirTemp(imgCacheParent, "img-cache-")
	if err != nil {
		th.t.Fatalf("failed to create image server directory: %v", err)
	}
	imgServerIPNets := []net.IPNet{
		{IP: GetImageServerIPv4(), Mask: net.CIDRMask(32, 32)},
	}
	err = utils.CreateDummyInterface(imgServerIntfName, imgServerIPNets)
	if err != nil {
		th.t.Fatalf("failed to create image server interface: %v", err)
	}
	imgListenAddr := net.JoinHostPort(imgServerIPv4.String(), strconv.Itoa(imgServerPort))
	th.imgServerListener, err = net.Listen("tcp", imgListenAddr)
	if err != nil {
		th.t.Fatalf("failed to listen on image server address %s: %v", imgListenAddr, err)
	}
	go func() {
		mux := http.NewServeMux()
		mux.Handle("/", http.FileServer(http.Dir(th.imgServerDir)))
		_ = http.Serve(th.imgServerListener, mux)
	}()
	th.log.Infof("Image server listening on http://%s/ (serving %s)", imgListenAddr, th.imgServerDir)

	// Create broker client.
	brokerAddr := viper.GetString(constants.BrokerAddressEnv)
	if brokerAddr == "" {
		th.log.Infof("Connecting to the broker running inside the container")
		brokerAddr = "localhost"
		th.brokerInContainer = true
	}
	brokerPort := strconv.Itoa(viper.GetInt(constants.BrokerPortEnv))
	brokerAddr = net.JoinHostPort(brokerAddr, brokerPort)
	// Note: no I/O is performed by grpc.NewClient, connection to broker
	// is established with the first RPC call, which is Connect() -- see below.
	th.brokerConn, err = grpc.NewClient(brokerAddr,
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		th.t.Fatalf("failed to create broker client: %v", err)
	}
	th.brokerClient = api.NewBrokerClient(th.brokerConn)

	// Connect to the broker.
	ctx, cancel := context.WithTimeout(th.ctx, brokerConnectTimeout)
	connectResp, err := th.brokerClient.Connect(ctx, &api.ConnectRequest{})
	cancel()
	if err != nil {
		th.t.Fatalf("failed to connect to the broker at %s: %v", brokerAddr, err)
	}
	th.brokerClientID = connectResp.ClientId
	th.brokerSupportedArchs = connectResp.SupportedArchs
	th.log.Infof("Connected to broker at %s (client_id=%s, version=%s, archs=%v)",
		brokerAddr, th.brokerClientID, connectResp.BrokerVersion,
		th.brokerSupportedArchs)

	// Run broker keep-alive stream.
	th.wg.Add(1)
	go th.runBrokerKeepAlive()

	// Stream broker logs.
	th.wg.Add(1)
	go th.runBrokerLogStream()
	return th.t
}

// Close gracefully shuts down the test harness and releases all resources
// created during Init and Setup.
//
// If the test is running as part of a suite, Close performs no teardown and
// returns immediately, allowing shared resources (such as VMs and network
// infrastructure) to be reused by subsequent test cases.
//
// Otherwise, Close stops all background goroutines, shuts down the internal
// gRPC server, disconnects from the broker (triggering cleanup of all
// associated EVE and SDN devices), removes any SDN tunnel interfaces created
// by the test, and stops the Adam controller.
func Close() error {
	panicErr := recover()
	th := getTestHarness()

	// Unsubscribe any Watch* subscriptions that the test forgot to stop.
	th.devicesM.Lock()
	for _, devState := range th.devices {
		for key, unsub := range devState.watcherUnsubs {
			th.log.Warnf("Test forgot to stop a watcher for device %q, "+
				"unsubscribing automatically", devState.name)
			unsub()
			delete(devState.watcherUnsubs, key)
		}
	}
	th.devicesM.Unlock()

	// Check for unexpected or missing device reboots.
	// Skip when panicking (to avoid adding noise) or for the suite's own Close()
	// (subtests have already been checked; executedTestSuite is true then).
	if panicErr == nil && !th.test.executedTestSuite {
		th.checkRebootCounts()
	}

	// Collect artifacts (if requested by user) unless this is Close for a test suite.
	// (in which case the artifacts were already collected by Close of the last
	// executed test).
	collectArtifacts := viper.GetString(constants.ExternalArtifactDirEnv) != ""
	if collectArtifacts && !th.test.executedTestSuite {
		th.gatherLogsFromAllDevices()
		th.gatherConsoleOutputFromAllDevices()
		th.gatherInfoMsgsFromAllDevices()
		th.collectCoverageFromAllDevices()

		if th.suite != nil {
			// If running test-suite with the QEMU provider, copy QEMU artifacts
			// to the subtest directory.
			if st, err := os.Stat(th.qemuArtifactsDir()); err == nil && st.IsDir() {
				dst := filepath.Join(th.test.artifactDir, constants.QemuArtifactsDirname)
				if err = utils.CopyFolder(th.qemuArtifactsDir(), dst); err != nil {
					th.log.Warnf("Failed to copy QEMU artifacts to %s: %v", dst, err)
				}
			}
		}

		if th.t.Failed() || panicErr != nil {
			// If this test failed, collect diagnostic information from all devices
			// to aid troubleshooting.
			th.collectInfoFromAllDevices()
		}
	}

	if th.suite != nil {
		// When running as part of a test suite, resource teardown is deferred.
		// Shared resources (e.g., VMs) may be reused by subsequent test cases
		// within the same suite and must not be destroyed here.
		return nil
	}

	// Unsubscribe device state watchers.
	th.devicesM.Lock()
	th.unsubscribeDeviceWatchersLocked()
	th.devicesM.Unlock()

	// Stop all goroutines started inside Init().
	th.cancel()
	if th.grpcServer != nil {
		th.grpcServer.GracefulStop()
	}
	th.wg.Wait()

	// Close the gRPC listener.
	if th.listener != nil {
		_ = th.listener.Close()
	}

	// Disconnect from the broker.
	// Broker will remove all devices (EVE and SDN) associated with the client session.
	ctx, cancel := context.WithTimeout(context.Background(), brokerCloseTimeout)
	_, err := th.brokerClient.Close(ctx,
		&api.CloseRequest{ClientId: th.brokerClientID})
	cancel()
	if err != nil {
		th.log.Warnf("Failed to close broker client: %v", err)
	}
	err = th.brokerConn.Close()
	if err != nil {
		th.log.Warnf("Failed to close broker connection: %v", err)
	} else {
		th.log.Infof("Closed broker connection")
	}

	// Stop the image server and remove its cache directory.
	if th.imgServerListener != nil {
		if err := th.imgServerListener.Close(); err != nil {
			th.log.Warnf("Failed to close image server listener: %v", err)
		}
	}
	if th.imgServerDir != "" {
		if err := os.RemoveAll(th.imgServerDir); err != nil {
			th.log.Warnf("Failed to remove image cache dir %s: %v", th.imgServerDir, err)
		}
	}

	// Stop the Adam controller.
	// Not really necessary, Adam would die together with the evetest container.
	err = th.adamClient.Stop()
	if err != nil {
		th.log.Warnf("Failed to stop Adam controller: %v", err)
	}

	if th.test.executedTestSuite {
		// After running test-suite with the QEMU provider, remove the shared QEMU
		// artifacts directory. Artifacts from sub-tests have already been copied into
		// their test-specific artifact subdirectories during Close().
		if err := os.RemoveAll(th.qemuArtifactsDir()); err != nil {
			th.log.Warnf("Failed to remove the QEMU artifact directory: %v", err)
		}
	}

	_globalTH = nil
	if panicErr != nil {
		panic(panicErr)
	}
	return nil
}

// Logger returns the logrus logger associated with the current test harness.
//
// Tests should use this logger for all test-related logging so that output
// is consistently formatted and integrated with the harness lifecycle
// (artifacts, verbosity settings, etc.)
func Logger() *logrus.Logger {
	th := getTestHarness()
	return th.userLog
}

// Setup evaluates and enforces the provided test requirements and prepares
// the test environment accordingly.
//
// The function first validates all supplied requirements. Next, it prepares
// (or generates) a network model, provisions and configures the required EVE device(s),
// and ensures that the SDN and broker infrastructure are running and reachable.
//
// Depending on the test context, Setup will start or reuse existing EVE and
// SDN virtual machines, establish connectivity to the SDN gRPC service using
// a broker-proxied IP-over-TCP tunnel, and apply the requested network model.
//
// When Setup returns successfully, all requirements are satisfied and the
// EVE device(s) is/are powered on and onboarded into the controller. Any failure
// during setup results in the test being failed or skipped.
func Setup(requirements ...Requirement) {
	th := getTestHarness()
	defer th.log.Infof("Setup complete")

	// Collect test requirements.
	edgeDevReqs := make(map[string]RequireEdgeDevice) // key: device name
	var netModel *api.NetworkModel
	var internetReq *RequireInternetConnectivity

	for _, requirement := range requirements {
		switch req := requirement.(type) {
		case RequireEdgeDevice:
			if _, duplicate := edgeDevReqs[req.Name]; duplicate {
				th.t.Fatalf("Duplicate edge device name: %s", req.Name)
			}
			edgeDevReqs[req.Name] = req
		case RequireNetworkModel:
			netModel = proto.CloneOf(req.NetworkModel)
		case RequireInternetConnectivity:
			internetReq = &req
		default:
			th.t.Fatalf("Unsupported requirement: %T", req)
		}
	}

	// Validate edge device requirement.
	if len(edgeDevReqs) == 0 {
		th.t.Fatalf("Missing edge device requirement")
	}
	for _, devReq := range edgeDevReqs {
		if devReq.Name == "" {
			th.t.Fatalf("Missing edge device name")
		}
	}

	// Prepare network model.
	if netModel == nil {
		var devNames []string
		for devName := range edgeDevReqs {
			devNames = append(devNames, devName)
		}
		netModel = th.genDefaultNetworkModel(devNames)
	} else {
		// Make sure that device names and MAC addresses are defined.
		for _, port := range netModel.Ports {
			if port.GetEveDeviceName() == "" {
				if len(edgeDevReqs) > 1 {
					th.t.Fatalf(
						"Network model port is missing EveDeviceName; " +
							"with multiple onboarded EVE devices the target device " +
							"must be specified explicitly",
					)
				}
				// len(edgeDevReqs) == 1
				for name := range edgeDevReqs {
					port.EveDeviceName = name
				}
			}
			if port.GetSdnMacAddress() == "" {
				mac := utils.GenerateMAC(constants.SDNDeviceName, port.LogicalLabel)
				port.SdnMacAddress = mac.String()
			}
			if port.GetEveMacAddress() == "" {
				mac := utils.GenerateMAC(port.EveDeviceName, port.LogicalLabel)
				port.EveMacAddress = mac.String()
			}
		}
	}

	// Add controller configuration into the network model.
	netModel.ControllerConfig = &api.ControllerConfig{
		ControllerIps: []string{
			GetControllerIPv4().String(),
			GetControllerIPv6().String(),
		},
		ControllerPort: uint32(GetControllerPort()),
	}

	// Reuse devices if the requirements match the previous test
	// and the reuse policy for this test allows it.
	if th.maybeReuseDevices(edgeDevReqs, netModel) {
		th.log.Infof("Reusing devices from the previous test")
		// No need to set up devices; they are reused from the previous test.
		// Just check Internet connectivity if required.
		if internetReq != nil {
			th.checkInternetConnectivity(*internetReq)
		}
		return
	} else if len(th.devices) > 0 {
		th.log.Infof("Tearing down devices from the previous test")
		th.teardownDevices()
		// When running with the QEMU provider, remove the shared QEMU artifacts
		// directory. Artifacts from previous tests have already been copied into
		// their test-specific artifact subdirectories during Close().
		if err := os.RemoveAll(th.qemuArtifactsDir()); err != nil {
			th.log.Warnf("Failed to remove the QEMU artifact directory: %v", err)
		}
	}

	// Setup EVE devices.
	devices := make(map[string]*deviceState)
	withIPv6 := internetReq != nil && internetReq.RequireIPv6
	for devName, devReq := range edgeDevReqs {
		devState := &deviceState{name: devName, requirement: devReq}
		devices[devName] = devState
		th.prepareEVEDeviceForOnboarding(devState)
		th.prepareImageForEVEDevice(devState)
	}
	sdnUplinkIPs := th.setupEVEDevices(devices, netModel, withIPv6)
	th.devicesM.Lock()
	th.devices = devices
	th.devicesM.Unlock()

	// Establish an IP tunnel to SDN used for EVE <-> controller/test connectivity.
	th.openTunnelToSDN()
	th.setupSDNTunnelRoutes(sdnUplinkIPs)

	// Connect to the SDN gRPC server.
	// This function sets th.sdnConn and th.sdnClient (or fails with Fatal)
	th.connectToSDN(sdnUplinkIPs)

	// Check Internet connectivity if required.
	if internetReq != nil {
		th.checkInternetConnectivity(*internetReq)
	}

	// Apply the network model.
	ctx, cancel := context.WithTimeout(th.ctx, sdnApplyNetModelTimeout)
	th.log.Debugf("Submitting request to apply network model: %s", netModel)
	_, err := th.sdnClient.SetNetworkModel(ctx, &api.SDNSetNetworkModelRequest{
		NetworkModel: netModel,
	})
	cancel()
	if err != nil {
		th.t.Fatal(err)
	}
	th.netModelM.Lock()
	th.netModel = netModel
	th.netModelM.Unlock()
	th.log.Info("Successfully applied the network model")

	// Onboard EVE devices.
	th.onboardEVEDevices()

	// Configure K3s registry mirror on kubevirt devices if a mirror is specified.
	th.applyK3sRegistryMirrorIfConfigured()
}

// RunParallel runs workerFunc concurrently in numOfWorkers goroutines.
// workerFunc is invoked once per worker and is passed a zero-based
// workerIdx in the range [0, numOfWorkers).
// The function blocks until either:
//   - all workers complete successfully, or
//   - the test is marked as failed, in which case it returns immediately without
//     waiting for the remaining workers.
//
// This enables fail-fast behavior for parallel test execution.
func RunParallel(numOfWorkers int, workerFunc func(workerIdx int)) {
	th := getTestHarness()
	doneCh := make(chan struct{}, numOfWorkers)

	for i := 0; i < numOfWorkers; i++ {
		go func() {
			workerFunc(i)
			doneCh <- struct{}{}
		}()
	}

	th.testM.Lock()
	failedCh := th.test.failedCh
	th.testM.Unlock()

	waitCount := numOfWorkers
	for {
		select {
		case <-doneCh:
			waitCount--
			if waitCount == 0 {
				return
			}
		case <-failedCh:
			// A worker triggered T.Fatal;
			// fail fast and do not wait for the remaining workers.
			th.t.FailNow()
		}
	}
}

// Checkpoint marks a significant execution point in a test.
//
// Each checkpoint is identified by a name. If the environment variable
// EVETEST_PAUSE_ON_CHECKPOINT is set to the same name, test execution will pause
// when this checkpoint is reached.
//
// The test can be resumed via the CLI command:
//
//	evetest continue [--until <next-checkpoint>]
//
// This mechanism is primarily intended for interactive debugging and
// step-by-step inspection of long-running or complex tests.
func Checkpoint(name string) {
	th := getTestHarness()
	if name == "" {
		th.t.Fatalf("missing checkpoint name")
	}
	th.checkpointM.Lock()
	shouldPause := th.pauseAtCheckpoint == name
	if shouldPause {
		th.pausedAtCheckpoint = name
	}
	th.checkpointM.Unlock()

	if shouldPause {
		th.log.Infof("Paused at checkpoint %q", name)
		select {
		case <-th.resume:
			th.log.Infof("Resumed after checkpoint %q", name)
		case sig := <-th.sigCh:
			th.t.Fatalf("Received signal %v while paused at checkpoint %q", sig, name)
		case <-th.exitCh:
			th.log.Info("Exit requested while paused at checkpoint")
			th.t.SkipNow()
		}
	}
}

// UpdateNetworkModel updates the current network model,
// enforcing that device network ports cannot change at runtime.
func UpdateNetworkModel(netModel *api.NetworkModel) {
	th := getTestHarness()
	th.netModelM.Lock()
	defer th.netModelM.Unlock()

	// Fill in fields that were assigned during Setup.
	// The caller may pass a model cloned from a static template that lacks these.
	for _, newPort := range netModel.GetPorts() {
		for _, curPort := range th.netModel.GetPorts() {
			if newPort.GetLogicalLabel() != curPort.GetLogicalLabel() {
				continue
			}
			if newPort.GetEveDeviceName() == "" {
				newPort.EveDeviceName = curPort.GetEveDeviceName()
			}
			if newPort.GetEveMacAddress() == "" {
				newPort.EveMacAddress = curPort.GetEveMacAddress()
			}
			if newPort.GetSdnMacAddress() == "" {
				newPort.SdnMacAddress = curPort.GetSdnMacAddress()
			}
			break
		}
	}
	if netModel.GetControllerConfig() == nil {
		netModel.ControllerConfig = th.netModel.GetControllerConfig()
	}

	// Only the set of ports (by logical label and device assignment) must stay
	// the same -- properties like AdminUp or TrafficControl may change.
	samePortSet := generics.EqualSetsFn(th.netModel.GetPorts(), netModel.GetPorts(),
		func(a, b *api.Port) bool {
			return a.GetLogicalLabel() == b.GetLogicalLabel() &&
				a.GetEveDeviceName() == b.GetEveDeviceName() &&
				a.GetEveMacAddress() == b.GetEveMacAddress() &&
				a.GetSdnMacAddress() == b.GetSdnMacAddress()
		})
	if !samePortSet {
		th.t.Fatalf(
			"It is not allowed to change the set of device network ports in runtime")
	}

	// Apply the new network model.
	ctx, cancel := context.WithTimeout(th.ctx, sdnApplyNetModelTimeout)
	th.log.Debugf("Submitting request to apply network model: %s", netModel)
	_, err := th.sdnClient.SetNetworkModel(ctx, &api.SDNSetNetworkModelRequest{
		NetworkModel: netModel,
	})
	cancel()
	if err != nil {
		th.t.Fatal(err)
	}

	th.netModel = netModel
	th.log.Info("Successfully applied the new network model")
}

// ChangeSigningCert replaces the controller signing certificate
// with the provided one.
func ChangeSigningCert(newSignCertPEM string) error {
	th := getTestHarness()
	// TODO
	th.t.Fatalf("ChangeSigningCert is not implemented")
	return nil
}

// GetControllerHostname returns the controller hostname (stored inside /config/server)
func GetControllerHostname() string {
	return "adam.evetest"
}

// GetControllerPort returns the port number on which the controller listens.
func GetControllerPort() uint16 {
	return 443
}

// GetControllerIPv4 returns the controller (Adam) IPv4 address.
func GetControllerIPv4() net.IP {
	return controllerIPv4
}

// GetControllerIPv6 returns the controller (Adam) IPv6 address and subnet
// associated with the container's default IPv6 route, if present.
func GetControllerIPv6() net.IP {
	return controllerIPv6
}

// GetImageServerIPv4 returns the IPv4 address of the HTTP image server.
func GetImageServerIPv4() net.IP {
	return imgServerIPv4
}

// GetImageServerPort returns the port of the HTTP image server.
func GetImageServerPort() uint16 {
	return imgServerPort
}

// GetSrcIPv4ForInternetAccess returns the first non-link-local IPv4 address
// of the interface connecting container with the docker network.
// This IP should be used as the source IP when tests
// need to access the Internet from the evetest container.
func GetSrcIPv4ForInternetAccess() net.IP {
	th := getTestHarness()
	ips, err := utils.GetInterfaceIPs(th.dockerIntf)
	if err != nil {
		th.t.Fatal(err)
	}
	for _, ip := range ips {
		if ip.To4() == nil || !ip.IsGlobalUnicast() {
			continue
		}
		return ip
	}
	th.t.Fatalf("No suitable global-unicast IPv4 address found on %s",
		th.dockerIntf)
	return nil
}

// GetSrcIPv6ForInternetAccess returns the first global unicast IPv6 address
// assigned to the interface connecting container with the docker network.
// This IP should be used as the source address when tests need IPv6 Internet
// access from the evetest container.
func GetSrcIPv6ForInternetAccess() net.IP {
	th := getTestHarness()
	ips, err := utils.GetInterfaceIPs(th.dockerIntf)
	if err != nil {
		th.t.Fatal(err)
	}
	for _, ip := range ips {
		if ip.To4() != nil || !ip.IsGlobalUnicast() {
			continue
		}
		return ip
	}

	th.t.Fatalf("No suitable global-unicast IPv6 address found on %s",
		th.dockerIntf)
	return nil
}

// GetSrcIPv4ForEVEAccess returns the IPv4 address used as the source IP
// when a test communicates with EVE management services or EVE applications.
// This is exposed to allow network-model firewall rules (when enabled)
// to permit traffic between the test environment and EVE/app endpoints.
func GetSrcIPv4ForEVEAccess() net.IP {
	return sdnTunContainerIPv4
}

// GetSrcIPv6ForEVEAccess returns the IPv6 address used as the source IP
// when a test communicates with EVE management services or EVE applications.
// This is exposed to allow network-model firewall rules (when enabled)
// to permit traffic between the test environment and EVE/app endpoints.
func GetSrcIPv6ForEVEAccess() net.IP {
	return sdnTunContainerIPv6
}

func (th *TestHarness) qemuArtifactsDir() string {
	return filepath.Join(th.artifactDir, constants.QemuArtifactsDirname)
}

func (th *TestHarness) monitorAdam(adamLog *logrus.Entry) {
	defer th.wg.Done()
	for {
		select {
		case <-th.ctx.Done():
			adamLog.Info("Test harness context canceled, stopping Adam monitoring")
			return
		case status := <-th.adamStatusCh:
			if status.Type == controller.AdamStateCrashed {
				// TODO: Calling th.t.Fatalf here will not stop the main test,
				// because it is running in a different goroutine than the one executing the test.
				// Consider signaling the main test goroutine to fail instead.
				th.t.Fatalf("Adam crashed: %v", status.Err)
			}
		}
	}
}

func (th *TestHarness) runBrokerKeepAlive() {
	defer th.wg.Done()

	stream, err := th.brokerClient.KeepAlive(th.ctx)
	if err != nil {
		th.log.Errorf("KeepAlive failed: %v", err)
		return
	}

	// Send initial ping with client ID
	err = stream.Send(&api.KeepAlivePing{ClientId: th.brokerClientID})
	if err != nil {
		th.log.Errorf("Failed to send initial keepalive ping: %v", err)
		return
	}

	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	// Loop to send periodic pings and receive pongs
	for {
		select {
		case <-th.ctx.Done():
			th.log.Info("Test harness context canceled, stopping keep-alive stream")
			return
		case <-ticker.C:
			// Send ping
			err = stream.Send(&api.KeepAlivePing{ClientId: th.brokerClientID})
			if err != nil {
				th.log.Errorf("Failed to send keepalive ping: %v", err)
				return
			}
			// Receive pong
			_, err = stream.Recv()
			if err != nil {
				th.log.Errorf("Failed to receive keepalive pong: %v", err)
				return
			}
			th.log.Tracef("Received keepalive pong")
		}
	}
}

func (th *TestHarness) runBrokerLogStream() {
	defer th.wg.Done()

	req := &api.LogsRequest{ClientId: th.brokerClientID}
	stream, err := th.brokerClient.StreamLogs(th.ctx, req)
	if err != nil {
		th.log.Errorf("StreamLogs failed: %v", err)
		return
	}

	for {
		m, err := stream.Recv()
		if err == io.EOF {
			return
		}
		if err != nil {
			if th.ctx.Err() != nil {
				th.log.Info(
					"Test harness context canceled, stopping broker log stream")
				return
			}
			th.log.Errorf("Broker log stream error: %v", err)
			return
		}
		level := logger.APILogSeverityToLogrusLevel(m.Severity)
		th.brokerLog.WithTime(m.Timestamp.AsTime()).Log(level, m.Message)
	}
}

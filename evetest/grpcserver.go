// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package evetest

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	eveinfo "github.com/lf-edge/eve-api/go/info"
	evemetrics "github.com/lf-edge/eve-api/go/metrics"
	"github.com/lf-edge/eve/evetest/constants"
	api "github.com/lf-edge/eve/evetest/grpcapi/go"
	"github.com/lf-edge/eve/evetest/logger"
	"github.com/lf-edge/eve/evetest/utils"
	uuid "github.com/satori/go.uuid"
	"github.com/spf13/viper"
	"google.golang.org/grpc"
)

type infoMsgGrpcIterator[T any] struct {
	stream grpc.ServerStreamingServer[T]
	mapper func(*eveinfo.ZInfoMsg) (*T, error)
}

func (w *infoMsgGrpcIterator[T]) Iterate(msg *eveinfo.ZInfoMsg) (bool, error) {
	resp, err := w.mapper(msg)
	if err != nil {
		return false, err
	}
	return false, w.stream.Send(resp)
}

type metricMsgGrpcIterator[T any] struct {
	stream grpc.ServerStreamingServer[T]
	// mapper extracts a response from a metrics message; returns nil to skip.
	mapper func(*evemetrics.ZMetricMsg) (*T, error)
}

// syncStream wraps a gRPC server stream with a mutex so that Send can be
// called concurrently from multiple goroutines. It embeds the underlying
// stream to satisfy the full grpc.ServerStreamingServer interface.
type syncStream[T any] struct {
	grpc.ServerStream
	stream grpc.ServerStreamingServer[T]
	mu     sync.Mutex
}

func (s *syncStream[T]) Send(msg *T) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.stream.Send(msg)
}

func (w *metricMsgGrpcIterator[T]) Iterate(msg *evemetrics.ZMetricMsg) (bool, error) {
	resp, err := w.mapper(msg)
	if err != nil {
		return false, err
	}
	if resp == nil {
		return false, nil
	}
	return false, w.stream.Send(resp)
}

func (th *TestHarness) errIfBrokerNotReady() error {
	if th.brokerClientID == "" {
		return errors.New("broker is not yet connected")
	}
	return nil
}

func (th *TestHarness) errIfAdamNotReady() error {
	if th.adamClient == nil {
		return errors.New("controller (Adam) is not yet initialized")
	}
	return nil
}

// Continue test execution until the end/failure or another checkpoint.
func (th *TestHarness) Continue(
	ctx context.Context, req *api.ContinueRequest) (*api.ContinueResponse, error) {
	th.checkpointM.Lock()
	defer th.checkpointM.Unlock()
	switch {
	case th.pausedAtCheckpoint != "":
		th.resume <- struct{}{}
		th.pausedAtCheckpoint = ""
	case th.pausedOnFailure != "":
		th.resume <- struct{}{}
		th.pausedOnFailure = ""
	}
	th.pauseAtCheckpoint = req.GetUntilCheckpoint()
	return &api.ContinueResponse{}, nil
}

// Exit the test early. If the test is paused at a checkpoint or on failure,
// it will be marked as skipped. Otherwise, the process is terminated with
// os.Exit(0).
func (th *TestHarness) Exit(
	ctx context.Context, req *api.ExitRequest) (*api.ExitResponse, error) {
	th.log.Info("Exit requested via CLI")
	th.checkpointM.Lock()
	paused := th.pausedAtCheckpoint != "" || th.pausedOnFailure != ""
	th.checkpointM.Unlock()
	if paused {
		// Unblock the test goroutine.
		close(th.exitCh)
	} else {
		// Test is actively running — no clean way to interrupt it.
		// Schedule process exit after a short delay to allow the gRPC
		// response to be sent back to the CLI.
		go func() {
			time.Sleep(100 * time.Millisecond)
			os.Exit(0)
		}()
	}
	return &api.ExitResponse{}, nil
}

// Status returns current test execution state and active devices.
func (th *TestHarness) Status(
	ctx context.Context, req *api.StatusRequest) (*api.StatusResponse, error) {
	// Determine test/suite name.
	var testName string
	var suiteName string
	th.testM.Lock()
	if th.suite != nil {
		suiteName = th.suite.name
	}
	testName = th.test.name
	th.testM.Unlock()

	// Collect the specifications of all deployed EVE devices.
	var eveDevices []*api.EVEDeviceStatus
	th.devicesM.Lock()
	for _, dev := range th.devices {
		eveDevices = append(eveDevices, &api.EVEDeviceStatus{
			Spec:       dev.spec,
			State:      dev.state,
			Interfaces: dev.interfaces,
		})
	}
	th.devicesM.Unlock()

	// Determine current checkpoint/failure.
	th.checkpointM.Lock()
	checkpoint := th.pausedAtCheckpoint
	failure := th.pausedOnFailure
	th.checkpointM.Unlock()

	return &api.StatusResponse{
		EvetestVersion:    viper.GetString(constants.VersionEnv),
		TestName:          testName,
		TestSuiteName:     suiteName,
		EveDevices:        eveDevices,
		Paused:            checkpoint != "" || failure != "",
		CurrentCheckpoint: checkpoint,
		TestFailure:       failure,
	}, nil
}

// HardRebootEVEDevice forces immediate power cycle of the EVE device.
func (th *TestHarness) HardRebootEVEDevice(
	ctx context.Context, req *api.EVEDeviceRequest) (*api.EVERebootResponse, error) {
	if err := th.errIfBrokerNotReady(); err != nil {
		return nil, err
	}
	devName, _, err := th.resolveEVEDeviceName(req.GetDeviceName())
	if err != nil {
		return nil, err
	}
	th.incExpectedRebootCount(devName)
	th.collectCoverageFromDevice(ctx, devName)
	_, err = th.brokerClient.RebootDevice(ctx, &api.DeviceControlRequest{
		ClientId:   th.brokerClientID,
		DeviceName: devName,
	})
	return &api.EVERebootResponse{}, err
}

// SoftRebootEVEDevice request a clean OS-level reboot on the EVE device.
func (th *TestHarness) SoftRebootEVEDevice(
	ctx context.Context, req *api.EVEDeviceRequest) (*api.EVERebootResponse, error) {
	devName, _, err := th.resolveEVEDeviceName(req.GetDeviceName())
	if err != nil {
		return nil, err
	}
	th.incExpectedRebootCount(devName)
	th.collectCoverageFromDevice(ctx, devName)
	err = th.runScriptOnEVEOverSSH(ctx, devName, "reboot", nil, nil, 0)
	return &api.EVERebootResponse{}, err
}

// GetEVEConfig fetches the current configuration submitted to the EVE device.
func (th *TestHarness) GetEVEConfig(
	ctx context.Context, req *api.EVEDeviceRequest) (*api.EVEConfigResponse, error) {
	th.devicesM.Lock()
	defer th.devicesM.Unlock()
	devName, _, err := th.resolveEVEDeviceNameLocked(req.GetDeviceName())
	if err != nil {
		return nil, err
	}
	if th.devices[devName].config == nil {
		return nil, fmt.Errorf("no config submitted for device %s", devName)
	}
	config := th.devices[devName].config.EdgeDevConfig
	return &api.EVEConfigResponse{Config: config}, nil
}

// GetEVEInfo streams real-time system info from EVE device (ZInfoDevice).
func (th *TestHarness) GetEVEInfo(
	req *api.EVEDeviceStreamableRequest, stream api.Evetest_GetEVEInfoServer) error {
	if err := th.errIfAdamNotReady(); err != nil {
		return err
	}
	devName, devUUID, err := th.resolveEVEDeviceName(req.GetDeviceName())
	if err != nil {
		return err
	}
	if devUUID == uuid.Nil {
		return fmt.Errorf("device %q is not onboarded", devName)
	}
	matcher := func(msg *eveinfo.ZInfoMsg) bool {
		return msg.GetZtype() == eveinfo.ZInfoTypes_ZiDevice &&
			msg.GetDinfo() != nil
	}
	iterator := &infoMsgGrpcIterator[api.EVEInfoResponse]{
		stream: stream,
		mapper: func(msg *eveinfo.ZInfoMsg) (*api.EVEInfoResponse, error) {
			return &api.EVEInfoResponse{
				DeviceInfo: msg.GetDinfo(),
			}, nil
		},
	}
	return th.adamClient.IterateDeviceInfoMsgs(stream.Context(), devUUID, matcher,
		iterator, req.GetFollow())
}

// GetEVEMetrics streams real-time metrics from EVE device (deviceMetric).
func (th *TestHarness) GetEVEMetrics(
	req *api.EVEDeviceStreamableRequest, stream api.Evetest_GetEVEMetricsServer) error {
	if err := th.errIfAdamNotReady(); err != nil {
		return err
	}
	devName, devUUID, err := th.resolveEVEDeviceName(req.GetDeviceName())
	if err != nil {
		return err
	}
	if devUUID == uuid.Nil {
		return fmt.Errorf("device %q is not onboarded", devName)
	}
	iterator := &metricMsgGrpcIterator[api.EVEMetricsResponse]{
		stream: stream,
		mapper: func(msg *evemetrics.ZMetricMsg) (*api.EVEMetricsResponse, error) {
			dm := msg.GetDm()
			if dm == nil {
				return nil, nil
			}
			return &api.EVEMetricsResponse{DeviceMetrics: dm}, nil
		},
	}
	return th.adamClient.IterateDeviceMetrics(
		stream.Context(), devUUID, iterator, req.GetFollow())
}

// GetEVELogs streams logs from EVE device (agent logs, kernel logs, etc).
func (th *TestHarness) GetEVELogs(
	req *api.EVEDeviceStreamableRequest, stream api.Evetest_GetEVELogsServer) error {
	if err := th.errIfAdamNotReady(); err != nil {
		return err
	}
	devName, devUUID, err := th.resolveEVEDeviceName(req.GetDeviceName())
	if err != nil {
		return err
	}
	if devUUID == uuid.Nil {
		return fmt.Errorf("device %q is not onboarded", devName)
	}
	logIterator := &logger.GrpcDeviceLogStreamer{Stream: stream}
	return th.adamClient.IterateDeviceLogs(
		stream.Context(), devUUID, nil, logIterator, req.GetFollow())
}

// GetEVEConsoleOutput returns the full console output from the EVE device.
func (th *TestHarness) GetEVEConsoleOutput(
	ctx context.Context, req *api.EVEDeviceRequest) (*api.ConsoleOutputResponse, error) {
	if err := th.errIfBrokerNotReady(); err != nil {
		return nil, err
	}
	devName, _, err := th.resolveEVEDeviceName(req.GetDeviceName())
	if err != nil {
		return nil, err
	}
	return th.brokerClient.GetDeviceConsoleOutput(ctx, &api.DeviceControlRequest{
		ClientId:   th.brokerClientID,
		DeviceName: devName,
	})
}

// GetAppInfo streams application-specific info from a device (ZInfoApp).
func (th *TestHarness) GetAppInfo(
	req *api.AppRequest, stream api.Evetest_GetAppInfoServer) error {
	if err := th.errIfAdamNotReady(); err != nil {
		return err
	}
	devName, devUUID, err := th.resolveEVEDeviceName(req.GetDeviceName())
	if err != nil {
		return err
	}
	if devUUID == uuid.Nil {
		return fmt.Errorf("device %q is not onboarded", devName)
	}
	matcher := func(msg *eveinfo.ZInfoMsg) bool {
		if msg.GetZtype() != eveinfo.ZInfoTypes_ZiApp {
			return false
		}
		appInfo := msg.GetAinfo()
		if appInfo == nil {
			return false
		}
		return appInfo.GetAppID() == req.GetAppNameOrUuid() ||
			appInfo.GetAppName() == req.GetAppNameOrUuid()
	}
	iterator := &infoMsgGrpcIterator[api.AppInfoResponse]{
		stream: stream,
		mapper: func(msg *eveinfo.ZInfoMsg) (*api.AppInfoResponse, error) {
			return &api.AppInfoResponse{
				AppInfo: msg.GetAinfo(),
			}, nil
		},
	}
	return th.adamClient.IterateDeviceInfoMsgs(stream.Context(), devUUID, matcher,
		iterator, req.GetFollow())
}

// GetAppMetrics streams application-level metrics from a device (appMetric).
func (th *TestHarness) GetAppMetrics(
	req *api.AppRequest, stream api.Evetest_GetAppMetricsServer) error {
	if err := th.errIfAdamNotReady(); err != nil {
		return err
	}
	devName, devUUID, err := th.resolveEVEDeviceName(req.GetDeviceName())
	if err != nil {
		return err
	}
	if devUUID == uuid.Nil {
		return fmt.Errorf("device %q is not onboarded", devName)
	}
	appNameOrUUID := req.GetAppNameOrUuid()
	iterator := &metricMsgGrpcIterator[api.AppMetricsResponse]{
		stream: stream,
		mapper: func(msg *evemetrics.ZMetricMsg) (*api.AppMetricsResponse, error) {
			for _, am := range msg.GetAm() {
				if am.GetAppID() == appNameOrUUID || am.GetAppName() == appNameOrUUID {
					return &api.AppMetricsResponse{AppMetrics: am}, nil
				}
			}
			return nil, nil
		},
	}
	return th.adamClient.IterateDeviceMetrics(
		stream.Context(), devUUID, iterator, req.GetFollow())
}

// GetAppLogs streams logs from an EVE-managed application.
func (th *TestHarness) GetAppLogs(
	req *api.AppRequest, stream api.Evetest_GetAppLogsServer) error {
	if err := th.errIfAdamNotReady(); err != nil {
		return err
	}
	devName, devUUID, err := th.resolveEVEDeviceName(req.GetDeviceName())
	if err != nil {
		return err
	}
	if devUUID == uuid.Nil {
		return fmt.Errorf("device %q is not onboarded", devName)
	}
	appUUID, err := th.resolveAppUUID(stream.Context(), devUUID, req.GetAppNameOrUuid())
	if err != nil {
		return err
	}
	logIterator := &logger.GrpcDeviceLogStreamer{Stream: stream}
	return th.adamClient.IterateAppLogs(
		stream.Context(), devUUID, appUUID, nil, logIterator, req.GetFollow())
}

// GetAppFlowLogs streams flow logs and DNS request logs for an application.
func (th *TestHarness) GetAppFlowLogs(
	req *api.AppRequest, stream api.Evetest_GetAppFlowLogsServer) error {
	// TODO
	return errors.New("not implemented")
}

// GetNIInfo streams info (ZInfoNetworkInstance) about a network instance (NI).
func (th *TestHarness) GetNIInfo(
	req *api.NIRequest, stream api.Evetest_GetNIInfoServer) error {
	if err := th.errIfAdamNotReady(); err != nil {
		return err
	}
	devName, devUUID, err := th.resolveEVEDeviceName(req.GetDeviceName())
	if err != nil {
		return err
	}
	if devUUID == uuid.Nil {
		return fmt.Errorf("device %q is not onboarded", devName)
	}
	matcher := func(msg *eveinfo.ZInfoMsg) bool {
		if msg.GetZtype() != eveinfo.ZInfoTypes_ZiNetworkInstance {
			return false
		}
		niInfo := msg.GetNiinfo()
		if niInfo == nil {
			return false
		}
		return niInfo.GetNetworkID() == req.GetNiNameOrUuid() ||
			niInfo.GetDisplayname() == req.GetNiNameOrUuid()
	}
	iterator := &infoMsgGrpcIterator[api.NIInfoResponse]{
		stream: stream,
		mapper: func(msg *eveinfo.ZInfoMsg) (*api.NIInfoResponse, error) {
			return &api.NIInfoResponse{
				NiInfo: msg.GetNiinfo(),
			}, nil
		},
	}
	return th.adamClient.IterateDeviceInfoMsgs(stream.Context(), devUUID, matcher,
		iterator, req.GetFollow())
}

// GetNIMetrics streams metrics (ZMetricNetworkInstance) for a network instance.
func (th *TestHarness) GetNIMetrics(
	req *api.NIRequest, stream api.Evetest_GetNIMetricsServer) error {
	if err := th.errIfAdamNotReady(); err != nil {
		return err
	}
	devName, devUUID, err := th.resolveEVEDeviceName(req.GetDeviceName())
	if err != nil {
		return err
	}
	if devUUID == uuid.Nil {
		return fmt.Errorf("device %q is not onboarded", devName)
	}
	niNameOrUUID := req.GetNiNameOrUuid()
	iterator := &metricMsgGrpcIterator[api.NIMetricsResponse]{
		stream: stream,
		mapper: func(msg *evemetrics.ZMetricMsg) (*api.NIMetricsResponse, error) {
			for _, nm := range msg.GetNm() {
				if nm.GetNetworkID() == niNameOrUUID || nm.GetDisplayname() == niNameOrUUID {
					return &api.NIMetricsResponse{NiMetrics: nm}, nil
				}
			}
			return nil, nil
		},
	}
	return th.adamClient.IterateDeviceMetrics(
		stream.Context(), devUUID, iterator, req.GetFollow())
}

// GetClusterInfo streams summary information for the entire Kubernetes cluster
// from all devices.
func (th *TestHarness) GetClusterInfo(
	req *api.ClusterRequest, stream api.Evetest_GetClusterInfoServer) error {
	if err := th.errIfAdamNotReady(); err != nil {
		return err
	}
	devices := th.getOnboardedDevices()
	if len(devices) == 0 {
		return fmt.Errorf("no device is onboarded")
	}
	matcher := func(msg *eveinfo.ZInfoMsg) bool {
		return msg.GetZtype() == eveinfo.ZInfoTypes_ZiKubeCluster &&
			msg.GetClusterInfo() != nil
	}
	safeStream := &syncStream[api.ClusterInfoResponse]{stream: stream}
	ctx, cancel := context.WithCancel(stream.Context())
	defer cancel()
	errCh := make(chan error, len(devices))
	for devName, devUUID := range devices {
		go func(devName string, devUUID uuid.UUID) {
			iterator := &infoMsgGrpcIterator[api.ClusterInfoResponse]{
				stream: safeStream,
				mapper: func(msg *eveinfo.ZInfoMsg) (*api.ClusterInfoResponse, error) {
					return &api.ClusterInfoResponse{
						ClusterInfo: msg.GetClusterInfo(),
						FromNode:    devName,
					}, nil
				},
			}
			errCh <- th.adamClient.IterateDeviceInfoMsgs(
				ctx, devUUID, matcher, iterator, req.GetFollow())
		}(devName, devUUID)
	}
	return waitForParallelStreams(ctx, cancel, errCh, len(devices))
}

// GetClusterUpdateInfo streams information about ongoing cluster updates.
func (th *TestHarness) GetClusterUpdateInfo(
	req *api.ClusterRequest, stream api.Evetest_GetClusterUpdateInfoServer) error {
	if err := th.errIfAdamNotReady(); err != nil {
		return err
	}
	devices := th.getOnboardedDevices()
	if len(devices) == 0 {
		return fmt.Errorf("no device is onboarded")
	}
	matcher := func(msg *eveinfo.ZInfoMsg) bool {
		return msg.GetZtype() == eveinfo.ZInfoTypes_ZiKubeClusterUpdateStatus &&
			msg.GetClusterUpdateInfo() != nil
	}
	safeStream := &syncStream[api.ClusterUpdateInfoResponse]{stream: stream}
	ctx, cancel := context.WithCancel(stream.Context())
	defer cancel()
	errCh := make(chan error, len(devices))
	for devName, devUUID := range devices {
		go func(devName string, devUUID uuid.UUID) {
			iterator := &infoMsgGrpcIterator[api.ClusterUpdateInfoResponse]{
				stream: safeStream,
				mapper: func(msg *eveinfo.ZInfoMsg) (*api.ClusterUpdateInfoResponse, error) {
					return &api.ClusterUpdateInfoResponse{
						ClusterUpdateInfo: msg.GetClusterUpdateInfo(),
						FromNode:          devName,
					}, nil
				},
			}
			errCh <- th.adamClient.IterateDeviceInfoMsgs(
				ctx, devUUID, matcher, iterator, req.GetFollow())
		}(devName, devUUID)
	}
	return waitForParallelStreams(ctx, cancel, errCh, len(devices))
}

// GetClusterMetrics streams metrics for the Kubernetes cluster (KubeClusterMetrics)
// from all devices.
func (th *TestHarness) GetClusterMetrics(
	req *api.ClusterRequest, stream api.Evetest_GetClusterMetricsServer) error {
	devices := th.getOnboardedDevices()
	if len(devices) == 0 {
		return fmt.Errorf("no device is onboarded")
	}
	if err := th.errIfAdamNotReady(); err != nil {
		return err
	}
	safeStream := &syncStream[api.ClusterMetricsResponse]{stream: stream}
	ctx, cancel := context.WithCancel(stream.Context())
	defer cancel()
	errCh := make(chan error, len(devices))
	for devName, devUUID := range devices {
		go func(devName string, devUUID uuid.UUID) {
			iterator := &metricMsgGrpcIterator[api.ClusterMetricsResponse]{
				stream: safeStream,
				mapper: func(msg *evemetrics.ZMetricMsg) (*api.ClusterMetricsResponse, error) {
					cm := msg.GetCm()
					if cm == nil {
						return nil, nil
					}
					return &api.ClusterMetricsResponse{
						ClusterMetrics: cm,
						FromNode:       devName,
					}, nil
				},
			}
			errCh <- th.adamClient.IterateDeviceMetrics(
				ctx, devUUID, iterator, req.GetFollow())
		}(devName, devUUID)
	}
	return waitForParallelStreams(ctx, cancel, errCh, len(devices))
}

// getOnboardedDevices returns a map of device name to UUID for all onboarded devices.
func (th *TestHarness) getOnboardedDevices() map[string]uuid.UUID {
	th.devicesM.Lock()
	defer th.devicesM.Unlock()
	devices := make(map[string]uuid.UUID)
	for devName, devState := range th.devices {
		if devState.ID != uuid.Nil {
			devices[devName] = devState.ID
		}
	}
	return devices
}

// waitForParallelStreams waits for all goroutines to finish and returns the
// first non-nil, non-context-canceled error. If any goroutine fails, the
// context is canceled to stop the others.
func waitForParallelStreams(ctx context.Context, cancel context.CancelFunc,
	errCh <-chan error, count int) error {
	var firstErr error
	for i := 0; i < count; i++ {
		if err := <-errCh; err != nil && firstErr == nil {
			if ctx.Err() == nil {
				firstErr = err
				cancel()
			}
		}
	}
	return firstErr
}

// resolveAppUUID parses appNameOrUUID as a UUID.
// If it is not a valid UUID, it iterates historical info messages for devUUID
// to find an app whose name matches, and returns that app's UUID.
func (th *TestHarness) resolveAppUUID(
	ctx context.Context, devUUID uuid.UUID, appNameOrUUID string) (uuid.UUID, error) {
	if appUUID, err := uuid.FromString(appNameOrUUID); err == nil {
		return appUUID, nil
	}
	// Name lookup: iterate historical app info messages.
	var found uuid.UUID
	err := th.adamClient.IterateDeviceInfoMsgs(ctx, devUUID,
		func(msg *eveinfo.ZInfoMsg) bool {
			return msg.GetZtype() == eveinfo.ZInfoTypes_ZiApp
		},
		infoMsgIterFn(func(msg *eveinfo.ZInfoMsg) (bool, error) {
			ainfo := msg.GetAinfo()
			if ainfo.GetAppName() == appNameOrUUID {
				if id, err := uuid.FromString(ainfo.GetAppID()); err == nil {
					found = id
					return true, nil
				}
			}
			return false, nil
		}),
		false,
	)
	if err != nil {
		return uuid.Nil, fmt.Errorf("failed to look up app %q: %w", appNameOrUUID, err)
	}
	if found == uuid.Nil {
		return uuid.Nil, fmt.Errorf("app %q not found on device", appNameOrUUID)
	}
	return found, nil
}

// CollectInfo retrieves debug information from a device (eve-info tarball).
func (th *TestHarness) CollectInfo(
	ctx context.Context, req *api.EVEDeviceRequest) (*api.CollectInfoResponse, error) {
	artifactHostDir := viper.GetString(constants.ExternalArtifactDirEnv)
	if artifactHostDir == "" {
		return nil, fmt.Errorf(
			"%s is not defined: no artifact directory is mounted into the evetest "+
				"container, so collect-info output cannot be shared with the host",
			constants.EnvPrefix+constants.ExternalArtifactDirEnv,
		)
	}

	devName, _, err := th.resolveEVEDeviceName(req.GetDeviceName())
	if err != nil {
		return nil, err
	}

	// collectInfoFromDevice returns the artifact path inside the container,
	// i.e. under /artifacts
	outputFileContainer, err := th.collectInfoFromDevice(ctx, devName)
	if err != nil {
		return nil, err
	}

	// Translate container artifact path to host path.
	// The evetest container mounts:
	//   -v $(EVETEST_COLLECT_ARTIFACTS):/artifacts
	const artifactContainerDir = "/artifacts/"
	if !strings.HasPrefix(outputFileContainer, artifactContainerDir) {
		return nil, fmt.Errorf("unexpected artifact path %q (expected under %q)",
			outputFileContainer, artifactContainerDir,
		)
	}

	outputFileHost := filepath.Join(
		artifactHostDir, strings.TrimPrefix(outputFileContainer, artifactContainerDir))
	return &api.CollectInfoResponse{
		ArtifactPath: outputFileHost,
	}, nil
}

// ConnectTunnelToEVE carries a single TCP connection to an EVE device port over gRPC.
// The client sends an EVETunnelConnect as the first message; the server dials EVE,
// replies with TunnelConnected, then relays raw bytes bidirectionally.
func (th *TestHarness) ConnectTunnelToEVE(
	stream api.Evetest_ConnectTunnelToEVEServer) error {
	msg, err := stream.Recv()
	if err != nil {
		return fmt.Errorf("failed to receive connect request: %w", err)
	}
	connectReq := msg.GetConnect()
	if connectReq == nil {
		return fmt.Errorf("first message must be a connect request")
	}

	devName, _, err := th.resolveEVEDeviceName(connectReq.GetDeviceName())
	if err != nil {
		return err
	}
	targetPort := connectReq.GetTargetPort()
	if targetPort == 0 {
		return fmt.Errorf("target_port must be specified")
	}

	eveIP, err := th.getReachableEVEAddr(
		stream.Context(), devName, targetPort, connectReq.GetInterfaceName())
	if err != nil {
		return fmt.Errorf("unable to reach EVE device %q port %d: %w",
			devName, targetPort, err)
	}

	dialer := net.Dialer{}
	eveConn, err := dialer.DialContext(
		stream.Context(), "tcp",
		net.JoinHostPort(eveIP, fmt.Sprintf("%d", targetPort)))
	if err != nil {
		return fmt.Errorf("failed to connect to EVE device %q port %d: %w",
			devName, targetPort, err)
	}
	defer eveConn.Close()
	th.log.Debugf("Connected to EVE device %q port %d", devName, targetPort)

	if err := stream.Send(&api.ConnectTunnelToEVEResponse{
		Payload: &api.ConnectTunnelToEVEResponse_Connected{
			Connected: &api.TunnelConnected{},
		},
	}); err != nil {
		return fmt.Errorf("failed to send connected response: %w", err)
	}

	grpcPipe := utils.GrpcServerPipe[
		api.ConnectTunnelToEVERequest, api.ConnectTunnelToEVEResponse]{
		MakeResponse: func(data []byte) *api.ConnectTunnelToEVEResponse {
			return &api.ConnectTunnelToEVEResponse{
				Payload: &api.ConnectTunnelToEVEResponse_Data{Data: data},
			}
		},
		Stream: stream,
	}
	evePipe := utils.ReadWriterPipe{
		PipeName: "EVE TCP connection",
		RW:       eveConn,
		Buf:      make([]byte, os.Getpagesize()),
	}
	proxyLog := th.log.WithField("component", "tunnel-to-eve")
	// Derive a context cancelled by either the stream ending or test teardown
	// (th.ctx). Using stream.Context() alone would deadlock Close(): GracefulStop
	// waits for all streams to finish, but stream.Context() is only cancelled
	// once the server has stopped — a circular dependency.
	proxyCtx, proxyCancel := context.WithCancel(stream.Context())
	defer proxyCancel()
	go func() {
		select {
		case <-th.ctx.Done():
			proxyCancel()
		case <-proxyCtx.Done():
		}
	}()
	utils.RunPipeProxy(proxyCtx, proxyLog, "EVE TCP tunnel", grpcPipe, evePipe)
	return nil
}

// ConnectConsoleToEVE carries an interactive serial-console session over gRPC.
// The client sends an EVEDeviceRequest as the first message; the server opens a
// broker console stream, forwards ConsoleProperties, then relays raw bytes
// bidirectionally between the CLI and the broker.
func (th *TestHarness) ConnectConsoleToEVE(
	stream api.Evetest_ConnectConsoleToEVEServer) error {
	if err := th.errIfBrokerNotReady(); err != nil {
		return err
	}

	msg, err := stream.Recv()
	if err != nil {
		return fmt.Errorf("failed to receive connect request: %w", err)
	}
	connectReq := msg.GetConnect()
	if connectReq == nil {
		return fmt.Errorf("first message must be a connect request")
	}

	th.devicesM.Lock()
	devName, _, err := th.resolveEVEDeviceNameLocked(connectReq.GetDeviceName())
	if err != nil {
		th.devicesM.Unlock()
		return err
	}
	if th.devices[devName].consoleInUse {
		th.devicesM.Unlock()
		return fmt.Errorf("EVE device %q console is already being used", devName)
	}
	th.devices[devName].consoleInUse = true
	th.devicesM.Unlock()
	defer func() {
		th.devicesM.Lock()
		th.devices[devName].consoleInUse = false
		th.devicesM.Unlock()
	}()

	brokerStream, err := th.brokerClient.ConnectConsoleToDevice(th.ctx)
	if err != nil {
		return fmt.Errorf("ConnectConsoleToDevice failed: %w", err)
	}
	defer brokerStream.CloseSend()

	if err := brokerStream.Send(&api.ConnectConsoleRequest{
		Payload: &api.ConnectConsoleRequest_Connect{
			Connect: &api.DeviceControlRequest{
				ClientId:   th.brokerClientID,
				DeviceName: devName,
			},
		},
	}); err != nil {
		return fmt.Errorf("failed to send connect request to broker: %w", err)
	}

	resp, err := brokerStream.Recv()
	if err != nil {
		return fmt.Errorf("failed to receive console properties from broker: %w", err)
	}
	props := resp.GetConnectReply()
	if props != nil {
		th.log.Infof("Connected to EVE device %q console (echoed=%v, telnet=%v)",
			devName, props.Echoed, props.Telnet)
	}

	if err := stream.Send(&api.ConnectConsoleToEVEResponse{
		Payload: &api.ConnectConsoleToEVEResponse_ConnectReply{
			ConnectReply: &api.ConsoleProperties{
				Echoed: props.GetEchoed(),
				Telnet: props.GetTelnet(),
			},
		},
	}); err != nil {
		return fmt.Errorf("failed to send console properties to CLI: %w", err)
	}

	cliPipe := utils.GrpcServerPipe[
		api.ConnectConsoleToEVERequest, api.ConnectConsoleToEVEResponse]{
		MakeResponse: func(data []byte) *api.ConnectConsoleToEVEResponse {
			return &api.ConnectConsoleToEVEResponse{
				Payload: &api.ConnectConsoleToEVEResponse_Data{Data: data},
			}
		},
		Stream: stream,
	}
	brokerPipe := utils.GrpcClientPipe[
		api.ConnectConsoleRequest, api.ConnectConsoleResponse]{
		MakeRequest: func(data []byte) *api.ConnectConsoleRequest {
			return &api.ConnectConsoleRequest{
				Payload: &api.ConnectConsoleRequest_Data{Data: data},
			}
		},
		Stream: brokerStream,
	}
	proxyLog := th.log.WithField("component", "eve-console")
	// Derive a context cancelled by either the stream ending or test teardown
	// (th.ctx). Using stream.Context() alone would deadlock Close(): GracefulStop
	// waits for all streams to finish, but stream.Context() is only cancelled
	// once the server has stopped — a circular dependency.
	proxyCtx, proxyCancel := context.WithCancel(stream.Context())
	defer proxyCancel()
	go func() {
		select {
		case <-th.ctx.Done():
			proxyCancel()
		case <-proxyCtx.Done():
		}
	}()
	utils.RunPipeProxy(proxyCtx, proxyLog, "EVE console", cliPipe, brokerPipe)
	return nil
}

// GetSDNStatus returns the overall SDN (network emulator) status.
func (th *TestHarness) GetSDNStatus(
	ctx context.Context, req *api.SDNRequest) (*api.SDNStatusResponse, error) {
	if th.sdnClient == nil {
		return nil, errors.New("SDN client is not initialized")
	}
	return th.sdnClient.GetStatus(ctx, req)
}

// GetSDNNetworkModel returns the SDN's abstract model of the network.
func (th *TestHarness) GetSDNNetworkModel(
	ctx context.Context, req *api.SDNRequest) (*api.SDNGetNetworkModelResponse, error) {
	if th.sdnClient == nil {
		return nil, errors.New("SDN client is not initialized")
	}
	return th.sdnClient.GetNetworkModel(ctx, req)
}

// GetSDNConfigGraph returns the SDN configuration visualized as a Graphviz
// dot-formatted graph.
func (th *TestHarness) GetSDNConfigGraph(
	ctx context.Context, req *api.SDNRequest) (*api.SDNConfigGraphResponse, error) {
	if th.sdnClient == nil {
		return nil, errors.New("SDN client is not initialized")
	}
	return th.sdnClient.GetConfigGraph(ctx, req)
}

// StreamSDNLogs streams logs from the SDN VM to the gRPC client.
// This method acts as a simple forwarder: it subscribes to the SDN log stream
// and relays all received log messages to the caller over the gRPC stream.
// If the SDN client is not initialized, an error is returned.
// The stream will terminate when either the SDN closes the stream
// (EOF) or the context is canceled.
func (th *TestHarness) StreamSDNLogs(
	req *api.SDNRequest, stream api.Evetest_StreamSDNLogsServer) error {
	if th.sdnClient == nil {
		return errors.New("SDN client is not initialized")
	}

	// Start SDN log stream.
	sdnStream, err := th.sdnClient.StreamLogs(stream.Context(), req)
	if err != nil {
		return fmt.Errorf("failed to start SDN log stream: %v", err)
	}

	// Forward each SDN log message to the gRPC client.
	for {
		m, recvErr := sdnStream.Recv()
		if recvErr == io.EOF {
			// SDN stream closed cleanly.
			return nil
		}
		if recvErr != nil {
			return fmt.Errorf("error receiving SDN log: %w", recvErr)
		}

		if sendErr := stream.Send(m); sendErr != nil {
			return fmt.Errorf("error sending SDN log over gRPC: %w", sendErr)
		}
	}
}

// ConnectTunnelToSDN carries a TCP connection to the SDN SSH port over gRPC.
// The client sends an SDNRequest as the first message; the server dials the SDN
// SSH endpoint, replies with TunnelConnected, then relays raw bytes bidirectionally.
func (th *TestHarness) ConnectTunnelToSDN(
	stream api.Evetest_ConnectTunnelToSDNServer) error {
	msg, err := stream.Recv()
	if err != nil {
		return fmt.Errorf("failed to receive connect request: %w", err)
	}
	if msg.GetConnect() == nil {
		return fmt.Errorf("first message must be a connect request")
	}

	dialer := net.Dialer{}
	sdnConn, err := dialer.DialContext(
		stream.Context(), "tcp", net.JoinHostPort(sdnTunVMIPv4.String(), "22"))
	if err != nil {
		return fmt.Errorf("failed to connect to SDN SSH endpoint %s:22: %w",
			sdnTunVMIPv4, err)
	}
	defer sdnConn.Close()
	th.log.Debugf("Connected to SDN SSH endpoint %s:22", sdnTunVMIPv4)

	if err := stream.Send(&api.ConnectSSHTunnelToSDNResponse{
		Payload: &api.ConnectSSHTunnelToSDNResponse_Connected{
			Connected: &api.TunnelConnected{},
		},
	}); err != nil {
		return fmt.Errorf("failed to send connected response: %w", err)
	}

	grpcPipe := utils.GrpcServerPipe[
		api.ConnectSSHTunnelToSDNRequest, api.ConnectSSHTunnelToSDNResponse]{
		MakeResponse: func(data []byte) *api.ConnectSSHTunnelToSDNResponse {
			return &api.ConnectSSHTunnelToSDNResponse{
				Payload: &api.ConnectSSHTunnelToSDNResponse_Data{Data: data},
			}
		},
		Stream: stream,
	}
	sdnPipe := utils.ReadWriterPipe{
		PipeName: "SDN SSH connection",
		RW:       sdnConn,
		Buf:      make([]byte, os.Getpagesize()),
	}
	proxyLog := th.log.WithField("component", "sdn-ssh-tunnel")
	// Same teardown fix as ConnectTunnelToEVE: merge stream and test contexts.
	proxyCtx, proxyCancel := context.WithCancel(stream.Context())
	defer proxyCancel()
	go func() {
		select {
		case <-th.ctx.Done():
			proxyCancel()
		case <-proxyCtx.Done():
		}
	}()
	utils.RunPipeProxy(proxyCtx, proxyLog, "SDN SSH tunnel", grpcPipe, sdnPipe)
	return nil
}

// resolveEVEDeviceName validates and resolves the target EVE device name.
// If devName is empty and exactly one device is onboarded, that device is selected.
// If multiple devices are onboarded, devName must be provided and must match
// one of the onboarded devices.
func (th *TestHarness) resolveEVEDeviceName(devName string) (string, uuid.UUID, error) {
	th.devicesM.Lock()
	defer th.devicesM.Unlock()
	return th.resolveEVEDeviceNameLocked(devName)
}

// resolveEVEDeviceNameLocked resolves the target EVE device name assuming
// that th.devicesM is already held by the caller.
//
// It returns the resolved device name and its UUID.
// The caller MUST hold th.devicesM before invoking this method.
func (th *TestHarness) resolveEVEDeviceNameLocked(
	devName string) (string, uuid.UUID, error) {
	if devName != "" {
		if dev, found := th.devices[devName]; found {
			return devName, dev.ID, nil
		}
		return "", uuid.Nil, fmt.Errorf("unknown EVE device %q", devName)
	}

	if len(th.devices) > 1 {
		return "", uuid.Nil, fmt.Errorf(
			"multiple EVE devices are onboarded; device name must be specified",
		)
	}

	for name, dev := range th.devices {
		return name, dev.ID, nil
	}

	// No devices at all
	return "", uuid.Nil, fmt.Errorf("no EVE devices are currently onboarded")
}

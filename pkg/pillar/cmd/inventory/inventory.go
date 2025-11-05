// Copyright (c) 2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package inventory

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/containerd/containerd/protobuf/proto"
	"github.com/jaypipes/ghw"
	"github.com/jaypipes/ghw/pkg/option"
	"github.com/jaypipes/ghw/pkg/pci/address"
	"github.com/jaypipes/pcidb"
	pcitypes "github.com/jaypipes/pcidb/types"
	"github.com/lf-edge/eve-api/go/hardwareinventory"
	"github.com/lf-edge/eve/pkg/pillar/agentbase"
	"github.com/lf-edge/eve/pkg/pillar/agentlog"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/containerd"
	"github.com/lf-edge/eve/pkg/pillar/controllerconn"
	"github.com/lf-edge/eve/pkg/pillar/hardware"
	"github.com/lf-edge/eve/pkg/pillar/netmonitor"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
	uuid "github.com/satori/go.uuid"
	"github.com/sirupsen/logrus"
)

const (
	agentName = "inventory"
	// Time limits for event loop handlers
	errorTime            = 3 * time.Minute
	warningTime          = 40 * time.Second
	stillRunningInterval = 25 * time.Second
)

var (
	logger *logrus.Logger
	log    *base.LogObject
)

type boardingStatusType uint32

const (
	unknownStatus boardingStatusType = iota
	onboardedStatus
	offboardStatus
)

type inventoryReporter struct {
	agentbase.AgentBase
	subscriptions map[string]pubsub.Subscription
	dns           types.DeviceNetworkStatus
	agentMetrics  *controllerconn.AgentMetrics

	needUpload     atomic.Bool
	boardingStatus atomic.Uint32

	uploading sync.Mutex
}

func SetLogger(newlogger *logrus.Logger, newlog *base.LogObject) {
	logger = newlogger
	log = newlog
}

// Run - Main function
func Run(ps *pubsub.PubSub, loggerArg *logrus.Logger, logArg *base.LogObject, arguments []string, baseDir string) int {
	fmt.Fprintf(os.Stderr, "AAAAAA Run\n")
	logger = loggerArg
	log = logArg

	ir := inventoryReporter{}
	ir.needUpload.Store(true)
	ir.boardingStatus.Store(uint32(unknownStatus))
	ir.subscriptions = make(map[string]pubsub.Subscription)

	agentbase.Init(&ir, logger, log, agentName,
		agentbase.WithPidFile(),
		agentbase.WithBaseDir(baseDir),
		agentbase.WithWatchdog(ps, warningTime, errorTime),
		agentbase.WithArguments(arguments))

	// Wait until we have been onboarded aka know our own UUID, but we don't use the UUID
	// err := wait.WaitForOnboarded(ps, log, agentName, warningTime, errorTime)
	// if err != nil {
	// 	log.Fatal(err)
	// }
	// log.Functionf("processed onboarded")

	// if err := wait.WaitForVault(ps, log, agentName, warningTime, errorTime); err != nil {
	// 	log.Fatal(err)
	// }
	// log.Functionf("processed Vault Status")

	ir.agentMetrics = controllerconn.NewAgentMetrics()

	ir.subscribe(ps)

	ir.process(ps)

	return 0
}

func (ir *inventoryReporter) upload() {
	fmt.Fprintf(os.Stderr, "AAAAA upload\n")
	// if ir.boardingStatus.Load() == uint32(unknownStatus) {
	// 	fmt.Fprintf(os.Stderr, "AAAAAA unknownStatus\n")
	// 	return
	// }
	if ir.boardingStatus.Load() == uint32(onboardedStatus) {
		fmt.Fprintf(os.Stderr, "AAAAAA onboardedStatus\n")
		return
	}
	if !ir.needUpload.Load() {
		fmt.Fprintf(os.Stderr, "AAAAAA not needed\n")
		return
	}

	if !ir.uploading.TryLock() {
		fmt.Fprintf(os.Stderr, "AAAAAA ongoing\n")
		return
	}

	defer ir.uploading.Unlock()

	dnsAny, err := ir.subscriptions["deviceNetworkStatus"].Get("global")
	if err != nil {
		log.Warnf("Getting deviceNetworkStatus with key 'global' failed: %v", err)
		return
	}

	dns, ok := dnsAny.(types.DeviceNetworkStatus)
	if !ok {
		fmt.Fprintf(os.Stderr, "AAAAAA invalid DNS %T: %+v\n", dnsAny, dnsAny)
		log.Warnf("Failed to cast %v (%T) to *types.DeviceNetworkStatus", dnsAny, dnsAny)
		return
	}

	gcp := agentlog.HandleGlobalConfig(log, ir.subscriptions["globalConfig"], agentName,
		false, logger)

	timeout := gcp.GlobalValueInt(types.NetworkSendTimeout)
	dialTimeoutSecs := gcp.GlobalValueInt(types.NetworkDialTimeout)

	networkMonitor := &netmonitor.LinuxNetworkMonitor{Log: log}

	nilUUID := uuid.UUID{}
	productSerial := hardware.GetProductSerial(log)
	softSerial := hardware.GetSoftSerial(log)
	ctrlClient := controllerconn.NewClient(log, controllerconn.ClientOptions{
		AgentName:           agentName,
		NetworkMonitor:      networkMonitor,
		DeviceNetworkStatus: &dns,
		TLSConfig:           nil,
		AgentMetrics:        ir.agentMetrics,
		NetworkSendTimeout:  time.Second * time.Duration(timeout),
		NetworkDialTimeout:  time.Second * time.Duration(dialTimeoutSecs),
		DevUUID:             nilUUID,
		DevSerial:           productSerial,
		DevSoftSerial:       softSerial,
		ResolverCacheFunc:   nil,
		NoLedManager:        false,
	})
	err = ctrlClient.UpdateTLSConfig(nil)
	if err != nil {
		log.Warnf("could not update TLS config: %v", err)
	}

	server, err := types.Server()
	if err != nil {
		fmt.Fprintf(os.Stderr, "AAAAAA no server name: %+v\n", err)
		log.Warnf("could not get server name: %+v", err)
		return
	}

	inventoryURL := controllerconn.URLPath(
		server, ctrlClient.UsingV2API(), nilUUID, "inventory")

	inventoryURL.Path = filepath.Join(inventoryURL.Path, productSerial, softSerial)

	inventory, err := CreateInventory()
	if err != nil {
		log.Warnf("creating inventory message failed: %+v", err)
		return
	}
	bs, err := proto.Marshal(inventory)

	fmt.Fprintf(os.Stderr, "AAAAAA sending inventory request %+v\n", inventoryURL)
	buf := bytes.NewBuffer(bs)
	rv, err := ctrlClient.SendOnAllIntf(context.Background(), inventoryURL.String(), buf, controllerconn.RequestOptions{
		WithNetTracing: false,
		BailOnHTTPErr:  false,
		Iteration:      0,
		AllowProxy:     true,
	})
	fmt.Fprintf(os.Stderr, "AAAAA sending to %s: %v / %v\n", inventoryURL.String(), rv, err)
	if err != nil {
		log.Noticef("Posting to %s failed: %v", inventoryURL.String(), err)
		return
	}
	if rv.Status.Failure() {
		log.Noticef("Posting to %s failed, status is %v", inventoryURL.String(), rv.Status.String())
		return
	}

	ir.needUpload.Store(false)
}

type inventoryMsgCreator struct {
	msg *hardwareinventory.InventoryMsg
}

func CreateInventory() (*hardwareinventory.InventoryMsg, error) {
	imc := &inventoryMsgCreator{}

	imc.msg = &hardwareinventory.InventoryMsg{}

	errs := make(map[string]error)
	errs["PCI"] = imc.fillPCI()
	errs["USB"] = imc.fillUSB()

	var errStr string
	for key, err := range errs {
		if err != nil {
			errStr += fmt.Sprintf("failed to query for %s: %v", key, err)
		}
	}

	var err error
	if len(errStr) > 0 {
		err = fmt.Errorf("querying for hardware failed: %s", errStr)
	}

	var buf bytes.Buffer

	args := []string{"/usr/bin/spec.sh", "-v", "-u"}

	env := []string{}

	taskID := fmt.Sprintf("%d", time.Now().Unix())
	err = containerd.RunInDebugContainer(context.Background(), taskID, &buf, args, env, 15*time.Minute)
	if err != nil {
		log.Warnf("running %+v failed: %+v", args, err)
	}

	imc.msg.SpecSh = buf.String()

	return imc.msg, err
}

func stringToPCIAddress(str string) *hardwareinventory.PCIAddress {
	pciAddr := address.FromString(str)
	if pciAddr == nil {
		return nil
	}
	domain := pciHexToUint32(pciAddr.Domain)
	bus := pciHexToUint32(pciAddr.Bus)
	device := pciHexToUint32(pciAddr.Device)
	function := pciHexToUint32(pciAddr.Function)

	return &hardwareinventory.PCIAddress{
		Domain:   domain,
		Bus:      bus,
		Device:   device,
		Function: function,
	}
}

func (imc *inventoryMsgCreator) fillUSB() error {
	usbs, err := ghw.USB()
	if err != nil {
		return err
	}

	for _, usb := range usbs.USBs {
		vendorId := pciHexToUint32(usb.VendorID)
		productId := pciHexToUint32(usb.ProductID)
		busnum := pciHexToUint32(usb.Busnum)
		devnum := pciHexToUint32(usb.Devnum)
		parentBusnum := pciHexToUint32(usb.ParentBusnum)
		parentDevnum := pciHexToUint32(usb.ParentDevnum)

		ud := hardwareinventory.USBDevice{
			PciParent: stringToPCIAddress(usb.PCIAddress),
			UsbParent: &hardwareinventory.USBBusDevnum{
				Bus:    parentBusnum,
				Devnum: parentDevnum,
			},
			VendorId:  vendorId,
			ProductId: productId,
			BusDevnum: &hardwareinventory.USBBusDevnum{
				Bus:    busnum,
				Devnum: devnum,
			},
		}
		imc.msg.UsbDevices = append(imc.msg.UsbDevices, &ud)
	}

	return nil
}

func (imc *inventoryMsgCreator) fillPCI() error {
	db := pcidb.PCIDB{
		Classes:  map[string]*pcitypes.Class{},
		Vendors:  map[string]*pcitypes.Vendor{},
		Products: map[string]*pcitypes.Product{},
	}
	pcis, err := ghw.PCI(option.WithPCIDB(&db))
	if err != nil {
		return fmt.Errorf("could not retrieve PCI information: %+w", err)
	}

	for _, pci := range pcis.Devices {
		vendorId := pciHexToUint32(pci.Vendor.ID)
		if vendorId == 0 {
			continue
		}
		productId := pciHexToUint32(pci.Product.ID)
		if productId == 0 {
			continue
		}
		revisionId := pciHexToUint32(pci.Revision)
		subsystemId := pciHexToUint32(pci.Subsystem.ID)
		classId := pciHexToUint32(pci.Class.ID)

		imc.msg.PciDevices = append(imc.msg.PciDevices, &hardwareinventory.PCIDevice{
			ParentPciDeviceAddress: stringToPCIAddress(pci.ParentAddress),
			Driver:                 pci.Driver,
			Address:                stringToPCIAddress(pci.Address),
			VendorId:               vendorId,
			DeviceId:               productId,
			Revision:               revisionId,
			SubsystemId:            subsystemId,
			ClassId:                classId,
			IommuGroup:             pci.IOMMUGroup,
		})
	}

	return nil
}

func pciHexToUint32(idString string) uint32 {
	if strings.HasPrefix(idString, "0x") {
		var id uint32
		_, err := fmt.Sscanf(idString, "0x%x", &id)
		if err != nil {
			log.Warnf("could not decode id '%s': %+v", idString, err)
			return 0
		}

		return id
	}

	// otherwise we get an "odd length hex string"
	if len(idString)%2 == 1 {
		idString = "0" + idString
	}
	bs, err := hex.DecodeString(idString)
	if err != nil {
		log.Warnf("could not decode id '%s': %+v", idString, err)
		return 0
	}
	if len(bs) == 4 {
		return binary.BigEndian.Uint32(bs)
	}
	if len(bs) == 2 {
		return uint32(binary.BigEndian.Uint16(bs))
	}
	if len(bs) == 1 {
		var id uint32

		_, err := fmt.Sscanf(idString, "%x", &id)
		if err != nil {
			log.Warnf("could not decode id '%s': %+v", idString, err)
			return 0
		}

		return id
	}

	log.Warnf("id %s is too short", idString)
	return 0
}

func (ir *inventoryReporter) requestOnboardStatus() {
	status := ir.subscriptions["onboardStatus"].GetAll()

	nilUUID := uuid.UUID{}
	for key, status := range status {
		onboardingStatus, ok := status.(types.OnboardingStatus)
		if !ok {
			log.Warnf("could not use %T with key %s as types.OnboardingStatus: %+v", status, key, status)
			return
		}
		if onboardingStatus.DeviceUUID == nilUUID {
			ir.boardingStatus.Store(uint32(offboardStatus))
		} else {
			ir.boardingStatus.Store(uint32(onboardedStatus))
		}
	}
}

func (ir *inventoryReporter) subscribe(ps *pubsub.PubSub) {
	var err error
	ir.subscriptions["deviceNetworkStatus"], err = ps.NewSubscription(pubsub.SubscriptionOptions{
		WarningTime: warningTime,
		ErrorTime:   errorTime,
		AgentName:   "nim",
		MyAgentName: agentName,
		TopicImpl:   types.DeviceNetworkStatus{},
	})

	if err != nil {
		log.Fatal(err)
	}

	ir.subscriptions["globalConfig"], err = ps.NewSubscription(
		pubsub.SubscriptionOptions{
			AgentName:   "zedagent",
			MyAgentName: agentName,
			TopicImpl:   types.ConfigItemValueMap{},
			Persistent:  true,
			Activate:    false,
			WarningTime: warningTime,
			ErrorTime:   errorTime,
		})
	if err != nil {
		log.Fatal(err)
	}

	ir.subscriptions["onboardStatus"], err = ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:   "zedclient",
		MyAgentName: agentName,
		TopicImpl:   types.OnboardingStatus{},
		Activate:    false,
		Persistent:  true,
		WarningTime: warningTime,
		ErrorTime:   errorTime,
	})
	if err != nil {
		log.Fatal(err)
	}

	for _, sub := range ir.subscriptions {
		err := sub.Activate()
		if err != nil {
			log.Fatalf("cannot subscribe to %+v: %+v", sub, err)
		}
	}

}

func (ir *inventoryReporter) process(ps *pubsub.PubSub) {
	stillRunning := time.NewTicker(stillRunningInterval)

	// TODO: get initial onboarding status
	watches := make([]pubsub.ChannelWatch, 0)
	for i := range ir.subscriptions {
		sub := ir.subscriptions[i]
		watches = append(watches, pubsub.WatchAndProcessSubChanges(sub))
	}

	watches = append(watches, pubsub.ChannelWatch{
		Chan: reflect.ValueOf(stillRunning.C),
		Callback: func(_ interface{}) (exit bool) {
			fmt.Fprintf(os.Stderr, "AAAAAA still running\n")
			ps.StillRunning(agentName, warningTime, errorTime)
			return false
		},
	})

	uploadTicker := time.NewTicker(2 * time.Minute)
	watches = append(watches, pubsub.ChannelWatch{
		Chan: reflect.ValueOf(uploadTicker.C),
		Callback: func(value interface{}) bool {
			ir.requestOnboardStatus()
			go func() {
				ir.upload()
			}()
			return false
		},
	})

	pubsub.MultiChannelWatch(watches)
}

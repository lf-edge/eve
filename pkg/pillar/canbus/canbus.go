// Copyright (c) 2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// CAN Bus support package
// This package provides functions to setup physical and/or create virtual
// CAN interfaces
package canbus

import (
	"bytes"
	"encoding/binary"
	"errors"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"
)

// Types of CAN interfaces
const (
	// LinkVCAN Virtual CAN interface type
	LinkVCAN = "vcan"
	// LinkCAN Physical CAN interface type
	LinkCAN = "can"
)

// The following constants are related to TDC (Transmitter Delay
// Compensation) and were taken from Linux's kernel header:
// include/uapi/linux/can/netlink.h (version 6.6)
// PS: All of them are treated as uint32 in netlink packages
//
//revive:disable:var-naming
const (
	IFLA_CAN_TDC          = unix.IFLA_CAN_BITRATE_MAX + 1
	IFLA_CAN_TDC_TDCV_MIN = 0x1
	IFLA_CAN_TDC_TDCV_MAX = 0x2
	IFLA_CAN_TDC_TDCO_MIN = 0x3
	IFLA_CAN_TDC_TDCO_MAX = 0x4
	IFLA_CAN_TDC_TDCF_MIN = 0x5
	IFLA_CAN_TDC_TDCF_MAX = 0x6
	IFLA_CAN_TDC_TDCV     = 0x7
	IFLA_CAN_TDC_TDCO     = 0x8
	IFLA_CAN_TDC_TDCF     = 0x9
)

// CAN Interface, it implements netlink.Link interface
type CAN struct {
	LinkAttrs          netlink.LinkAttrs
	CanType            string
	State              uint32
	BitTiming          unix.CANBitTiming
	DataBitTiming      unix.CANBitTiming
	BitTimingConst     unix.CANBitTimingConst
	DataBitTimingConst unix.CANBitTimingConst
	ErrorCounters      unix.CANBusErrorCounters
	Clock              unix.CANClock
	CtrlMode           unix.CANCtrlMode
	DeviceStats        unix.CANDeviceStats
	Restart            uint32
	RestartMs          uint32
	Termination        uint16
	TDCV               uint32
	TDCO               uint32
	TDCF               uint32
}

// Attrs returns Link attributes
func (d CAN) Attrs() *netlink.LinkAttrs {
	return &d.LinkAttrs
}

// Type returns the type of the CAN interface, i.e. "can" or "vcan"
func (d CAN) Type() string {
	return d.CanType
}

// Prepare data to be sent through a netlink package
// Returns a new buffer with the data
func makeBuffer(data any) (*bytes.Buffer, error) {
	raw := make([]byte, 0, unsafe.Sizeof(data))
	buf := bytes.NewBuffer(raw)
	err := binary.Write(buf, nl.NativeEndian(), data)
	if err != nil {
		return nil, err
	}
	return buf, nil
}

// Send a netlink request with a single attribute
// attrType: Attribute ID
// data: Attribute's data
func execSingleNetlinkReq(link CAN, attrType int, data []byte) error {
	attrsType := []int{attrType}
	payload := [][]byte{data}
	return execNetlinkReq(link, attrsType, payload)
}

// Send a netlink request
// attrsType: Array of attributes to change
// data: Array of the data for each attribute
func execNetlinkReq(link CAN, attrsType []int, data [][]byte) error {
	// Ensure the link index
	lattrs := link.Attrs()
	if lattrs == nil {
		return errors.New("Provided link has no attributes")
	}
	nlink, err := netlink.LinkByName(lattrs.Name)
	if err != nil {
		return err
	}
	linkIndex := nlink.Attrs().Index

	// Check if we have data
	la := len(attrsType)
	ld := len(data)
	if la == 0 || ld == 0 {
		return errors.New("No attributes and/or data provided")
	}
	if la != ld {
		return errors.New("Attributes and Data array must be of the same length")
	}

	// Build netlink message
	req := nl.NewNetlinkRequest(unix.RTM_NEWLINK, unix.NLM_F_REQUEST|unix.NLM_F_ACK)
	msg := nl.NewIfInfomsg(unix.AF_UNSPEC)
	msg.Index = int32(linkIndex)
	req.AddData(msg)

	linkInfo := nl.NewRtAttr(unix.IFLA_LINKINFO, nil)
	linkInfo.AddRtAttr(nl.IFLA_INFO_KIND, nl.NonZeroTerminated(link.Type()))

	nlData := linkInfo.AddRtAttr(nl.IFLA_INFO_DATA, nil)
	for i, att := range attrsType {
		payload := data[i]
		nlData.AddRtAttr(att, payload)
	}
	req.AddData(linkInfo)

	// Execute request
	_, err = req.Execute(unix.NETLINK_ROUTE, 0)
	return err
}

// Parse CAN data replied through netlink message
// This function was adapted and incremented from the netlink package version v1.2.0-beta
func parseCanData(link *CAN, data []syscall.NetlinkRouteAttr) {
	native := nl.NativeEndian()
	for _, datum := range data {
		switch datum.Attr.Type {
		case unix.IFLA_CAN_BITTIMING:
			link.BitTiming.Bitrate = native.Uint32(datum.Value)
			link.BitTiming.Sample_point = native.Uint32(datum.Value[4:])
			link.BitTiming.Tq = native.Uint32(datum.Value[8:])
			link.BitTiming.Prop_seg = native.Uint32(datum.Value[12:])
			link.BitTiming.Phase_seg1 = native.Uint32(datum.Value[16:])
			link.BitTiming.Phase_seg2 = native.Uint32(datum.Value[20:])
			link.BitTiming.Sjw = native.Uint32(datum.Value[24:])
			link.BitTiming.Brp = native.Uint32(datum.Value[28:])
		case unix.IFLA_CAN_BITTIMING_CONST:
			link.BitTimingConst.Tseg1_min = native.Uint32(datum.Value[16:])
			link.BitTimingConst.Tseg1_max = native.Uint32(datum.Value[20:])
			link.BitTimingConst.Tseg2_min = native.Uint32(datum.Value[24:])
			link.BitTimingConst.Tseg2_max = native.Uint32(datum.Value[28:])
			link.BitTimingConst.Sjw_max = native.Uint32(datum.Value[32:])
			link.BitTimingConst.Brp_min = native.Uint32(datum.Value[36:])
			link.BitTimingConst.Brp_max = native.Uint32(datum.Value[40:])
			link.BitTimingConst.Brp_inc = native.Uint32(datum.Value[44:])
		case unix.IFLA_CAN_DATA_BITTIMING:
			link.DataBitTiming.Bitrate = native.Uint32(datum.Value)
			link.DataBitTiming.Sample_point = native.Uint32(datum.Value[4:])
			link.DataBitTiming.Tq = native.Uint32(datum.Value[8:])
			link.DataBitTiming.Prop_seg = native.Uint32(datum.Value[12:])
			link.DataBitTiming.Phase_seg1 = native.Uint32(datum.Value[16:])
			link.DataBitTiming.Phase_seg2 = native.Uint32(datum.Value[20:])
			link.DataBitTiming.Sjw = native.Uint32(datum.Value[24:])
			link.DataBitTiming.Brp = native.Uint32(datum.Value[28:])
		case unix.IFLA_CAN_DATA_BITTIMING_CONST:
			link.DataBitTimingConst.Tseg1_min = native.Uint32(datum.Value[16:])
			link.DataBitTimingConst.Tseg1_max = native.Uint32(datum.Value[20:])
			link.DataBitTimingConst.Tseg2_min = native.Uint32(datum.Value[24:])
			link.DataBitTimingConst.Tseg2_max = native.Uint32(datum.Value[28:])
			link.DataBitTimingConst.Sjw_max = native.Uint32(datum.Value[32:])
			link.DataBitTimingConst.Brp_min = native.Uint32(datum.Value[36:])
			link.DataBitTimingConst.Brp_max = native.Uint32(datum.Value[40:])
			link.DataBitTimingConst.Brp_inc = native.Uint32(datum.Value[44:])
		case unix.IFLA_CAN_BERR_COUNTER:
			link.ErrorCounters.Txerr = native.Uint16(datum.Value)
			link.ErrorCounters.Rxerr = native.Uint16(datum.Value[2:])
		case unix.IFLA_CAN_CLOCK:
			link.Clock.Freq = native.Uint32(datum.Value)
		case unix.IFLA_CAN_CTRLMODE:
			link.CtrlMode.Mask = native.Uint32(datum.Value)
			link.CtrlMode.Flags = native.Uint32(datum.Value[4:])
		case unix.IFLA_CAN_STATE:
			link.State = native.Uint32(datum.Value)
		case unix.IFLA_CAN_RESTART_MS:
			link.RestartMs = native.Uint32(datum.Value)
		case unix.IFLA_CAN_RESTART:
			link.Restart = native.Uint32(datum.Value)
		case unix.IFLA_CAN_TERMINATION:
			link.Termination = native.Uint16(datum.Value)
		case IFLA_CAN_TDC | nl.NLA_F_NESTED:
			nmsg, err := nl.ParseRouteAttr(datum.Value)
			if err != nil {
				continue
			}
			for _, nested := range nmsg {
				switch nested.Attr.Type {
				case IFLA_CAN_TDC_TDCV:
					link.TDCV = native.Uint32(nested.Value)
				case IFLA_CAN_TDC_TDCO:
					link.TDCO = native.Uint32(nested.Value)
				case IFLA_CAN_TDC_TDCF:
					link.TDCF = native.Uint32(nested.Value)
				}
			}
		}
	}
}

// Set a bit flag
func setBitFlag(flags uint32, mask uint32) uint32 {
	return (flags | mask)
}

// Clear a bit flag
func clearBitFlag(flags uint32, mask uint32) uint32 {
	return (flags & (^mask))
}

// Convert Sample Point string (float format) value to uint32
// (multiplying by 1000)
func convSamplePoint(str string) (uint32, error) {
	value, err := strconv.ParseFloat(str, 32)
	if err != nil {
		return 0, err
	}
	return uint32(value * 1000), nil
}

// Convert string value to uint32
func convUint32(str string) (uint32, error) {
	value, err := strconv.ParseUint(str, 0, 32)
	if err != nil {
		return 0, err
	}
	return uint32(value), nil
}

// Convert string value to uint16
func convUint16(str string) (uint16, error) {
	value, err := strconv.ParseUint(str, 0, 16)
	if err != nil {
		return 0, err
	}
	return uint16(value), nil
}

// Set the proper flag of unix.CANCtrlMode according to the state (e.g.
// "on" or "off"), except the TDC mode
func setCtrlModeFlags(flagBit uint32, state string, ctrlMode *unix.CANCtrlMode) error {
	if ctrlMode == nil {
		return errors.New("No unix.CANCtrlMode provided")
	}
	mask := ctrlMode.Mask
	flag := ctrlMode.Flags

	if state == "on" {
		mask = setBitFlag(mask, flagBit)
		flag = setBitFlag(flag, flagBit)
	} else {
		mask = clearBitFlag(mask, flagBit)
		flag = clearBitFlag(flag, flagBit)
	}

	ctrlMode.Mask = mask
	ctrlMode.Flags = flag
	return nil
}

// Set TDC mode flags of unix.CANCtrlMode according to the state provided as
// string
func setCtrlModeTDC(state string, ctrlMode *unix.CANCtrlMode) error {
	if ctrlMode == nil {
		return errors.New("No unix.CANCtrlMode provided")
	}
	mask := ctrlMode.Mask
	flag := ctrlMode.Flags

	switch state {
	case "auto":
		mask = setBitFlag(mask, unix.CAN_CTRLMODE_TDC_AUTO)
		flag = setBitFlag(flag, unix.CAN_CTRLMODE_TDC_AUTO)
	case "manual":
		mask = setBitFlag(mask, unix.CAN_CTRLMODE_TDC_MANUAL)
		flag = setBitFlag(flag, unix.CAN_CTRLMODE_TDC_MANUAL)
	case "off":
		mask = setBitFlag(mask,
			unix.CAN_CTRLMODE_TDC_AUTO|unix.CAN_CTRLMODE_TDC_MANUAL)
		flag = setBitFlag(flag,
			unix.CAN_CTRLMODE_TDC_AUTO|unix.CAN_CTRLMODE_TDC_MANUAL)
	}

	ctrlMode.Mask = mask
	ctrlMode.Flags = flag
	return nil
}

// Check each property string in the map and call the corresponding
// function to set the parameter
func executeBitSetFunc(properties map[string]string, cmds map[string]func(string) error, executorFunc func() error) error {
	var err error

	cvErr := make([]error, 0)
	runExecutorFunc := false
	for key, value := range properties {
		value = strings.ToLower(value)
		cmd, ok := cmds[key]
		if ok {
			runExecutorFunc = true
			err = cmd(value)
		}

		if err != nil {
			cvErr = append(cvErr, err)
			err = nil
		}
	}

	if len(cvErr) != 0 {
		return errors.Join(cvErr...)
	}

	if runExecutorFunc {
		return executorFunc()
	}
	return nil
}

// GetCANLinks fetches all CAN interfaces (virtual or physical)
func GetCANLinks() ([]netlink.Link, error) {
	var canIfs []netlink.Link
	ifs, err := netlink.LinkList()

	if err != nil {
		return nil, err
	}

	for _, dev := range ifs {
		if dev.Type() == LinkCAN || dev.Type() == LinkVCAN {
			canIfs = append(canIfs, dev)
		}
	}

	return canIfs, err
}

// GetCANLink returns a CAN interface from the interface's name (e.g. "can0",
// "vcan0"). All the information about the interface will be fetched from the
// system
func GetCANLink(name string) (*CAN, error) {
	nlink, err := netlink.LinkByName(name)
	if err != nil {
		return nil, err
	}
	if nlink.Type() != LinkCAN && nlink.Type() != LinkVCAN {
		return nil, errors.New("Not a CAN interface")
	}
	linkIndex := nlink.Attrs().Index

	// Build netlink message
	req := nl.NewNetlinkRequest(unix.RTM_GETLINK, unix.NLM_F_REQUEST|unix.NLM_F_ACK)
	msg := nl.NewIfInfomsg(unix.AF_PACKET)
	msg.Index = int32(linkIndex)
	req.AddData(msg)

	ifname := nl.NewRtAttr(unix.IFLA_IFNAME, nl.ZeroTerminated(name))
	req.AddData(ifname)

	// Send request
	msgs, err := req.Execute(unix.NETLINK_ROUTE, 0)
	if err != nil {
		return nil, err
	}
	if len(msgs) == 0 {
		return nil, errors.New("Link not found")
	}

	// Parse replied message
	reply := nl.DeserializeIfInfomsg(msgs[0])
	attrs, err := nl.ParseRouteAttr(msgs[0][reply.Len():])
	if err != nil {
		return nil, err
	}

	// Create CAN interface object
	ifcan := CAN{}
	ifcan.LinkAttrs = *nlink.Attrs()
	ifcan.CanType = nlink.Type()

	// At this point, we are interested only in the specific CAN options
	native := nl.NativeEndian()
	for _, attr := range attrs {
		switch attr.Attr.Type {
		case unix.IFLA_LINKINFO:
			infos, err := nl.ParseRouteAttr(attr.Value)
			if err != nil {
				return nil, err
			}
			for _, info := range infos {
				switch info.Attr.Type {
				case unix.IFLA_INFO_DATA:
					payload, err := nl.ParseRouteAttr(info.Value)
					if err != nil {
						return nil, err
					}
					parseCanData(&ifcan, payload)
				case unix.IFLA_INFO_XSTATS:
					ifcan.DeviceStats.Bus_error = native.Uint32(info.Value)
					ifcan.DeviceStats.Error_warning = native.Uint32(info.Value[4:])
					ifcan.DeviceStats.Error_passive = native.Uint32(info.Value[8:])
					ifcan.DeviceStats.Bus_off = native.Uint32(info.Value[12:])
					ifcan.DeviceStats.Arbitration_lost = native.Uint32(info.Value[16:])
					ifcan.DeviceStats.Restarts = native.Uint32(info.Value[20:])
				}
			}
		default:
			continue
		}
	}

	return &ifcan, nil
}

// AddVCANLink adds a new Virtual CAN interface
// name: Interface's name, e.g. "vcan0", "vcan1"
func AddVCANLink(name string) (*CAN, error) {
	vcan := CAN{}
	vcan.LinkAttrs.Name = name
	vcan.CanType = "vcan"
	err := netlink.LinkAdd(&vcan)
	return &vcan, err
}

// DelVCANLink deletes a Virtual CAN interface
// name: Interface's name, e.g. "vcan0", "vcan1"
func DelVCANLink(name string) error {
	cdev, err := netlink.LinkByName(name)
	if err != nil || cdev == nil {
		return err
	}
	return netlink.LinkDel(cdev)
}

// LinkSetUp brings up a CAN interface
func LinkSetUp(link *CAN) error {
	return netlink.LinkSetUp(link)
}

// LinkSetDown brings down a CAN interface
func LinkSetDown(link *CAN) error {
	return netlink.LinkSetDown(link)
}

// StateToString returns the string corresponding to a CAN State
func StateToString(state uint32) string {
	st2str := map[uint32]string{
		unix.CAN_STATE_ERROR_ACTIVE:  "Error Active",
		unix.CAN_STATE_ERROR_WARNING: "Error Warning",
		unix.CAN_STATE_ERROR_PASSIVE: "Error Passive",
		unix.CAN_STATE_BUS_OFF:       "Bus off",
		unix.CAN_STATE_STOPPED:       "Stopped",
		unix.CAN_STATE_SLEEPING:      "Sleeping",
	}
	return st2str[state]
}

// SetBitTiming sets bit timing properties of a CAN interface
func SetBitTiming(link *CAN, bitTiming unix.CANBitTiming) error {
	if link == nil {
		return errors.New("No link provided")
	}

	buf, err := makeBuffer(bitTiming)
	if err != nil {
		return err
	}

	// Execute request
	err = execSingleNetlinkReq(*link, unix.IFLA_CAN_BITTIMING, buf.Bytes())
	if err != nil {
		return err
	}
	link.BitTiming = bitTiming
	return nil
}

// SetDataBitTiming sets data bit timing properties of a CAN interface
func SetDataBitTiming(link *CAN, dataBitTiming unix.CANBitTiming) error {
	if link == nil {
		return errors.New("No link provided")
	}

	buf, err := makeBuffer(dataBitTiming)
	if err != nil {
		return err
	}

	// Execute request
	err = execSingleNetlinkReq(*link, unix.IFLA_CAN_DATA_BITTIMING, buf.Bytes())
	if err != nil {
		return err
	}
	link.DataBitTiming = dataBitTiming
	return nil
}

// SetBitTimingConst sets bit timing constant properties of a CAN interface
func SetBitTimingConst(link *CAN, bitTimingConst unix.CANBitTimingConst) error {
	if link == nil {
		return errors.New("No link provided")
	}

	buf, err := makeBuffer(bitTimingConst)
	if err != nil {
		return err
	}

	// Execute request
	err = execSingleNetlinkReq(*link, unix.IFLA_CAN_BITTIMING_CONST, buf.Bytes())
	if err != nil {
		return err
	}
	link.BitTimingConst = bitTimingConst
	return nil
}

// SetDataBitTimingConst sets data bit timing constant properties of a CAN interface
func SetDataBitTimingConst(link *CAN, dataBitTimingConst unix.CANBitTimingConst) error {
	if link == nil {
		return errors.New("No link provided")
	}

	buf, err := makeBuffer(dataBitTimingConst)
	if err != nil {
		return err
	}

	// Execute request
	err = execSingleNetlinkReq(*link, unix.IFLA_CAN_DATA_BITTIMING_CONST, buf.Bytes())
	if err != nil {
		return err
	}
	link.DataBitTimingConst = dataBitTimingConst
	return nil
}

// SetCtrlMode sets control mode flags of a CAN interface
func SetCtrlMode(link *CAN, ctrlMode unix.CANCtrlMode) error {
	if link == nil {
		return errors.New("No link provided")
	}

	buf, err := makeBuffer(ctrlMode)
	if err != nil {
		return err
	}

	// Execute request
	err = execSingleNetlinkReq(*link, unix.IFLA_CAN_CTRLMODE, buf.Bytes())
	if err != nil {
		return err
	}
	link.CtrlMode = ctrlMode
	return nil
}

// SetRestart sets restart property of a CAN interface
func SetRestart(link *CAN, restart uint32) error {
	if link == nil {
		return errors.New("No link provided")
	}

	// Execute request
	err := execSingleNetlinkReq(*link,
		unix.IFLA_CAN_RESTART, nl.Uint32Attr(restart))
	if err != nil {
		return err
	}
	link.Restart = restart
	return nil
}

// SetRestartMs sets restart-ms property of a CAN interface
func SetRestartMs(link *CAN, restartMs uint32) error {
	if link == nil {
		return errors.New("No link provided")
	}

	// Execute request
	err := execSingleNetlinkReq(*link,
		unix.IFLA_CAN_RESTART_MS, nl.Uint32Attr(restartMs))
	if err != nil {
		return err
	}
	link.RestartMs = restartMs
	return nil
}

// SetTermination sets termination property of a CAN interface
func SetTermination(link *CAN, termination uint16) error {
	if link == nil {
		return errors.New("No link provided")
	}

	// Execute request
	err := execSingleNetlinkReq(*link,
		unix.IFLA_CAN_TERMINATION, nl.Uint16Attr(termination))
	if err != nil {
		return err
	}
	link.Termination = termination
	return nil
}

// SetTDC sets TDC parameters
func SetTDC(link *CAN, tdcv uint32, tdco uint32, tdcf uint32) error {
	if link == nil {
		return errors.New("No link provided")
	}
	// Ensure the link index
	lattrs := link.Attrs()
	if lattrs == nil {
		return errors.New("Provided link has no attributes")
	}
	nlink, err := netlink.LinkByName(lattrs.Name)
	if err != nil {
		return err
	}
	linkIndex := nlink.Attrs().Index

	// Build netlink message
	req := nl.NewNetlinkRequest(unix.RTM_NEWLINK, unix.NLM_F_REQUEST|unix.NLM_F_ACK)
	msg := nl.NewIfInfomsg(unix.AF_UNSPEC)
	msg.Index = int32(linkIndex)
	req.AddData(msg)

	linkInfo := nl.NewRtAttr(unix.IFLA_LINKINFO, nil)
	linkInfo.AddRtAttr(nl.IFLA_INFO_KIND, nl.NonZeroTerminated(link.Type()))

	tdcAttr := linkInfo.AddRtAttr(IFLA_CAN_TDC|unix.NLA_F_NESTED, nil)
	tdcAttr.AddRtAttr(IFLA_CAN_TDC_TDCV, nl.Uint32Attr(link.TDCV))
	tdcAttr.AddRtAttr(IFLA_CAN_TDC_TDCO, nl.Uint32Attr(link.TDCO))
	tdcAttr.AddRtAttr(IFLA_CAN_TDC_TDCF, nl.Uint32Attr(link.TDCF))
	req.AddData(linkInfo)

	// Execute request
	_, err = req.Execute(unix.NETLINK_ROUTE, 0)
	if err != nil {
		return err
	}

	link.TDCV = tdcv
	link.TDCO = tdco
	link.TDCF = tdcf
	return nil
}

// SetupCAN setup CAN interface from a map of properties described as
// strings, e.g.:
//
//	properties := map[string]string{
//	 "bitrate": "125000",
//	 "sample-point": "0.875",
//	 "tq": "29",
//	 "prop_seg": "118",
//	 "phase_seg1": "119",
//	 "phase_seg2": "34",
//	 "sjw": "1",
//	}
func SetupCAN(link *CAN, properties map[string]string) error {
	if link == nil {
		return errors.New("No link provided")
	}
	// Try to fetch current properties from the interface
	var canProps CAN
	iface, err := GetCANLink(link.Attrs().Name)
	if err == nil {
		canProps = *iface
	} else {
		canProps = CAN{}
	}

	//nolint:dupl // False positive with dataBitTimingCmds
	bitTimingCmds := map[string]func(string) error{
		"bitrate": func(value string) error {
			canProps.BitTiming.Bitrate, err = convUint32(value)
			return err
		},
		"sample-point": func(value string) error {
			canProps.BitTiming.Sample_point, err = convSamplePoint(value)
			return err
		},
		"tq": func(value string) error {
			canProps.BitTiming.Tq, err = convUint32(value)
			return err
		},
		"prop_seg": func(value string) error {
			canProps.BitTiming.Prop_seg, err = convUint32(value)
			return err
		},
		"phase_seg1": func(value string) error {
			canProps.BitTiming.Phase_seg1, err = convUint32(value)
			return err
		},
		"phase_seg2": func(value string) error {
			canProps.BitTiming.Phase_seg2, err = convUint32(value)
			return err
		},
		"sjw": func(value string) error {
			canProps.BitTiming.Sjw, err = convUint32(value)
			return err
		},
	}

	//nolint:dupl // False positive with bitTimingCmds
	dataBitTimingCmds := map[string]func(string) error{
		"dbitrate": func(value string) error {
			canProps.DataBitTiming.Bitrate, err = convUint32(value)
			return err
		},
		"dsample-point": func(value string) error {
			canProps.DataBitTiming.Sample_point, err = convSamplePoint(value)
			return err
		},
		"dtq": func(value string) error {
			canProps.DataBitTiming.Tq, err = convUint32(value)
			return err
		},
		"dprop_seg": func(value string) error {
			canProps.DataBitTiming.Prop_seg, err = convUint32(value)
			return err
		},
		"dprop_seg1": func(value string) error {
			canProps.DataBitTiming.Phase_seg1, err = convUint32(value)
			return err
		},
		"dprop_seg2": func(value string) error {
			canProps.DataBitTiming.Phase_seg2, err = convUint32(value)
			return err
		},
		"dsjw": func(value string) error {
			canProps.DataBitTiming.Sjw, err = convUint32(value)
			return err
		},
	}

	changeCtrlModeCmds := map[string]func(string) error{
		"loopback": func(value string) error {
			err = setCtrlModeFlags(unix.CAN_CTRLMODE_LOOPBACK, value, &canProps.CtrlMode)
			return err
		},
		"listen-only": func(value string) error {
			err = setCtrlModeFlags(unix.CAN_CTRLMODE_LISTENONLY, value, &canProps.CtrlMode)
			return err
		},
		"triple-sampling": func(value string) error {
			err = setCtrlModeFlags(unix.CAN_CTRLMODE_3_SAMPLES, value, &canProps.CtrlMode)
			return err
		},
		"one-shot": func(value string) error {
			err = setCtrlModeFlags(unix.CAN_CTRLMODE_ONE_SHOT, value, &canProps.CtrlMode)
			return err
		},
		"berr-reporting": func(value string) error {
			err = setCtrlModeFlags(unix.CAN_CTRLMODE_BERR_REPORTING, value, &canProps.CtrlMode)
			return err
		},
		"fd": func(value string) error {
			err = setCtrlModeFlags(unix.CAN_CTRLMODE_FD, value, &canProps.CtrlMode)
			return err
		},
		"fd-non-iso": func(value string) error {
			err = setCtrlModeFlags(unix.CAN_CTRLMODE_FD_NON_ISO, value, &canProps.CtrlMode)
			return err
		},
		"presume-ack": func(value string) error {
			err = setCtrlModeFlags(unix.CAN_CTRLMODE_PRESUME_ACK, value, &canProps.CtrlMode)
			return err
		},
		"cc-len8-dlc": func(value string) error {
			err = setCtrlModeFlags(unix.CAN_CTRLMODE_CC_LEN8_DLC, value, &canProps.CtrlMode)
			return err
		},
		"tdc-mode": func(value string) error {
			err = setCtrlModeTDC(value, &canProps.CtrlMode)
			return err
		},
	}

	changeTerminationCmds := map[string]func(string) error{
		"termination": func(value string) error {
			canProps.Termination, err = convUint16(value)
			return err
		},
	}

	changeRestartMsCmds := map[string]func(string) error{
		"restart": func(value string) error {
			var err error
			switch value {
			case "true":
				fallthrough
			case "1":
				canProps.Restart = 1
			case "false":
				fallthrough
			case "0":
				canProps.Restart = 0
			default:
				err = errors.New("Invalid value")
			}
			return err
		},
		"restart-ms": func(value string) error {
			canProps.RestartMs, err = convUint32(value)
			return err
		},
	}

	changeTDCCmds := map[string]func(string) error{
		"tdcv": func(value string) error {
			canProps.TDCV, err = convUint32(value)
			return err
		},
		"tdco": func(value string) error {
			canProps.TDCO, err = convUint32(value)
			return err
		},
		"tdcf": func(value string) error {
			canProps.TDCF, err = convUint32(value)
			return err
		},
	}
	// Set BiTiming
	err = executeBitSetFunc(properties, bitTimingCmds, func() error {
		return SetBitTiming(link, canProps.BitTiming)
	})
	if err != nil {
		return err
	}

	// Set DataBitTiming
	err = executeBitSetFunc(properties, dataBitTimingCmds, func() error {
		return SetDataBitTiming(link, canProps.DataBitTiming)
	})
	if err != nil {
		return err
	}

	// Set CtrlMode
	err = executeBitSetFunc(properties, changeCtrlModeCmds, func() error {
		return SetCtrlMode(link, canProps.CtrlMode)
	})
	if err != nil {
		return err
	}

	// Set Termination
	err = executeBitSetFunc(properties, changeTerminationCmds, func() error {
		return SetTermination(link, canProps.Termination)
	})
	if err != nil {
		return err
	}

	// Set Restart
	err = executeBitSetFunc(properties, changeRestartMsCmds, func() error {
		return SetRestartMs(link, canProps.RestartMs)
	})
	if err != nil {
		return err
	}

	// Set TDC
	err = executeBitSetFunc(properties, changeTDCCmds, func() error {
		return SetTDC(link, canProps.TDCV, canProps.TDCO, canProps.TDCF)
	})
	return err
}

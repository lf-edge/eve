// SPDX-License-Identifier: Apache-2.0

package eventlog

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"unicode/utf16"
)

type EFIDPathNodeType uint8

const (
	EFIDPathNodeHardware EFIDPathNodeType = 0x01
	EFIDPathNodeACPI                      = 0x02
	EFIDPathNodeMsg                       = 0x03
	EFIDPathNodeMedia                     = 0x04
	EFIDPathNodeBBS                       = 0x05
	EFIDPathNodeEoH                       = 0x7f
)

const (
	efiHardwareDPathNodePCI = 0x01

	efiACPIDPathNodeNormal = 0x01

	efiMsgDPathNodeLU   = 0x11
	efiMsgDPathNodeSATA = 0x12

	efiMediaDPathNodeHardDrive      = 0x01
	efiMediaDPathNodeFilePath       = 0x04
	efiMediaDPathNodeFvFile         = 0x06
	efiMediaDPathNodeFv             = 0x07
	efiMediaDPathNodeRelOffsetRange = 0x08
)

func firmwareDPathNodeToStringNew(data []byte, t EFIDPathNodeType, subType uint8) (string, error) {
	stream := bytes.NewReader(data)

	var name Guid
	if err := binary.Read(stream, binary.LittleEndian, &name); err != nil {
		return "", err
	}

	var builder bytes.Buffer
	switch subType {
	case efiMediaDPathNodeFvFile:
		builder.WriteString("\\FvFile")
	case efiMediaDPathNodeFv:
		builder.WriteString("\\Fv")
	default:
		return "", fmt.Errorf("invalid sub type for firmware device path node: %d", subType)
	}

	fmt.Fprintf(&builder, "(%s)", &name)
	return builder.String(), nil
}

func acpiDPathNodeToString(data []byte, t EFIDPathNodeType, subType uint8) (string, error) {
	stream := bytes.NewReader(data)

	var hid uint32
	if err := binary.Read(stream, binary.LittleEndian, &hid); err != nil {
		return "", err
	}

	var uid uint32
	if err := binary.Read(stream, binary.LittleEndian, &uid); err != nil {
		return "", err
	}

	if hid&0xffff == 0x41d0 {
		switch hid >> 16 {
		case 0x0a03:
			return fmt.Sprintf("\\PciRoot(0x%x)", uid), nil
		case 0x0a08:
			return fmt.Sprintf("\\PcieRoot(0x%x)", uid), nil
		case 0x0604:
			return fmt.Sprintf("\\Floppy(0x%x)", uid), nil
		default:
			return fmt.Sprintf("\\Acpi(PNP%04x,0x%x)", hid>>16, uid), nil
		}
	} else {
		return fmt.Sprintf("\\Acpi(0x%08x,0x%x)", hid, uid), nil
	}
}

func pciDPathNodeToString(data []byte, t EFIDPathNodeType, subType uint8) (string, error) {
	stream := bytes.NewReader(data)

	var function uint8
	if err := binary.Read(stream, binary.LittleEndian, &function); err != nil {
		return "", err
	}

	var device uint8
	if err := binary.Read(stream, binary.LittleEndian, &device); err != nil {
		return "", err
	}

	return fmt.Sprintf("\\Pci(0x%x,0x%x)", device, function), nil
}

func luDPathNodeToString(data []byte, t EFIDPathNodeType, subType uint8) (string, error) {
	stream := bytes.NewReader(data)

	var lun uint8
	if err := binary.Read(stream, binary.LittleEndian, &lun); err != nil {
		return "", err
	}

	return fmt.Sprintf("\\Unit(0x%x)", lun), nil
}

func hardDriveDPathNodeToString(data []byte, t EFIDPathNodeType, subType uint8) (string, error) {
	stream := bytes.NewReader(data)

	var partNumber uint32
	if err := binary.Read(stream, binary.LittleEndian, &partNumber); err != nil {
		return "", err
	}

	var partStart uint64
	if err := binary.Read(stream, binary.LittleEndian, &partStart); err != nil {
		return "", err
	}

	var partSize uint64
	if err := binary.Read(stream, binary.LittleEndian, &partSize); err != nil {
		return "", err
	}

	var sig [16]byte
	if _, err := io.ReadFull(stream, sig[:]); err != nil {
		return "", err
	}

	var partFormat uint8
	if err := binary.Read(stream, binary.LittleEndian, &partFormat); err != nil {
		return "", err
	}

	var sigType uint8
	if err := binary.Read(stream, binary.LittleEndian, &sigType); err != nil {
		return "", err
	}

	var builder bytes.Buffer

	switch sigType {
	case 0x01:
		fmt.Fprintf(&builder, "\\HD(%d,MBR,0x%08x,", partNumber, binary.LittleEndian.Uint32(sig[:]))
	case 0x02:
		r := bytes.NewReader(sig[:])
		var guid Guid
		if err := binary.Read(r, binary.LittleEndian, &guid); err != nil {
			return "", err
		}
		fmt.Fprintf(&builder, "\\HD(%d,GPT,%s,", partNumber, &guid)
	default:
		fmt.Fprintf(&builder, "\\HD(%d,%d,0,", partNumber, sigType)
	}

	fmt.Fprintf(&builder, "0x%016x, 0x%016x)", partStart, partSize)
	return builder.String(), nil
}

func sataDPathNodeToString(data []byte, t EFIDPathNodeType, subType uint8) (string, error) {
	stream := bytes.NewReader(data)

	var hbaPortNumber uint16
	if err := binary.Read(stream, binary.LittleEndian, &hbaPortNumber); err != nil {
		return "", err
	}

	var portMultiplierPortNumber uint16
	if err := binary.Read(stream, binary.LittleEndian, &portMultiplierPortNumber); err != nil {
		return "", err
	}

	var lun uint16
	if err := binary.Read(stream, binary.LittleEndian, &lun); err != nil {
		return "", err
	}

	return fmt.Sprintf("\\Sata(0x%x,0x%x,0x%x)", hbaPortNumber, portMultiplierPortNumber, lun), nil
}

func filePathDPathNodeToString(data []byte, t EFIDPathNodeType, subType uint8) (string, error) {
	u16 := make([]uint16, len(data)/2)
	stream := bytes.NewReader(data)
	binary.Read(stream, binary.LittleEndian, &u16)

	var buf bytes.Buffer
	for _, r := range utf16.Decode(u16) {
		buf.WriteRune(r)
	}
	return buf.String(), nil
}

func relOffsetRangePathNodeToString(data []byte, t EFIDPathNodeType, subType uint8) (string, error) {
	stream := bytes.NewReader(data)

	if _, err := stream.Seek(4, io.SeekCurrent); err != nil {
		return "", err
	}

	var start uint64
	if err := binary.Read(stream, binary.LittleEndian, &start); err != nil {
		return "", err
	}

	var end uint64
	if err := binary.Read(stream, binary.LittleEndian, &end); err != nil {
		return "", err
	}

	return fmt.Sprintf("\\Offset(0x%x,0x%x)", start, end), nil
}

type pathDecoder func([]byte, EFIDPathNodeType, uint8) (string, error)
type typeSubType struct {
	t  EFIDPathNodeType
	st uint8
}

var pathDecoders = map[typeSubType]pathDecoder{
	{EFIDPathNodeMedia, efiMediaDPathNodeFvFile}:         firmwareDPathNodeToStringNew,
	{EFIDPathNodeMedia, efiMediaDPathNodeFv}:             firmwareDPathNodeToStringNew,
	{EFIDPathNodeMedia, efiMediaDPathNodeHardDrive}:      hardDriveDPathNodeToString,
	{EFIDPathNodeMedia, efiMediaDPathNodeFilePath}:       filePathDPathNodeToString,
	{EFIDPathNodeMedia, efiMediaDPathNodeRelOffsetRange}: relOffsetRangePathNodeToString,
	{EFIDPathNodeACPI, efiACPIDPathNodeNormal}:           acpiDPathNodeToString,
	{EFIDPathNodeHardware, efiHardwareDPathNodePCI}:      pciDPathNodeToString,
	{EFIDPathNodeMsg, efiMsgDPathNodeLU}:                 luDPathNodeToString,
	{EFIDPathNodeMsg, efiMsgDPathNodeSATA}:               sataDPathNodeToString,
}

func parseDPathNode(stream io.Reader) (string, error) {
	var t EFIDPathNodeType
	if err := binary.Read(stream, binary.LittleEndian, &t); err != nil {
		return "", err
	}

	if t == EFIDPathNodeEoH {
		return "", nil
	}

	var subType uint8
	if err := binary.Read(stream, binary.LittleEndian, &subType); err != nil {
		return "", err
	}

	var length uint16
	if err := binary.Read(stream, binary.LittleEndian, &length); err != nil {
		return "", err
	}

	if length < 4 {
		return "", fmt.Errorf("unexpected device path node length (got %d, expected >= 4)", length)
	}

	data := make([]byte, length-4)
	if _, err := io.ReadFull(stream, data); err != nil {
		return "", err
	}

	pathDecoderFn, found := pathDecoders[typeSubType{t: t, st: subType}]
	if found {
		return pathDecoderFn(data, t, subType)
	}
	return fmt.Sprintf("%x", data), nil
}

func parseDevicePath(data []byte) (string, error) {
	stream := bytes.NewReader(data)
	var builder bytes.Buffer

	for {
		node, err := parseDPathNode(stream)
		if err != nil {
			return "", err
		}
		if node == "" {
			return builder.String(), nil
		}
		fmt.Fprintf(&builder, "%s", node)
	}
}

type efiImageLoadEventData struct {
	data             []byte
	locationInMemory uint64
	lengthInMemory   uint64
	linkTimeAddress  uint64
	path             string
}

func (e *efiImageLoadEventData) String() string {
	return fmt.Sprintf("UEFI_IMAGE_LOAD_EVENT{ ImageLocationInMemory: 0x%016x, ImageLengthInMemory: %d, "+
		"ImageLinkTimeAddress: 0x%016x, DevicePath: %s }", e.locationInMemory, e.lengthInMemory,
		e.linkTimeAddress, e.path)
}

func (e *efiImageLoadEventData) Bytes() []byte {
	return e.data
}

func parseEventDataEFIImageLoad(data []byte) error {
	stream := bytes.NewReader(data)

	var locationInMemory uint64
	if err := binary.Read(stream, binary.LittleEndian, &locationInMemory); err != nil {
		return err
	}

	var lengthInMemory uint64
	if err := binary.Read(stream, binary.LittleEndian, &lengthInMemory); err != nil {
		return err
	}

	var linkTimeAddress uint64
	if err := binary.Read(stream, binary.LittleEndian, &linkTimeAddress); err != nil {
		return err
	}

	var devicePathLength uint64
	if err := binary.Read(stream, binary.LittleEndian, &devicePathLength); err != nil {
		return err
	}

	devicePathBuf := make([]byte, devicePathLength)

	if _, err := io.ReadFull(stream, devicePathBuf); err != nil {
		return err
	}

	path, err := parseDevicePath(devicePathBuf)
	if err != nil {
		return err
	}

	efiImageData := &efiImageLoadEventData{data: data,
		locationInMemory: locationInMemory,
		lengthInMemory:   lengthInMemory,
		linkTimeAddress:  linkTimeAddress,
		path:             path}
	fmt.Printf("%s\n", efiImageData)
	return nil
}

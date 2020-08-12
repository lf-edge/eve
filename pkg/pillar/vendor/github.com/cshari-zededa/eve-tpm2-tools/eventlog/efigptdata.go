// SPDX-License-Identifier: Apache-2.0

package eventlog

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"unicode/utf16"
)

type efiGPTPartitionEntry struct {
	tGuid Guid
	uGuid Guid
	sLBA  uint64
	eLBA  uint64
	attr  uint64
	name  string
}

func (p *efiGPTPartitionEntry) String() string {
	return fmt.Sprintf("PartitionTypeGUID: %s, UniquePartitionGUID: %s, Name: \"%s\", Attributes: 0x%X",
		&p.tGuid, &p.uGuid, p.name, p.attr)
}

type efiGPTEventData struct {
	data       []byte
	diskGUID   Guid
	partitions []efiGPTPartitionEntry
}

func (e *efiGPTEventData) String() string {
	var builder bytes.Buffer
	fmt.Fprintf(&builder, "UEFI_GPT_DATA{ DiskGUID: %s, Partitions: [", &e.diskGUID)
	for i, part := range e.partitions {
		if i > 0 {
			fmt.Fprintf(&builder, ", ")
		}
		fmt.Fprintf(&builder, "{ %s }", &part)
	}
	fmt.Fprintf(&builder, "] }")
	return builder.String()
}

func (e *efiGPTEventData) ImgGuid(Img string) Guid {
	for _, part := range e.partitions {
		if part.name == Img {
			return part.uGuid
		}
	}
	return Guid{}
}

func (e *efiGPTEventData) Bytes() []byte {
	return e.data
}

const (
	diskGuidOffset  = 56
	partEntryOffset = 12 //relative to end of DiskGUID
)

func parseEventDataEFIGPT(data []byte) error {
	if gptData, err := parseGPTData(data); err == nil {
		fmt.Printf("%s\n", gptData.String())
		return nil
	} else {
		return err
	}
}

func parseGPTData(data []byte) (*efiGPTEventData, error) {
	stream := bytes.NewReader(data)

	// Skip to DiskGUID
	if _, err := stream.Seek(diskGuidOffset, io.SeekCurrent); err != nil {
		return nil, err
	}

	var diskGUID Guid
	if err := binary.Read(stream, binary.LittleEndian, &diskGUID); err != nil {
		return nil, err
	}

	// Skip to parseEventData
	if _, err := stream.Seek(partEntryOffset, io.SeekCurrent); err != nil {
		return nil, err
	}

	var partEntrySize uint32
	if err := binary.Read(stream, binary.LittleEndian, &partEntrySize); err != nil {
		return nil, err
	}

	if _, err := stream.Seek(4, io.SeekCurrent); err != nil {
		return nil, err
	}

	var numberOfParts uint64
	if err := binary.Read(stream, binary.LittleEndian, &numberOfParts); err != nil {
		return nil, err
	}

	eventData := &efiGPTEventData{diskGUID: diskGUID, partitions: make([]efiGPTPartitionEntry, numberOfParts)}

	for i := uint64(0); i < numberOfParts; i++ {
		entryData := make([]byte, partEntrySize)
		if _, err := io.ReadFull(stream, entryData); err != nil {
			return nil, err
		}

		entryStream := bytes.NewReader(entryData)

		var tGuid Guid
		if err := binary.Read(entryStream, binary.LittleEndian, &tGuid); err != nil {
			return nil, err
		}

		var uGuid Guid
		if err := binary.Read(entryStream, binary.LittleEndian, &uGuid); err != nil {
			return nil, err
		}

		var sLBA uint64
		if err := binary.Read(entryStream, binary.LittleEndian, &sLBA); err != nil {
			return nil, err
		}
		var eLBA uint64
		if err := binary.Read(entryStream, binary.LittleEndian, &eLBA); err != nil {
			return nil, err
		}
		var attr uint64
		if err := binary.Read(entryStream, binary.LittleEndian, &attr); err != nil {
			return nil, err
		}

		nameutf := make([]uint16, entryStream.Len()/2)
		if err := binary.Read(entryStream, binary.LittleEndian, &nameutf); err != nil {
			return nil, err
		}

		var name bytes.Buffer
		for _, r := range utf16.Decode(nameutf) {
			if r == rune(0) {
				break
			}
			name.WriteRune(r)
		}
		eventData.partitions[i] = efiGPTPartitionEntry{tGuid: tGuid,
			uGuid: uGuid,
			sLBA:  sLBA,
			eLBA:  eLBA,
			attr:  attr,
			name:  name.String()}
	}

	return eventData, nil
}

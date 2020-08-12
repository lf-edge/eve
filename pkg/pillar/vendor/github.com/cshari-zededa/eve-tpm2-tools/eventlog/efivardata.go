// SPDX-License-Identifier: Apache-2.0

package eventlog

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"unicode/utf16"
	"unicode/utf8"
)

// EFIVariableEventData corresponds to the EFI_VARIABLE_DATA type.
type EFIVariableEventData struct {
	data         []byte
	VariableName Guid
	UnicodeName  string
	VariableData []byte
}

var (
	surr1 uint16 = 0xd800
	surr2 uint16 = 0xdc00
	surr3 uint16 = 0xe000
)

//Write
func utf16ToStr(u []uint16) string {
	var utf8Str []byte
	for _, r := range utf16.Decode(u) {
		utf8Char := make([]byte, utf8.RuneLen(r))
		utf8.EncodeRune(utf8Char, r)
		utf8Str = append(utf8Str, utf8Char...)
	}
	return string(utf8Str)
}

func extractUTF16Buffer(stream io.ReadSeeker, nchars uint64) ([]uint16, error) {
	var out []uint16

	for i := nchars; i > 0; i-- {
		var c uint16
		if err := binary.Read(stream, binary.LittleEndian, &c); err != nil {
			return nil, err
		}
		out = append(out, c)
		if c >= surr1 && c < surr2 {
			if err := binary.Read(stream, binary.LittleEndian, &c); err != nil {
				return nil, err
			}
			if c < surr2 || c >= surr3 {
				// Invalid surrogate sequence. utf16.Decode doesn't consume this
				// byte when inserting the replacement char
				if _, err := stream.Seek(-1, io.SeekCurrent); err != nil {
					return nil, err
				}
				continue
			}
			// Valid surrogate sequence
			out = append(out, c)
		}
	}

	return out, nil
}

func (e *EFIVariableEventData) String() string {
	return fmt.Sprintf("UEFI_VARIABLE_DATA{ VariableName: %s, UnicodeName: \"%s\" }",
		e.VariableName.String(), e.UnicodeName)
}

func (e *EFIVariableEventData) Bytes() []byte {
	return e.data
}

func parseEventDataEFIVariable(data []byte, eventType EventType) error {
	stream := bytes.NewReader(data)

	var guid Guid
	if err := binary.Read(stream, binary.LittleEndian, &guid); err != nil {
		return err
	}

	var unicodeNameLength uint64
	if err := binary.Read(stream, binary.LittleEndian, &unicodeNameLength); err != nil {
		return err
	}

	var variableDataLength uint64
	if err := binary.Read(stream, binary.LittleEndian, &variableDataLength); err != nil {
		return err
	}

	utf16Name, err := extractUTF16Buffer(stream, unicodeNameLength)
	if err != nil {
		return err
	}

	variableData := make([]byte, variableDataLength)
	if _, err := io.ReadFull(stream, variableData); err != nil {
		return err
	}

	efivar := &EFIVariableEventData{data: data,
		VariableName: guid,
		UnicodeName:  utf16ToStr(utf16Name),
		VariableData: variableData}
	fmt.Printf("Data: %s\n", efivar.String())
	return nil
}

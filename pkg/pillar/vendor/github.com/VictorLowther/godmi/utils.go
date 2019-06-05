/*
* File Name:	utils.go
* Description:
* Author:	Chapman Ou <ochapman.cn@gmail.com>
* Created:	2014-08-21
 */
package godmi

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math"
	"unsafe"
)

var (
	Endian    binary.ByteOrder
	bigEndian bool
)

const INT_SIZE int = int(unsafe.Sizeof(0))

func init() {
	if getEndian() {
		Endian = binary.BigEndian
		bigEndian = true
	} else {
		Endian = binary.LittleEndian
		bigEndian = false
	}
}

func IsBigEndian() bool {
	return bigEndian
}

func IsLittleEndian() bool {
	return bigEndian
}

func getEndian() bool {
	var i int = 0x1
	bs := (*[INT_SIZE]byte)(unsafe.Pointer(&i))
	if bs[0] == 0 {
		return true
	}
	return false
}

func CheckBit(data uint64, bit int) bool {
	mask := uint64(0x01 << uint(bit))
	return data&mask == mask
}

func u16Tobytes(data uint16) []byte {
	bs := make([]byte, 2)
	if IsBigEndian() {
		binary.BigEndian.PutUint16(bs, data)
	} else {
		binary.LittleEndian.PutUint16(bs, data)
	}
	return bs
}

func u32Tobytes(data uint32) []byte {
	bs := make([]byte, 4)
	if IsBigEndian() {
		binary.BigEndian.PutUint32(bs, data)
	} else {
		binary.LittleEndian.PutUint32(bs, data)
	}
	return bs
}

func u64Tobytes(data uint64) []byte {
	bs := make([]byte, 8)
	if IsBigEndian() {
		binary.BigEndian.PutUint64(bs, data)
	} else {
		binary.LittleEndian.PutUint64(bs, data)
	}
	return bs
}

func bcd(data []byte) int64 {
	var b int64
	l := len(data)
	if l > 8 {
		panic("bcd: Out of range")
	}
	// Number of 4-bits
	nb := int64(l * 2)
	for i := int64(0); i < nb; i++ {
		var shift uint64
		if i%2 == 0 {
			shift = 0
		} else {
			shift = 4
		}
		b += int64((data[i/2]>>shift)&0x0F) * int64(math.Pow10(int(i)))
	}
	return b
}

func u16(data []byte) uint16 {
	var u uint16
	binary.Read(bytes.NewBuffer(data[0:2]), Endian, &u)
	return u
}

func u32(data []byte) uint32 {
	var u uint32
	binary.Read(bytes.NewBuffer(data[0:4]), Endian, &u)
	return u
}

func u64(data []byte) uint64 {
	var u uint64
	binary.Read(bytes.NewBuffer(data[0:8]), Endian, &u)
	return u
}

func uuid(data []byte, ver string) string {
	if bytes.Index(data, []byte{0x00}) != -1 {
		return "Not present"
	}

	if bytes.Index(data, []byte{0xFF}) != -1 {
		return "Not settable"
	}

	if ver > "2.6" {
		return fmt.Sprintf("%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X",
			data[3], data[2], data[1], data[0], data[5], data[4], data[7], data[6],
			data[8], data[9], data[10], data[11], data[12], data[13], data[14], data[15])
	}
	return fmt.Sprintf("%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X",
		data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
		data[8], data[9], data[10], data[11], data[12], data[13], data[14], data[15])
}

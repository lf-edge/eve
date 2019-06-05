/*
* File Name:	type33_64bit_memrory_error.go
* Description:	
* Author:	Chapman Ou <ochapman.cn@gmail.com>
* Created:	2014-08-20
*/
package godmi

import (
	"fmt"
)

type _64BitMemoryErrorInformation struct {
	infoCommon
	Type              MemoryErrorInformationType
	Granularity       MemoryErrorInformationGranularity
	Operation         MemoryErrorInformationOperation
	VendorSyndrome    uint32
	ArrayErrorAddress uint32
	ErrorAddress      uint32
	Reslution         uint32
}

func (m _64BitMemoryErrorInformation) String() string {
	return fmt.Sprintf("_64 Bit Memory Error Information\n"+
		"\tType: %s\n"+
		"\tGranularity: %s\n"+
		"\tOperation: %s\n"+
		"\tVendor Syndrome: %d\n"+
		"\tArray Error Address: %d\n"+
		"\tError Address: %d\n"+
		"\tReslution: %d",
		m.Type,
		m.Granularity,
		m.Operation,
		m.VendorSyndrome,
		m.ArrayErrorAddress,
		m.ErrorAddress,
		m.Reslution)
}



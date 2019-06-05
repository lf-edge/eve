/*
* File Name:	type40_additional.go
* Description:	
* Author:	Chapman Ou <ochapman.cn@gmail.com>
* Created:	2014-08-20
*/
package godmi

import (
	"fmt"
)

type AdditionalInformationEntries struct {
	Length           byte
	ReferencedHandle uint16
	ReferencedOffset byte
	String           string
	Value            []byte
}

type AdditionalInformationEntriess []AdditionalInformationEntries

func (a AdditionalInformationEntriess) String() string {
	var str string
	for _, s := range a {
		str += fmt.Sprintf("\n\t\t\t\tReferenced Handle: %d\n"+
			"\t\t\t\tReferenced Offset: %d\n"+
			"\t\t\t\tString: %s\n"+
			"\t\t\t\tValue: %v",
			s.ReferencedHandle,
			s.ReferencedOffset,
			s.String,
			s.Value)
	}
	return str
}

type AdditionalInformation struct {
	infoCommon
	NumberOfEntries byte
	Entries         []AdditionalInformationEntries
}

func (a AdditionalInformation) String() string {
	return fmt.Sprintf("Additional Information\n"+
		"\tNumber Of Entries: %d\n"+
		"\tEntries: %s",
		a.NumberOfEntries,
		AdditionalInformationEntriess(a.Entries))
}

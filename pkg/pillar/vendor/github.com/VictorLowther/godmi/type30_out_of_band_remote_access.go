/*
* File Name:	type30_out_of_band_remote_access.go
* Description:	
* Author:	Chapman Ou <ochapman.cn@gmail.com>
* Created:	2014-08-20
*/
package godmi

import (
	"fmt"
)

type OutOfBandRemoteAccessConnections struct {
	OutBoundEnabled bool
	InBoundEnabled  bool
}

func NewOutOfBandRemoteAccessConnections(data byte) OutOfBandRemoteAccessConnections {
	return OutOfBandRemoteAccessConnections{
		OutBoundEnabled: (data&0x02 != 0),
		InBoundEnabled:  (data&0x01 != 0),
	}
}

func (o OutOfBandRemoteAccessConnections) String() string {
	return fmt.Sprintf("\n\t\t\t\tOutbound Enabled: %t\n\t\t\t\tInbound Enabled: %t",
		o.OutBoundEnabled, o.InBoundEnabled)
}

type OutOfBandRemoteAccess struct {
	infoCommon
	ManufacturerName string
	Connections      OutOfBandRemoteAccessConnections
}

func (o OutOfBandRemoteAccess) String() string {
	return fmt.Sprintf("Out Of Band Remote Access:\n\t\t"+
		"Manufacturer Name: %s\n\t\t"+
		"Connections: %s\n",
		o.ManufacturerName,
		o.Connections)
}


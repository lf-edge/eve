/*
* File Name:	type25_system_power_controls.go
* Description:	
* Author:	Chapman Ou <ochapman.cn@gmail.com>
* Created:	2014-08-19
*/
package godmi

import (
	"fmt"
)

type SystemPowerControlsMonth byte
type SystemPowerControlsDayOfMonth byte
type SystemPowerControlsHour byte
type SystemPowerControlsMinute byte
type SystemPowerControlsSecond byte

type SystemPowerControls struct {
	infoCommon
	NextScheduledPowerOnMonth      SystemPowerControlsMonth
	NextScheduledPowerOnDayOfMonth SystemPowerControlsDayOfMonth
	NextScheduledPowerOnHour       SystemPowerControlsHour
	NextScheduledPowerMinute       SystemPowerControlsMinute
	NextScheduledPowerSecond       SystemPowerControlsSecond
}

func (s SystemPowerControls) String() string {
	return fmt.Sprintf("System Power Controls\n"+
		"\tNext Scheduled Power-on Month: %d"+
		"\tNext Scheduled Power-on Day-of-month: %d"+
		"\tNext Scheduled Power-on Hour: %d"+
		"\tNext Scheduled Power-on Minute: %d"+
		"\tNext Scheduled Power-on Second: %d",
		s.NextScheduledPowerOnMonth,
		s.NextScheduledPowerOnDayOfMonth,
		s.NextScheduledPowerOnHour,
		s.NextScheduledPowerMinute,
		s.NextScheduledPowerSecond)
}

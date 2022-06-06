package types

// UpdateStats standard structure for statistics that get sent on a notification channel
// during a data transfer operation
type UpdateStats struct {
	Size      int64
	Asize     int64
	DoneParts DownloadedParts
	Error     error
}

// StatsNotifChan channel to send UpdateStats
type StatsNotifChan chan UpdateStats

// SendStats send stats of type UpdateStats on prgChan, but after first checking that the prgChan is not nil
func SendStats(prgChan StatsNotifChan, stats UpdateStats) {
	if prgChan != nil {
		select {
		case prgChan <- stats:
		default: //ignore we cannot write
		}
	}
}

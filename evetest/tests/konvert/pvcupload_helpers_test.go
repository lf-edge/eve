// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package konvert_test

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/lf-edge/eve/evetest"
)

// pvcUploadGrep selects the pillar records that trace each carried volume's CDI
// upload on EVE-k and what volumemgr did with the PVC after a reboot. The
// completion pattern names the Notice-level line; RolloutDiskToPVC also logs a
// debug line with the same opening words.
const pvcUploadGrep = `grep -aE "virtctl args .image-upload|` +
	`image upload completed on try:[0-9]* after virtctl-image-upload|` +
	`Populate called for PVC|Populate: PVC |exists but upload not complete|` +
	`did not complete .upload state" | sort -u`

var pvcNameRE = regexp.MustCompile(`[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}-pvc-[0-9]+`)

// pvcUploadEvent is one of those records.
type pvcUploadEvent struct {
	at   time.Time
	pvc  string
	kind string
}

// pvcUploadReport sums up the events.
//
// unfinished counts Populate calls on a PVC whose latest upload had started and
// not completed: a reboot cut the upload short and volumemgr then looked at the
// partial PVC. That is the condition, whatever the image does about it.
// rejected counts the Populate calls that reported the upload incomplete, which
// only an image with the fix logs. recovered counts PVCs that were unfinished at
// a Populate and later logged a completed upload.
type pvcUploadReport struct {
	counts     map[string]int
	unfinished int
	recovered  int
	probed     bool
}

func (r pvcUploadReport) String() string {
	if !r.probed {
		return "probe=failed"
	}
	keys := make([]string, 0, len(r.counts))
	for k := range r.counts {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := []string{fmt.Sprintf("unfinished-at-populate=%d recovered=%d", r.unfinished, r.recovered)}
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s=%d", k, r.counts[k]))
	}
	return strings.Join(parts, " ")
}

// classifyPVCUploadMsg maps a record's message to an event kind, or "".
func classifyPVCUploadMsg(msg string) string {
	switch {
	case strings.Contains(msg, "virtctl args [image-upload"):
		return "started"
	case strings.Contains(msg, "after virtctl-image-upload"):
		return "done"
	case strings.Contains(msg, "Populate called for PVC"):
		return "populate"
	case strings.Contains(msg, "upload state unknown"):
		return "populate-unknown"
	case strings.HasPrefix(msg, "Populate: PVC "):
		if i := strings.LastIndex(msg, "upload state "); i >= 0 {
			return "populate-" + strings.TrimSpace(msg[i+len("upload state "):])
		}
	case strings.Contains(msg, "exists but upload not complete"):
		return "redrive"
	case strings.Contains(msg, "did not complete (upload state"):
		return "created-rejected"
	}
	return ""
}

// parsePVCUploadEvents reads newlog records, one JSON object per line, and
// returns the upload events in time order. Lines that do not parse are skipped.
func parsePVCUploadEvents(out string) []pvcUploadEvent {
	var events []pvcUploadEvent
	for _, line := range strings.Split(out, "\n") {
		var rec struct {
			Content   string `json:"content"`
			Timestamp struct {
				Seconds int64 `json:"seconds"`
				Nanos   int64 `json:"nanos"`
			} `json:"timestamp"`
		}
		if json.Unmarshal([]byte(strings.TrimSpace(line)), &rec) != nil {
			continue
		}
		var inner struct {
			Msg string `json:"msg"`
		}
		msg := rec.Content
		if json.Unmarshal([]byte(rec.Content), &inner) == nil && inner.Msg != "" {
			msg = inner.Msg
		}
		kind := classifyPVCUploadMsg(msg)
		pvc := pvcNameRE.FindString(msg)
		if kind == "" || pvc == "" {
			continue
		}
		events = append(events, pvcUploadEvent{
			at:   time.Unix(rec.Timestamp.Seconds, rec.Timestamp.Nanos),
			pvc:  pvc,
			kind: kind,
		})
	}
	sort.SliceStable(events, func(i, j int) bool { return events[i].at.Before(events[j].at) })
	return events
}

// summarizePVCUploadEvents builds the report from time-ordered events.
func summarizePVCUploadEvents(events []pvcUploadEvent) pvcUploadReport {
	r := pvcUploadReport{counts: map[string]int{}, probed: true}
	inFlight := map[string]bool{}
	wasUnfinished := map[string]bool{}
	recovered := map[string]bool{}
	for _, e := range events {
		r.counts[e.kind]++
		switch e.kind {
		case "started":
			inFlight[e.pvc] = true
		case "done":
			inFlight[e.pvc] = false
			if wasUnfinished[e.pvc] {
				recovered[e.pvc] = true
			}
		case "populate":
			if inFlight[e.pvc] {
				r.unfinished++
				wasUnfinished[e.pvc] = true
			}
		}
	}
	r.recovered = len(recovered)
	return r
}

// recordPVCUpload reports, from the device's newlog, whether a carried volume's
// upload was cut short by a reboot and what EVE-k did with the partial PVC. It
// logs one [PVC-UPLOAD] line for the soak to record and never fails the test.
func recordPVCUpload(device *evetest.EdgeDevice) pvcUploadReport {
	log := evetest.Logger()
	out, errOut, err := device.RunShellScript(newlogProbe(pvcUploadGrep), 3*time.Minute, 0)
	if err != nil {
		log.Warnf("[PVC-UPLOAD] probe=failed (%v) %s", err, strings.TrimSpace(errOut))
		return pvcUploadReport{}
	}
	r := summarizePVCUploadEvents(parsePVCUploadEvents(out))
	log.Infof("[PVC-UPLOAD] %s", r)
	return r
}

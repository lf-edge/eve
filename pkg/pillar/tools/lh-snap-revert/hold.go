// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	lh "github.com/longhorn/longhorn-manager/k8s/pkg/apis/longhorn/v1beta2"
)

// A recurring job selects only volumes whose job or group label is
// "enabled", and only while they are attached. The tool attaches the
// volume, so it sets these labels to "disabled" for the run and records
// them in heldAnnotation, so that a later run can restore them.
const (
	jobLabelPrefix    = "recurring-job.longhorn.io/"
	groupLabelPrefix  = "recurring-job-group.longhorn.io/"
	sourceLabel       = jobLabelPrefix + "source"
	defaultGroupLabel = groupLabelPrefix + "default"
	heldAnnotation    = "lh-snap-revert/held-recurring-jobs"
	labelEnabled      = "enabled"
	labelDisabled     = "disabled"
)

// isRecurringLabel matches Longhorn's IsRecurringJobLabel, which excludes
// the source label.
func isRecurringLabel(k string) bool {
	return k != sourceLabel &&
		(strings.HasPrefix(k, jobLabelPrefix) || strings.HasPrefix(k, groupLabelPrefix))
}

// labelsToHold returns the recurring-job labels to disable on vol: the
// enabled ones and those an earlier run left held. Longhorn puts a volume
// without labels of these prefixes, source included, in the default group.
func labelsToHold(vol *lh.Volume) []string {
	keys := map[string]bool{}
	hasRecurring := false
	for k, v := range vol.Labels {
		if strings.HasPrefix(k, jobLabelPrefix) || strings.HasPrefix(k, groupLabelPrefix) {
			hasRecurring = true
		}
		if isRecurringLabel(k) && v == labelEnabled {
			keys[k] = true
		}
	}
	for _, k := range heldLabels(vol) {
		keys[k] = true
	}
	if !hasRecurring {
		keys[defaultGroupLabel] = true
	}
	out := make([]string, 0, len(keys))
	for k := range keys {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// heldLabels returns the labels recorded by a run that did not restore them.
func heldLabels(vol *lh.Volume) []string {
	var out []string
	for _, k := range strings.Split(vol.Annotations[heldAnnotation], ",") {
		if k != "" {
			out = append(out, k)
		}
	}
	return out
}

func enabledRecurringLabels(vol *lh.Volume) []string {
	var out []string
	for k, v := range vol.Labels {
		if isRecurringLabel(k) && v == labelEnabled {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

// holdPatch builds a JSON merge patch for the volume that disables the
// labels and records them, or enables them and removes the record.
func holdPatch(keys []string, hold bool) ([]byte, error) {
	value := labelEnabled
	var held interface{}
	if hold {
		value = labelDisabled
		held = strings.Join(keys, ",")
	}
	labels := map[string]string{}
	for _, k := range keys {
		labels[k] = value
	}
	return json.Marshal(map[string]interface{}{
		"metadata": map[string]interface{}{
			"labels":      labels,
			"annotations": map[string]interface{}{heldAnnotation: held},
		},
	})
}

func manualReleaseCmd(volume string, keys []string) string {
	data, _ := holdPatch(keys, false)
	return fmt.Sprintf(`eve exec kube kubectl -n %s patch volumes.longhorn.io %s --type merge -p '%s'`,
		longhornNamespace, volume, data)
}

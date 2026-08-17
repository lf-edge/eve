// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package zedmanager

import (
	"sort"

	"github.com/lf-edge/eve/pkg/pillar/types"
)

// publishCPUDemandSet tells domainmgr which applications are intended to run,
// and what CPU placement each asked for.
//
// domainmgr plans CPU placement over the whole set at once, so the layout does
// not depend on the order workloads happen to start in. It cannot derive that
// set from DomainConfig: a DomainConfig only exists once the app's volumes are
// resolved and its network is up, so an app whose image is still downloading is
// invisible and the app that finished first gets planned as if it were alone.
// The CPU intent, by contrast, is known the moment the app config arrives.
//
// INVARIANT: the demand set reaches domainmgr before any DomainConfig for the
// same app. It holds because both are published by this agent, and this one is
// published straight from the app config while a DomainConfig has to wait for
// volume resolution -- work that takes at least one more pubsub round trip.
// domainmgr still tolerates a missing set, but only by falling back to the
// order-dependent behaviour this exists to avoid.
//
// Called on anything that changes the set or the effective-activate decision.
// Publishing an identical set is a no-op in pubsub, so callers need not check.
func publishCPUDemandSet(ctx *zedmanagerContext) {
	var set types.CPUDemandSet
	for key := range ctx.subAppInstanceConfig.GetAll() {
		// The local config wins when there is one, exactly as handleModify
		// resolves it, so the demand set describes the config that will
		// actually become a DomainConfig.
		config := lookupAppInstanceConfig(ctx, key, true)
		if config == nil {
			continue
		}
		// An app that is configured but not activated must not hold a CPU
		// reservation: its cores belong to the workloads that do run.
		if !effectiveActivateCombined(*config, ctx) {
			continue
		}
		set.Apps = append(set.Apps, types.AppCPUDemand{
			UUID:         config.UUIDandVersion.UUID,
			DisplayName:  config.DisplayName,
			VCpus:        config.FixedResources.VCpus,
			CPUsPinned:   config.FixedResources.CPUsPinned,
			CPUPlacement: config.FixedResources.CPUPlacement,
		})
	}
	// GetAll iterates a map, so without this an unchanged set would be a
	// different object on every publication.
	sort.Slice(set.Apps, func(i, j int) bool {
		return set.Apps[i].UUID.String() < set.Apps[j].UUID.String()
	})

	if err := ctx.pubCPUDemandSet.Publish(set.Key(), set); err != nil {
		log.Errorf("publishCPUDemandSet failed: %v", err)
	}
}

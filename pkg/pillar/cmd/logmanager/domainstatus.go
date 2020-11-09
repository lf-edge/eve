// Copyright (c) 2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package logmanager

import (
	"github.com/lf-edge/eve/pkg/pillar/types"
)

// Return the UUID of the instance based on the domainname
func lookupDomainName(ctxArg interface{}, domainName string) string {
	ctx := ctxArg.(*logmanagerContext)
	ctx.RLock()
	defer ctx.RUnlock()
	if du, ok := domainUuid[domainName]; ok {
		return du
	}
	return ""
}

// Map from domainName to the UUID
var domainUuid map[string]string = make(map[string]string)

func handleDomainStatusCreate(ctxArg interface{}, key string,
	statusArg interface{}) {
	handleDomainStatusImpl(ctxArg, key, statusArg)
}

func handleDomainStatusModify(ctxArg interface{}, key string,
	statusArg interface{}, oldStatusArg interface{}) {
	handleDomainStatusImpl(ctxArg, key, statusArg)
}

func handleDomainStatusImpl(ctxArg interface{}, key string,
	statusArg interface{}) {

	ctx := ctxArg.(*logmanagerContext)
	ctx.Lock()
	defer ctx.Unlock()
	log.Functionf("handleDomainStatusImpl for %s", key)
	status := statusArg.(types.DomainStatus)
	// Record the domainName even if Pending* is set
	log.Functionf("handleDomainStatusImpl add %s to %s",
		status.DomainName, status.UUIDandVersion.UUID.String())
	domainUuid[status.DomainName] = status.UUIDandVersion.UUID.String()
	log.Functionf("handleDomainStatusImpl done for %s", key)
}

func handleDomainStatusDelete(ctxArg interface{}, key string,
	statusArg interface{}) {

	ctx := ctxArg.(*logmanagerContext)
	ctx.Lock()
	defer ctx.Unlock()
	log.Functionf("handleDomainStatusDelete for %s", key)
	status := statusArg.(types.DomainStatus)
	if _, ok := domainUuid[status.DomainName]; !ok {
		log.Errorf("handleDomainStatusDelete UUID %s not in map",
			status.UUIDandVersion.UUID.String())
		return
	}
	log.Functionf("handleDomainStatusDomain remove %s",
		status.DomainName)
	delete(domainUuid, status.DomainName)
	log.Functionf("handleDomainStatusDelete done for %s", key)
}

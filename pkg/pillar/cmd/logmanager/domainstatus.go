// Copyright (c) 2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package logmanager

import (
	"github.com/lf-edge/eve/pkg/pillar/types"
	log "github.com/sirupsen/logrus"
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

func handleDomainStatusModify(ctxArg interface{}, key string,
	statusArg interface{}) {

	ctx := ctxArg.(*logmanagerContext)
	ctx.Lock()
	defer ctx.Unlock()
	log.Infof("handleDomainStatusModify for %s\n", key)
	status := statusArg.(types.DomainStatus)
	// Record the domainName even if Pending* is set
	log.Infof("handleDomainStatusModify add %s to %s\n",
		status.DomainName, status.UUIDandVersion.UUID.String())
	domainUuid[status.DomainName] = status.UUIDandVersion.UUID.String()
	log.Infof("handleDomainStatusModify done for %s\n", key)
}

func handleDomainStatusDelete(ctxArg interface{}, key string,
	statusArg interface{}) {

	ctx := ctxArg.(*logmanagerContext)
	ctx.Lock()
	defer ctx.Unlock()
	log.Infof("handleDomainStatusDelete for %s\n", key)
	status := statusArg.(types.DomainStatus)
	if _, ok := domainUuid[status.DomainName]; !ok {
		log.Errorf("handleDomainStatusDelete UUID %s not in map\n",
			status.UUIDandVersion.UUID.String())
		return
	}
	log.Infof("handleDomainStatusDomain remove %s\n",
		status.DomainName)
	delete(domainUuid, status.DomainName)
	log.Infof("handleDomainStatusDelete done for %s\n", key)
}

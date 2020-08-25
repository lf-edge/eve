// Copyright (c) 2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package logmanager

import (
	"github.com/lf-edge/eve/pkg/pillar/types"
	"strconv"
	"strings"
)

// Return the UUID of the instance based on the domainname
func lookupDomainName(ctxArg interface{}, domainName string) string {
	ctx := ctxArg.(*logmanagerContext)
	ctx.RLock()
	defer ctx.RUnlock()
	newName := nameRemLastdotNum(domainName)
	if du, ok := domainUuid[newName]; ok {
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
	log.Infof("handleDomainStatusModify for %s", key)
	status := statusArg.(types.DomainStatus)
	// Record the domainName even if Pending* is set
	newName := nameRemLastdotNum(status.DomainName)
	log.Infof("handleDomainStatusModify add %s(%s) to %s",
		status.DomainName, newName, status.UUIDandVersion.UUID.String())
	domainUuid[newName] = status.UUIDandVersion.UUID.String()
	log.Infof("handleDomainStatusModify done for %s", key)
}

func handleDomainStatusDelete(ctxArg interface{}, key string,
	statusArg interface{}) {

	ctx := ctxArg.(*logmanagerContext)
	ctx.Lock()
	defer ctx.Unlock()
	log.Infof("handleDomainStatusDelete for %s", key)
	status := statusArg.(types.DomainStatus)
	if _, ok := domainUuid[status.DomainName]; !ok {
		log.Errorf("handleDomainStatusDelete UUID %s not in map",
			status.UUIDandVersion.UUID.String())
		return
	}
	log.Infof("handleDomainStatusDomain remove %s",
		status.DomainName)
	newName := nameRemLastdotNum(status.DomainName)
	delete(domainUuid, newName)
	log.Infof("handleDomainStatusDelete done for %s", key)
}

// XXX remove the .num from the domain name for now
func nameRemLastdotNum(dName string) string {
	dNames := strings.Split(dName, ".")
	numPart := dNames[len(dNames)-1]
	if _, err := strconv.Atoi(numPart); err == nil {
		return strings.TrimSuffix(dName, "."+numPart)
	}
	return dName
}

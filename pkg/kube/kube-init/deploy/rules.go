// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package deploy

// deriveStructuralEdges derives graph edges from parsed Manifests.
func deriveStructuralEdges(byName map[string]*Component) ([]Edge, error) {
	anyManifests := false
	for _, c := range byName {
		if len(c.Manifests) > 0 {
			anyManifests = true
			break
		}
	}
	if !anyManifests {
		return nil, nil
	}
	return nil, nil
}

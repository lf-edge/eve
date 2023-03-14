// Copyright (c) 2019-2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package downloader

import (
	"fmt"
	"net/url"
	"strings"
)

// ociRepositorySplit will get the URL for the registry and the path to the
// specific image
func ociRepositorySplit(image string) (string, string, error) {
	var registry, path string
	imageURL, err := url.Parse(image)
	if err != nil {
		return registry, path, fmt.Errorf("invalid image URL: %s, %v", image, err)
	}

	if imageURL.Scheme != "docker" && imageURL.Scheme != "oci" {
		return registry, path, fmt.Errorf("unknown OCI registry scheme %s, original URL: %s", imageURL.Scheme,
			image)
	}

	// remove any leading slash on the path, as that can mess things up
	registry = imageURL.Host
	path = strings.TrimPrefix(imageURL.Path, "/")

	return registry, path, nil
}

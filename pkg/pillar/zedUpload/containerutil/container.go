// Copyright(c) 2017-2018 Zededa, Inc.
// All rights reserved.

package container

import (
	"bytes"
	"encoding/base64"
	"encoding/json"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/client"
	"golang.org/x/net/context"
	"net/http"
	"strings"
)

func getContainerClient(httpClient *http.Client) (*client.Client, error) {
	var containerClient *client.Client
	var err error
	if httpClient == nil {
		containerClient, err = client.NewClientWithOpts(client.WithVersion("1.39"))
	} else {
		containerClient, err = client.NewClientWithOpts(client.WithVersion("1.39"), client.WithHTTPClient(httpClient))
	}
	return containerClient, err
}

func getEncodedString(user, pass string) string {
	authConfig := types.AuthConfig{
		Username: user,
		Password: pass,
	}
	encodedJSON, err := json.Marshal(authConfig)
	if err != nil {
		panic(err)
	}
	regAuth := base64.URLEncoding.EncodeToString(encodedJSON)
	return regAuth
}

func UploadContainerImage(registry, accountKey, accountPass, localFile string, httpClient *http.Client) (string, error) {
	ctx := context.Background()
	containerClient, err := getContainerClient(httpClient)
	if err != nil {
		return "", err
	}
	var file string
	if registry != "" {
		if strings.HasSuffix(registry, "/") {
			file = registry + localFile
		} else {
			file = registry + "/" + localFile
		}
	}
	out, uploadErr := containerClient.ImagePush(ctx, file, types.ImagePushOptions{RegistryAuth: getEncodedString(accountKey, accountPass)})
	if uploadErr != nil {
		return "", uploadErr
	}
	buf := new(bytes.Buffer)
	buf.ReadFrom(out)
	output := buf.String()
	return output, nil
}

func DownloadContainerImage(registry, accountKey, accountPass, remoteFile string, httpClient *http.Client) (string, error) {
	ctx := context.Background()
	containerClient, err := getContainerClient(httpClient)
	if err != nil {
		return "", err
	}
	var file string
	if registry != "" {
		if strings.HasSuffix(registry, "/") {
			file = registry + remoteFile
		} else {
			file = registry + "/" + remoteFile
		}
	}
	out, downloadErr := containerClient.ImagePull(ctx, file, types.ImagePullOptions{RegistryAuth: getEncodedString(accountKey, accountPass)})
	if downloadErr != nil {
		return "", downloadErr
	}
	buf := new(bytes.Buffer)
	buf.ReadFrom(out)
	output := buf.String()
	return output, nil
}

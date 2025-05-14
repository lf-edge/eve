// Copyright (c) 2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package collectinfo

import (
	"reflect"
	"testing"

	"github.com/lf-edge/eve/pkg/pillar/agentlog"
	"github.com/lf-edge/eve/pkg/pillar/types"
)

func init() {
	logger, log = agentlog.Init(agentName)
}

func convertLOCConfigsToInterface(locs map[string]types.LOCConfig) map[string]interface{} {
	ret := make(map[string]interface{})
	for k, v := range locs {
		ret[k] = v
	}
	return ret
}

func plainCredentials(datastore types.DatastoreConfig) (string, string) {
	return datastore.ApiKey, datastore.Password
}

func TestCollectInfoRetrieveDSUploadInfo(t *testing.T) {
	tests := []struct {
		name                string // description of this test case
		want                uploadInfo
		wantErr             bool
		extractDS           func(datastore types.DatastoreConfig) (string, string, string)
		retrieveLOCConfigs  func() map[string]interface{}
		decipherCredentials func(datastore types.DatastoreConfig) (string, string)
	}{
		{
			name: "basic",
			want: uploadInfo{
				url:          "https://datastore:1234/images",
				authMethod:   "BASIC",
				authPassword: "foobar",
			},
			retrieveLOCConfigs: func() map[string]interface{} {
				locs := map[string]types.LOCConfig{
					"": {
						LocURL: "http://loc:80",
						CollectInfoDatastore: types.DatastoreConfig{
							DsType:   "DsHttps",
							Fqdn:     "http://datastore:1234",
							ApiKey:   "BASIC",
							Password: "foobar",
							Dpath:    "images",
						},
					},
				}

				return convertLOCConfigsToInterface(locs)
			},
			wantErr:             false,
			decipherCredentials: plainCredentials,
		},
		{
			name: "empty credentials",
			want: uploadInfo{
				url:          "http://datastore:1234/foo/bar",
				authMethod:   "",
				authPassword: "",
			},
			wantErr: false,
			retrieveLOCConfigs: func() map[string]interface{} {
				locs := map[string]types.LOCConfig{
					"": {
						LocURL: "http://loc:80",
						CollectInfoDatastore: types.DatastoreConfig{
							DsType:   "DsHttp",
							Fqdn:     "http://datastore:1234/foo",
							ApiKey:   "",
							Password: "",
							Dpath:    "bar",
						},
					},
				}

				return convertLOCConfigsToInterface(locs)
			},
			decipherCredentials: plainCredentials,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var ci collectInfo

			ci.retrieveLOCConfigs = tt.retrieveLOCConfigs
			ci.decipherCredentials = tt.decipherCredentials

			got, gotErr := ci.retrieveDSUploadInfo()

			if gotErr != nil {
				if !tt.wantErr {
					t.Errorf("retrieveDSUploadInfo() failed: %v", gotErr)
				}
				return
			}
			if tt.wantErr {
				t.Fatal("retrieveDSUploadInfo() succeeded unexpectedly")
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("retrieveDSUploadInfo() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsToken(t *testing.T) {
	tests := []struct {
		name string // description of this test case
		// Named input parameters for target function.
		str  string
		want bool
	}{
		{
			name: "NTLM",
			str:  "NTLM",
			want: true,
		},
		{
			name: "Bearer",
			str:  "Bearer",
			want: true,
		},
		{
			name: "Basic",
			str:  "Basic",
			want: true,
		},
		{
			name: "Spaces",
			str:  " ",
			want: false,
		},
		{
			name: "Empty",
			str:  "",
			want: true,
		},
		{
			name: "Newline",
			str:  "\n",
			want: false,
		},
		{
			name: "Colon",
			str:  ":",
			want: false,
		},
		{
			name: "Equal sign",
			str:  "=",
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isToken(tt.str)
			if got != tt.want {
				t.Errorf("isToken() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsToken68(t *testing.T) {
	tests := []struct {
		name string // description of this test case
		// Named input parameters for target function.
		str  string
		want bool
	}{
		{
			name: "Spaces",
			str:  " ",
			want: false,
		},
		{
			name: "Empty",
			str:  "",
			want: true,
		},
		{
			name: "Newline",
			str:  "\n",
			want: false,
		},
		{
			name: "Colon",
			str:  ":",
			want: false,
		},
		{
			name: "Trailing equal sign",
			str:  "=",
			want: true,
		},
		{
			name: "Non-Trailing equal sign",
			str:  "=A",
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isToken68(tt.str)
			if got != tt.want {
				t.Errorf("isToken68() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCreateHttpURLFromDatastore(t *testing.T) {
	tests := []struct {
		name string // description of this test case
		// Named input parameters for target function.
		datastore types.DatastoreConfig
		want      string
	}{
		{
			name: "empty",
			datastore: types.DatastoreConfig{
				Fqdn:  "",
				Dpath: "",
			},
			want: "",
		},
		{
			name: "example.com/foo",
			datastore: types.DatastoreConfig{
				Fqdn:  "example.com",
				Dpath: "foo",
			},
			want: "https://example.com/foo",
		},
		{
			name: "too many /",
			datastore: types.DatastoreConfig{
				Fqdn:  "example.com//",
				Dpath: "//foo//",
			},
			want: "https://example.com/foo",
		},
		{
			name: "fqdn with path",
			datastore: types.DatastoreConfig{
				Fqdn:  "example.com/path//",
				Dpath: "//foo//",
			},
			want: "https://example.com/path/foo",
		},
		{
			name: "fqdn with path and scheme",
			datastore: types.DatastoreConfig{
				Fqdn:   "https://example.com/path///",
				Dpath:  "///foo//",
				DsType: "DsHttp",
			},
			want: "http://example.com/path/foo",
		},
		{
			name: "relative path",
			datastore: types.DatastoreConfig{
				Fqdn:  "example.com/foo/",
				Dpath: "../bar",
			},
			want: "https://example.com/bar",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.datastore.DsType == "" {
				tt.datastore.DsType = "DsHttps"
			}
			got := createCleanHTTPURLFromDatastore(tt.datastore)
			if got != tt.want {
				t.Errorf("createHttpURLFromDatastore() = %v, want %v", got, tt.want)
			}
		})
	}
}

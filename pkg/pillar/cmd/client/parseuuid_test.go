// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"testing"

	eveuuid "github.com/lf-edge/eve-api/go/eveuuid"
	uuid "github.com/satori/go.uuid"
	"google.golang.org/protobuf/proto"
)

func TestGenerateUUIDRequest_RoundTrip(t *testing.T) {
	b, err := generateUUIDRequest()
	if err != nil {
		t.Fatalf("generateUUIDRequest: %v", err)
	}
	if b == nil {
		t.Fatal("generateUUIDRequest returned nil bytes")
	}
	var req eveuuid.UuidRequest
	if err := proto.Unmarshal(b, &req); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
}

func TestParseUUIDResponse(t *testing.T) {
	const goodUUID = "f47ac10b-58cc-4372-a567-0e02b2c3d479"

	marshal := func(t *testing.T, msg *eveuuid.UuidResponse) []byte {
		t.Helper()
		b, err := proto.Marshal(msg)
		if err != nil {
			t.Fatalf("proto.Marshal: %v", err)
		}
		return b
	}

	tests := []struct {
		name         string
		body         []byte
		wantUUID     string
		wantModel    string
		wantParseErr bool
		emptyModelOK bool // for cases where empty hardwaremodel is the expected result
	}{
		{
			name: "valid with manufacturer and product",
			body: marshal(t, &eveuuid.UuidResponse{
				Uuid:         goodUUID,
				Manufacturer: "Dell",
				ProductName:  "PowerEdge R740",
			}),
			wantUUID:  goodUUID,
			wantModel: "Dell.PowerEdge R740",
		},
		{
			name: "valid without manufacturer/product gives empty model",
			body: marshal(t, &eveuuid.UuidResponse{
				Uuid: goodUUID,
			}),
			wantUUID:     goodUUID,
			emptyModelOK: true,
		},
		{
			name: "manufacturer only is not enough for a model",
			body: marshal(t, &eveuuid.UuidResponse{
				Uuid:         goodUUID,
				Manufacturer: "Dell",
			}),
			wantUUID:     goodUUID,
			emptyModelOK: true,
		},
		{
			name: "uuid with surrounding whitespace is trimmed",
			body: marshal(t, &eveuuid.UuidResponse{
				Uuid: "  " + goodUUID + "\n",
			}),
			wantUUID:     goodUUID,
			emptyModelOK: true,
		},
		{
			name:         "invalid uuid string returns error",
			body:         marshal(t, &eveuuid.UuidResponse{Uuid: "not-a-uuid"}),
			wantParseErr: true,
		},
		{
			name:         "garbage bytes fail proto unmarshal",
			body:         []byte("not a protobuf"),
			wantParseErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotUUID, gotModel, err := parseUUIDResponse(nil, tc.body)
			if tc.wantParseErr {
				if err == nil {
					t.Fatalf("want error, got UUID=%s model=%q", gotUUID, gotModel)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			wantUUID, _ := uuid.FromString(tc.wantUUID)
			if gotUUID != wantUUID {
				t.Errorf("UUID = %s, want %s", gotUUID, wantUUID)
			}
			if tc.emptyModelOK {
				if gotModel != "" {
					t.Errorf("hardwaremodel = %q, want empty", gotModel)
				}
				return
			}
			if gotModel != tc.wantModel {
				t.Errorf("hardwaremodel = %q, want %q", gotModel, tc.wantModel)
			}
		})
	}
}

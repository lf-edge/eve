// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestPrepareStdinForBridgeDelegateDefaultRoutePolicy(t *testing.T) {
	tests := []struct {
		name                  string
		kind                  kubeAppNetKind
		wantDefaultGateway    bool
		wantRouteDestinations []string
	}{
		{"ordinary or native workload", kubeAppNetKindNative, true,
			[]string{"10.42.0.0/16"}},
		{"controller-managed EVE application", kubeAppNetKindController, false,
			[]string{"10.42.0.0/16", clusterSvcIPRange, "10.244.244.1/28"}},
		{"native workload with default-route request", kubeAppNetKindNativeNIDefault,
			false, []string{"10.42.0.0/16", clusterSvcIPRange, "10.244.244.1/28"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			input := rawJSONStruct{
				"nodeIP": "10.244.244.1/28",
				"ipam": rawJSONStruct{"routes": []interface{}{
					rawJSONStruct{"dst": "10.42.0.0/16"},
				}},
			}
			raw, err := prepareStdinForBridgeDelegate(input, tc.kind)
			if err != nil {
				t.Fatal(err)
			}
			var got rawJSONStruct
			if err := json.Unmarshal(raw, &got); err != nil {
				t.Fatal(err)
			}
			if got["isDefaultGateway"] != tc.wantDefaultGateway {
				t.Fatalf("isDefaultGateway=%v, want %v", got["isDefaultGateway"],
					tc.wantDefaultGateway)
			}
			if routeDestinations := bridgeRouteDestinations(t, got); !reflect.DeepEqual(
				routeDestinations, tc.wantRouteDestinations) {
				t.Fatalf("route destinations=%v, want %v", routeDestinations,
					tc.wantRouteDestinations)
			}
		})
	}
}

func TestReadKubeAppNetKind(t *testing.T) {
	originalMarkerDir := kubeAppMarkerDir
	kubeAppMarkerDir = t.TempDir()
	t.Cleanup(func() { kubeAppMarkerDir = originalMarkerDir })

	namespace, podName := "eve-kube-app", "native-workload-test"
	if kind, known := readKubeAppNetKind(namespace, podName); known {
		t.Fatalf("missing marker was reported known, with kind %q", kind)
	}

	markerPath := filepath.Join(kubeAppMarkerDir, namespace+"_"+podName)
	if err := os.WriteFile(markerPath, []byte(kubeAppNetKindNative), 0o600); err != nil {
		t.Fatalf("failed to create marker: %v", err)
	}
	kind, known := readKubeAppNetKind(namespace, podName)
	if !known {
		t.Fatal("created marker was not detected")
	}
	if kind != kubeAppNetKindNative {
		t.Fatalf("kind=%q, want %q", kind, kubeAppNetKindNative)
	}
}

func bridgeRouteDestinations(t *testing.T, stdinArgs rawJSONStruct) []string {
	t.Helper()
	ipamArgs, ok := stdinArgs["ipam"].(map[string]interface{})
	if !ok {
		t.Fatalf("ipam=%T, want object", stdinArgs["ipam"])
	}
	routes, ok := ipamArgs["routes"].([]interface{})
	if !ok {
		t.Fatalf("routes=%T, want array", ipamArgs["routes"])
	}
	destinations := make([]string, 0, len(routes))
	for _, route := range routes {
		routeArgs, ok := route.(map[string]interface{})
		if !ok {
			t.Fatalf("route=%T, want object", route)
		}
		destination, ok := routeArgs["dst"].(string)
		if !ok {
			t.Fatalf("route destination=%T, want string", routeArgs["dst"])
		}
		destinations = append(destinations, destination)
	}
	return destinations
}

func TestPrepareStdinForDhcpDelegateUsesStableMACClientID(t *testing.T) {
	stdinArgs := rawJSONStruct{
		"cniVersion": "0.3.1",
		"name":       "ni-cluster-switch-ni",
		"type":       "eve-bridge",
	}
	mac := net.HardwareAddr{0x02, 0x16, 0x3e, 0x83, 0x6f, 0xb1}

	dhcpArgs, err := prepareStdinForDhcpDelegate(stdinArgs, mac)
	if err != nil {
		t.Fatalf("prepareStdinForDhcpDelegate failed: %v", err)
	}
	var got struct {
		IPAM struct {
			Type    string `json:"type"`
			Provide []struct {
				Option string `json:"option"`
				Value  string `json:"value"`
			} `json:"provide"`
		} `json:"ipam"`
	}
	if err := json.Unmarshal(dhcpArgs, &got); err != nil {
		t.Fatalf("failed to decode DHCP delegate config: %v", err)
	}
	if got.IPAM.Type != "dhcp" {
		t.Fatalf("unexpected IPAM type %q", got.IPAM.Type)
	}
	if len(got.IPAM.Provide) != 1 {
		t.Fatalf("expected one provided DHCP option, got %+v", got.IPAM.Provide)
	}
	if got.IPAM.Provide[0].Option != "dhcp-client-identifier" {
		t.Fatalf("unexpected provided DHCP option %q", got.IPAM.Provide[0].Option)
	}
	wantClientID := "\x00eve-mac-02163e836fb1"
	if got.IPAM.Provide[0].Value != wantClientID {
		t.Fatalf("unexpected DHCP client ID %q, want %q",
			got.IPAM.Provide[0].Value, wantClientID)
	}
}

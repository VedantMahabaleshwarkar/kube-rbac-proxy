/*
Copyright 2026 the kube-rbac-proxy maintainers. All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package audit

import (
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestSourceEndpoint(t *testing.T) {
	tests := []struct {
		name             string
		remoteAddr       string
		forwardedFor     []string
		useForwardedFor  bool
		wantEndpoint     Endpoint
		wantForwardedFor []string
	}{
		{name: "IPv4 peer", remoteAddr: "192.0.2.10:8443", wantEndpoint: Endpoint{IP: "192.0.2.10", Port: 8443}},
		{name: "IPv6 peer", remoteAddr: "[2001:db8::10]:8443", wantEndpoint: Endpoint{IP: "2001:db8::10", Port: 8443}},
		{name: "bare IPv4 peer", remoteAddr: "192.0.2.11", wantEndpoint: Endpoint{IP: "192.0.2.11"}},
		{name: "bare IPv6 peer", remoteAddr: "2001:db8::11", wantEndpoint: Endpoint{IP: "2001:db8::11"}},
		{name: "missing forwarded header falls back to peer", remoteAddr: "192.0.2.12:9443", useForwardedFor: true, wantEndpoint: Endpoint{IP: "192.0.2.12", Port: 9443}},
		{
			name:             "rightmost valid forwarded address wins",
			remoteAddr:       "192.0.2.10:8443",
			forwardedFor:     []string{"203.0.113.99, malformed", "10.0.0.15"},
			useForwardedFor:  true,
			wantEndpoint:     Endpoint{IP: "10.0.0.15"},
			wantForwardedFor: []string{"203.0.113.99", "10.0.0.15"},
		},
		{
			name:             "IPv6 forwarded address",
			remoteAddr:       "192.0.2.10:8443",
			forwardedFor:     []string{"198.51.100.1, 2001:db8::5"},
			useForwardedFor:  true,
			wantEndpoint:     Endpoint{IP: "2001:db8::5"},
			wantForwardedFor: []string{"198.51.100.1", "2001:db8::5"},
		},
		{
			name:         "untrusted forwarded header is ignored",
			remoteAddr:   "192.0.2.10:8443",
			forwardedFor: []string{"203.0.113.99"},
			wantEndpoint: Endpoint{IP: "192.0.2.10", Port: 8443},
		},
		{
			name:            "malformed forwarded values fall back to peer",
			remoteAddr:      "192.0.2.10:8443",
			forwardedFor:    []string{"unknown, 192.0.2.1:8080"},
			useForwardedFor: true,
			wantEndpoint:    Endpoint{IP: "192.0.2.10", Port: 8443},
		},
		{name: "invalid peer is unknown", remoteAddr: "not-an-address", wantEndpoint: Endpoint{Name: "Unknown"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "http://proxy/infer", nil)
			req.RemoteAddr = tt.remoteAddr
			for _, value := range tt.forwardedFor {
				req.Header.Add("X-Forwarded-For", value)
			}
			gotEndpoint, gotForwardedFor := sourceEndpoint(req, tt.useForwardedFor)
			if diff := cmp.Diff(tt.wantEndpoint, gotEndpoint); diff != "" {
				t.Errorf("endpoint mismatch (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(tt.wantForwardedFor, gotForwardedFor); diff != "" {
				t.Errorf("forwarded addresses mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestDestinationEndpoint(t *testing.T) {
	tests := []struct {
		name     string
		upstream string
		want     *Endpoint
	}{
		{name: "hostname and explicit port", upstream: "https://model.example:9443", want: &Endpoint{Hostname: "model.example", Port: 9443}},
		{name: "IPv4 and inferred HTTP port", upstream: "http://192.0.2.20", want: &Endpoint{IP: "192.0.2.20", Port: 80}},
		{name: "IPv6 and inferred HTTPS port", upstream: "https://[2001:db8::20]", want: &Endpoint{IP: "2001:db8::20", Port: 443}},
		{name: "missing host", upstream: "/relative", want: nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			upstream, err := url.Parse(tt.upstream)
			if err != nil {
				t.Fatal(err)
			}
			if diff := cmp.Diff(tt.want, destinationEndpoint(upstream)); diff != "" {
				t.Errorf("destination mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

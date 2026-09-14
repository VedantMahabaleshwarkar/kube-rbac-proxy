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
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
)

func sourceEndpoint(req *http.Request, useForwardedFor bool) (Endpoint, []string) {
	var forwardedFor []string
	if useForwardedFor {
		forwardedFor = validatedForwardedFor(req.Header.Values("X-Forwarded-For"))
		if len(forwardedFor) > 0 {
			return Endpoint{IP: forwardedFor[len(forwardedFor)-1]}, forwardedFor
		}
	}

	if endpoint, ok := endpointFromAddress(req.RemoteAddr); ok {
		return endpoint, forwardedFor
	}

	return Endpoint{Name: "Unknown"}, forwardedFor
}

func validatedForwardedFor(values []string) []string {
	var addresses []string
	for _, value := range values {
		for _, candidate := range strings.Split(value, ",") {
			addr, err := netip.ParseAddr(strings.TrimSpace(candidate))
			if err != nil || addr.Zone() != "" {
				continue
			}
			addresses = append(addresses, addr.String())
		}
	}
	return addresses
}

func endpointFromAddress(address string) (Endpoint, bool) {
	host, portString, err := net.SplitHostPort(address)
	if err != nil {
		addr, parseErr := netip.ParseAddr(strings.TrimSpace(address))
		if parseErr != nil {
			return Endpoint{}, false
		}
		return Endpoint{IP: addr.WithZone("").String()}, true
	}

	addr, err := netip.ParseAddr(strings.TrimSpace(host))
	if err != nil {
		return Endpoint{}, false
	}

	endpoint := Endpoint{IP: addr.WithZone("").String()}
	if port, err := strconv.Atoi(portString); err == nil && port > 0 && port <= 65535 {
		endpoint.Port = port
	}
	return endpoint, true
}

func destinationEndpoint(upstream *url.URL) *Endpoint {
	if upstream == nil || upstream.Hostname() == "" {
		return nil
	}

	host := upstream.Hostname()
	endpoint := &Endpoint{}
	if addr, err := netip.ParseAddr(host); err == nil {
		endpoint.IP = addr.WithZone("").String()
	} else {
		endpoint.Hostname = host
	}

	if port, err := strconv.Atoi(upstream.Port()); err == nil && port > 0 && port <= 65535 {
		endpoint.Port = port
	} else {
		switch strings.ToLower(upstream.Scheme) {
		case "http":
			endpoint.Port = 80
		case "https":
			endpoint.Port = 443
		}
	}

	return endpoint
}

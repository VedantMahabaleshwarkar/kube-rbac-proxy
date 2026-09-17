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

package app

import (
	cryptotls "crypto/tls"
	"testing"

	"github.com/brancz/kube-rbac-proxy/cmd/kube-rbac-proxy/app/options"
)

func TestApplyTLSConfigFromFlags(t *testing.T) {
	proxyOptions := options.NewProxyRunOptions()
	flagSets := proxyOptions.Flags()
	flagSet := flagSets.FlagSet("kube-rbac-proxy")
	if err := flagSet.Parse([]string{"--tls-curve-preferences=23,4588"}); err != nil {
		t.Fatalf("parsing flags: %v", err)
	}

	config := &cryptotls.Config{}
	if err := applyTLSConfig(config, proxyOptions.TLS); err != nil {
		t.Fatalf("applyTLSConfig() returned an error: %v", err)
	}

	for _, want := range []cryptotls.CurveID{cryptotls.CurveP256, cryptotls.X25519MLKEM768} {
		found := false
		for _, got := range config.CurvePreferences {
			if got == want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("curve %v is missing from %v", want, config.CurvePreferences)
		}
	}
	if config.MinVersion != cryptotls.VersionTLS12 {
		t.Errorf("MinVersion = %d, want %d", config.MinVersion, cryptotls.VersionTLS12)
	}
}

func TestApplyTLSConfigRejectsUnsupportedCurveID(t *testing.T) {
	config := &cryptotls.Config{}
	if err := applyTLSConfig(config, &options.TLSConfig{MinVersion: "VersionTLS12", CurvePreferences: []int32{65535}}); err == nil {
		t.Fatal("expected unsupported CurveID to return an error")
	}
}

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

package tls

import (
	cryptotls "crypto/tls"
	"testing"
)

func TestParseCurvePreferences(t *testing.T) {
	got, err := ParseCurvePreferences([]int32{23, 29, 4588, 4587, 4589})
	if err != nil {
		t.Fatalf("ParseCurvePreferences() returned an error: %v", err)
	}
	want := []cryptotls.CurveID{
		cryptotls.CurveP256,
		cryptotls.X25519,
		cryptotls.X25519MLKEM768,
		cryptotls.SecP256r1MLKEM768,
		cryptotls.SecP384r1MLKEM1024,
	}
	for _, curve := range want {
		found := false
		for _, actual := range got {
			if actual == curve {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("curve %v is missing from %v", curve, got)
		}
	}
}

func TestParseCurvePreferencesRejectsInvalidInput(t *testing.T) {
	for _, ids := range [][]int32{{0}, {65536}, {23, 23}} {
		if _, err := ParseCurvePreferences(ids); err == nil {
			t.Errorf("ParseCurvePreferences(%v) returned no error", ids)
		}
	}
}

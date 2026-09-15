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
	"strings"
	"testing"
)

func TestProfileValidation(t *testing.T) {
	tests := []struct {
		name    string
		value   Profile
		wantErr bool
	}{
		{name: "none", value: ProfileNone},
		{name: "metadata", value: ProfileMetadata},
		{name: "empty", value: "", wantErr: true},
		{name: "future request profile", value: "request", wantErr: true},
		{name: "case variant", value: "Metadata", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.value.Validate()
			if (err != nil) != tt.wantErr {
				t.Fatalf("Profile(%q).Validate() error = %v, wantErr %t", tt.value, err, tt.wantErr)
			}
			if tt.wantErr && !strings.Contains(err.Error(), `must be one of "none" or "metadata"`) {
				t.Fatalf("validation error = %q, want supported values", err)
			}
		})
	}
}

func TestProfileSetRejectsUnsupportedValueWithoutMutation(t *testing.T) {
	profile := ProfileNone
	if err := (&profile).Set("request"); err == nil {
		t.Fatal("Set(request) error = nil, want unsupported-profile error")
	}
	if profile != ProfileNone {
		t.Fatalf("profile = %q after failed Set, want %q", profile, ProfileNone)
	}
	if err := (&profile).Set("metadata"); err != nil {
		t.Fatalf("Set(metadata) error = %v", err)
	}
	if profile != ProfileMetadata {
		t.Fatalf("profile = %q, want %q", profile, ProfileMetadata)
	}
}

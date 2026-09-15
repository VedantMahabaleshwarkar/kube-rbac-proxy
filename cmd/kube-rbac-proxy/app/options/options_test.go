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

package options

import (
	"strings"
	"testing"

	"github.com/brancz/kube-rbac-proxy/pkg/audit"
)

func TestAuditFlags(t *testing.T) {
	o := NewProxyRunOptions()
	flagSets := o.Flags()
	flagSet := flagSets.FlagSet("audit logging")
	for _, name := range []string{
		"audit-log-profile",
		"audit-resource-name",
		"audit-resource-namespace",
		"audit-resource-type",
		"audit-ai-provider",
		"audit-use-forwarded-for",
	} {
		if flagSet.Lookup(name) == nil {
			t.Fatalf("flag --%s is not registered", name)
		}
	}

	for _, name := range []string{"audit-log-enabled", "audit-isvc-name", "audit-isvc-namespace"} {
		if flagSet.Lookup(name) != nil {
			t.Fatalf("legacy flag --%s must not be registered", name)
		}
	}

	if o.AuditLogProfile != audit.ProfileNone || o.AuditUseForwardedFor || o.AuditResourceName != "" || o.AuditResourceNamespace != "" || o.AuditResourceType != "" || o.AuditAIProvider != "" {
		t.Fatalf("unexpected audit defaults: %+v", o)
	}

	if err := flagSet.Parse([]string{
		"--audit-log-profile=metadata",
		"--audit-resource-name=model",
		"--audit-resource-namespace=models",
		"--audit-resource-type=InferenceService",
		"--audit-ai-provider=KServe",
		"--audit-use-forwarded-for",
	}); err != nil {
		t.Fatal(err)
	}
	if o.AuditLogProfile != audit.ProfileMetadata || !o.AuditUseForwardedFor || o.AuditResourceName != "model" || o.AuditResourceNamespace != "models" || o.AuditResourceType != "InferenceService" || o.AuditAIProvider != "KServe" {
		t.Fatalf("audit flags were not parsed: %+v", o)
	}
}

func TestAuditLogProfileFlagRejectsUnimplementedProfile(t *testing.T) {
	o := NewProxyRunOptions()
	flagSets := o.Flags()
	flagSet := flagSets.FlagSet("audit logging")
	err := flagSet.Set("audit-log-profile", "request")
	if err == nil || !strings.Contains(err.Error(), `must be one of "none" or "metadata"`) {
		t.Fatalf("Parse(request) error = %v, want supported-profile error", err)
	}
}

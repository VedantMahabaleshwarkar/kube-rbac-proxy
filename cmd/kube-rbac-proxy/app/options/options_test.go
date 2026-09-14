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

import "testing"

func TestAuditFlags(t *testing.T) {
	o := NewProxyRunOptions()
	flagSets := o.Flags()
	flagSet := flagSets.FlagSet("audit logging")
	for _, name := range []string{
		"audit-log-enabled",
		"audit-isvc-name",
		"audit-isvc-namespace",
		"audit-use-forwarded-for",
	} {
		if flagSet.Lookup(name) == nil {
			t.Fatalf("flag --%s is not registered", name)
		}
	}

	if o.AuditLogEnabled || o.AuditUseForwardedFor || o.AuditISVCName != "" || o.AuditISVCNamespace != "" {
		t.Fatalf("unexpected audit defaults: %+v", o)
	}

	if err := flagSet.Parse([]string{
		"--audit-log-enabled",
		"--audit-isvc-name=model",
		"--audit-isvc-namespace=models",
		"--audit-use-forwarded-for",
	}); err != nil {
		t.Fatal(err)
	}
	if !o.AuditLogEnabled || !o.AuditUseForwardedFor || o.AuditISVCName != "model" || o.AuditISVCNamespace != "models" {
		t.Fatalf("audit flags were not parsed: %+v", o)
	}
}

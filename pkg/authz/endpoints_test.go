/*
Copyright 2022 the kube-rbac-proxy maintainers. All rights reserved.

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

package authz

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/authorization/authorizer"
)

func testUser(name string) user.Info {
	return &user.DefaultInfo{Name: name}
}

func TestMatchEndpoint(t *testing.T) {
	cases := []struct {
		pattern       string
		path          string
		expectedMatch bool
	}{
		{"/api/v1/jobs", "/api/v1/jobsabc", false},
		{"/api/v1/jobs", "/api/v1/jobs/123", false},
		{"/api/v1/jobs/*", "/api/v1/jobs", false},
		{"/api/v1/jobs/*", "/api/v1/jobs/123", true},
		{"/api/v1/jobs/*", "/api/v1/jobs/123/details", false},
		{"/api/*/jobs/*", "/api/v2/jobs/abc", true},
		{"/api/*/jobs/*", "/api/v2/users/123", false},
		{"/api/v1/evaluations/jobs/*/events", "/api/v1/evaluations/jobs", false},
		{"/api/v1/evaluations/jobs/*/events", "/api/v1/evaluations/jobs/j1/events", true},
		{"/api/v1/evaluations/jobs/*/events", "/api/v1/evaluations/jobs/j1/events/extra", false},
		{"/api/v1/jobs/*", "//api/v1/jobs/99", true},
		{"/api/v1/jobs/*", "/api/v1/jobs/99/", true},
	}

	for _, c := range cases {
		ep := Endpoint{Path: c.pattern, PathParts: strings.Split(c.pattern, "/")}
		match := MatchEndpoint(c.path, ep)
		if match != c.expectedMatch {
			t.Errorf("MatchEndpoint(%q, pattern %q) = %v, want %v", c.path, c.pattern, match, c.expectedMatch)
		}
	}
}

func TestHTTPToKubeVerb(t *testing.T) {
	if got, want := HTTPToKubeVerb(http.MethodPost), "create"; got != want {
		t.Fatalf("HTTPToKubeVerb(POST) = %q, want %q", got, want)
	}
}

func TestMatchMethods(t *testing.T) {
	if matchMethods(http.MethodGet, nil) {
		t.Fatal("nil methods slice must not match")
	}
	if matchMethods(http.MethodGet, []string{}) {
		t.Fatal("empty methods slice must not match")
	}
	if !matchMethods(http.MethodGet, []string{"get", "head"}) {
		t.Fatal("GET must match entry")
	}
	if matchMethods(http.MethodPost, []string{"get"}) {
		t.Fatal("POST must not match GET-only list")
	}
	if !matchMethods("GET", []string{"get"}) {
		t.Fatal("method matching must be case-insensitive")
	}
}

func TestValidateAuthorizationConfig_EndpointMappingsMethods(t *testing.T) {
	if err := ValidateAuthorizationConfig(nil); err != nil {
		t.Fatalf("nil config: %v", err)
	}
	if err := ValidateAuthorizationConfig(&Config{}); err != nil {
		t.Fatalf("empty endpoints: %v", err)
	}
	err := ValidateAuthorizationConfig(&Config{
		Endpoints: []Endpoint{{
			Path: "/p",
			Mappings: []EndpointMapping{{
				Methods:   nil,
				Resources: []EndpointResourceRule{{ResourceAttributes: ResourceAttributes{Verb: "get"}}},
			}},
		}},
	})
	if err == nil {
		t.Fatal("expected error for nil methods")
	}
	err = ValidateAuthorizationConfig(&Config{
		Endpoints: []Endpoint{{
			Path: "/p",
			Mappings: []EndpointMapping{{
				Methods:   []string{},
				Resources: []EndpointResourceRule{{ResourceAttributes: ResourceAttributes{Verb: "get"}}},
			}},
		}},
	})
	if err == nil {
		t.Fatal("expected error for empty methods")
	}
	if err := ValidateAuthorizationConfig(&Config{
		Endpoints: []Endpoint{{
			Path: "/p",
			Mappings: []EndpointMapping{{
				Methods:   []string{"get"},
				Resources: []EndpointResourceRule{{ResourceAttributes: ResourceAttributes{Verb: "get"}}},
			}},
		}},
	}); err != nil {
		t.Fatal(err)
	}
}

func TestValidateAuthorizationConfig_invalidEndpointShape(t *testing.T) {
	cases := []struct {
		name   string
		cfg    *Config
		substr string
	}{
		{
			name: "empty path",
			cfg: &Config{Endpoints: []Endpoint{{
				Path: "",
				Mappings: []EndpointMapping{{
					Methods:   []string{"get"},
					Resources: []EndpointResourceRule{{ResourceAttributes: ResourceAttributes{Verb: "get"}}},
				}},
			}}},
			substr: "path must be non-empty",
		},
		{
			name: "whitespace-only path",
			cfg: &Config{Endpoints: []Endpoint{{
				Path: " \t ",
				Mappings: []EndpointMapping{{
					Methods:   []string{"get"},
					Resources: []EndpointResourceRule{{ResourceAttributes: ResourceAttributes{Verb: "get"}}},
				}},
			}}},
			substr: "path must be non-empty",
		},
		{
			name: "no mappings",
			cfg: &Config{Endpoints: []Endpoint{{
				Path:     "/p",
				Mappings: nil,
			}}},
			substr: "mappings must contain",
		},
		{
			name: "empty mappings slice",
			cfg: &Config{Endpoints: []Endpoint{{
				Path:     "/p",
				Mappings: []EndpointMapping{},
			}}},
			substr: "mappings must contain",
		},
		{
			name: "empty resources",
			cfg: &Config{Endpoints: []Endpoint{{
				Path: "/p",
				Mappings: []EndpointMapping{{
					Methods:   []string{"get"},
					Resources: nil,
				}},
			}}},
			substr: "at least one resource rule",
		},
		{
			name: "empty resources slice",
			cfg: &Config{Endpoints: []Endpoint{{
				Path: "/p",
				Mappings: []EndpointMapping{{
					Methods:   []string{"get"},
					Resources: []EndpointResourceRule{},
				}},
			}}},
			substr: "at least one resource rule",
		},
		{
			name: "byHttpHeader with empty name",
			cfg: &Config{Endpoints: []Endpoint{{
				Path: "/p",
				Mappings: []EndpointMapping{{
					Methods: []string{"get"},
					Resources: []EndpointResourceRule{{
						Rewrites:           SubjectAccessReviewRewrites{ByHTTPHeader: &HTTPHeaderRewriteConfig{Name: ""}},
						ResourceAttributes: ResourceAttributes{Verb: "get", Resource: "pods"},
					}},
				}},
			}}},
			substr: "byHttpHeader",
		},
		{
			name: "byQueryParameter with empty name",
			cfg: &Config{Endpoints: []Endpoint{{
				Path: "/p",
				Mappings: []EndpointMapping{{
					Methods: []string{"get"},
					Resources: []EndpointResourceRule{{
						Rewrites:           SubjectAccessReviewRewrites{ByQueryParameter: &QueryParameterRewriteConfig{Name: ""}},
						ResourceAttributes: ResourceAttributes{Verb: "get", Resource: "pods"},
					}},
				}},
			}}},
			substr: "byQueryParameter",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateAuthorizationConfig(tc.cfg)
			if err == nil || !strings.Contains(err.Error(), tc.substr) {
				t.Fatalf("ValidateAuthorizationConfig() err=%v, want substring %q", err, tc.substr)
			}
		})
	}
}

func TestEndpointAttributesFromRequest_wrongHTTPMethodOnMatchedPath(t *testing.T) {
	cfg := &Config{
		Endpoints: []Endpoint{{
			Path: "/api/v1/evaluations/jobs/*/events",
			Mappings: []EndpointMapping{{
				Methods: []string{"post"},
				Resources: []EndpointResourceRule{{
					ResourceAttributes: ResourceAttributes{Verb: "create", Resource: "status-events"},
				}},
			}},
		}},
	}
	cfg.PrepareEndpoints()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/evaluations/jobs/j1/events", nil)
	attrs, matched, err := EndpointAttributesFromRequest(testUser("u"), req, cfg)
	if attrs != nil {
		t.Fatalf("expected nil attrs, got %#v", attrs)
	}
	if !matched {
		t.Fatal("expected matched path (Format2 owns the request)")
	}
	if !errors.Is(err, ErrEndpointMethodNotAllowed) {
		t.Fatalf("got err=%v, want ErrEndpointMethodNotAllowed", err)
	}
}

func TestEndpointAttributesFromRequest_StatusEvents(t *testing.T) {
	cfg := &Config{
		Endpoints: []Endpoint{{
			Path: "/api/v1/evaluations/jobs/*/events",
			Mappings: []EndpointMapping{{
				Methods: []string{"post"},
				Resources: []EndpointResourceRule{{
					Rewrites: SubjectAccessReviewRewrites{
						ByHTTPHeader: &HTTPHeaderRewriteConfig{Name: "X-Tenant"},
					},
					ResourceAttributes: ResourceAttributes{
						Namespace: "{{.FromHeader}}",
						APIGroup:  "trustyai.opendatahub.io",
						Resource:  "status-events",
						Verb:      "create",
					},
				}},
			}},
		}},
	}
	cfg.PrepareEndpoints()

	req := httptest.NewRequest(http.MethodPost, "/api/v1/evaluations/jobs/job-1/events", nil)
	req.Header.Set("X-Tenant", "tenant-ns")

	attrs, matched, err := EndpointAttributesFromRequest(testUser("u"), req, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !matched {
		t.Fatal("expected path to match endpoints")
	}
	if len(attrs) != 1 {
		t.Fatalf("len(attrs)=%d, want 1", len(attrs))
	}
	rec := attrs[0].(authorizer.AttributesRecord)
	if rec.Namespace != "tenant-ns" || rec.APIGroup != "trustyai.opendatahub.io" || rec.Resource != "status-events" || rec.Verb != "create" {
		t.Fatalf("unexpected record: %#v", rec)
	}
}

func TestEndpointAttributesFromRequest_MissingHeader(t *testing.T) {
	cfg := &Config{
		Endpoints: []Endpoint{{
			Path: "/api/v1/evaluations/jobs/*/events",
			Mappings: []EndpointMapping{{
				Methods: []string{"post"},
				Resources: []EndpointResourceRule{{
					Rewrites: SubjectAccessReviewRewrites{
						ByHTTPHeader: &HTTPHeaderRewriteConfig{Name: "X-Tenant"},
					},
					ResourceAttributes: ResourceAttributes{Namespace: "{{.FromHeader}}", Verb: "create"},
				}},
			}},
		}},
	}
	cfg.PrepareEndpoints()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/evaluations/jobs/j1/events", nil)
	_, matched, err := EndpointAttributesFromRequest(testUser("u"), req, cfg)
	if !matched {
		t.Fatal("expected matched path")
	}
	if err == nil {
		t.Fatal("expected error for missing header")
	}
}

func TestEndpointAttributesFromRequest_InvalidResourceAttributesTemplate(t *testing.T) {
	cfg := &Config{
		Endpoints: []Endpoint{{
			Path: "/x",
			Mappings: []EndpointMapping{{
				Methods: []string{"get"},
				Resources: []EndpointResourceRule{{
					ResourceAttributes: ResourceAttributes{
						Namespace: "ns",
						Resource:  "pods",
						Verb:      "{{", // unclosed template action → parse error
					},
				}},
			}},
		}},
	}
	cfg.PrepareEndpoints()
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	_, matched, err := EndpointAttributesFromRequest(testUser("u"), req, cfg)
	if !matched {
		t.Fatal("expected matched path")
	}
	if err == nil {
		t.Fatal("expected template parse error")
	}
	if !strings.Contains(err.Error(), "verb") || !strings.Contains(err.Error(), "parse") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestEndpointAttributesFromRequest_NoMatchUsesFormat1(t *testing.T) {
	cfg := &Config{
		Endpoints: []Endpoint{{
			Path: "/api/v1/other",
			Mappings: []EndpointMapping{{
				Methods: []string{"get"},
				Resources: []EndpointResourceRule{{
					ResourceAttributes: ResourceAttributes{Resource: "should-not-use"},
				}},
			}},
		}},
		Rewrites: &SubjectAccessReviewRewrites{
			ByQueryParameter: &QueryParameterRewriteConfig{Name: "namespace"},
		},
		ResourceAttributes: &ResourceAttributes{
			Namespace:   "{{ .Value }}",
			APIVersion:  "v1",
			Resource:    "namespace",
			Subresource: "metrics",
		},
	}
	cfg.PrepareEndpoints()
	// This path does not match /api/v1/other. Format1 applies in pkg/proxy after
	// EndpointAttributesFromRequest returns matched=false. Here we only assert the latter:
	req := httptest.NewRequest(http.MethodGet, "/metrics?namespace=ns1", nil)
	attrs, matched, err := EndpointAttributesFromRequest(testUser("u"), req, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if matched {
		t.Fatal("did not expect endpoint match")
	}
	if attrs != nil {
		t.Fatalf("expected nil attrs from EndpointAttributesFromRequest, got %#v", attrs)
	}
}

func TestCollectRewriteParams(t *testing.T) {
	rw := &SubjectAccessReviewRewrites{
		ByQueryParameter: &QueryParameterRewriteConfig{Name: "ns"},
		ByHTTPHeader:     &HTTPHeaderRewriteConfig{Name: "X-Org"},
	}
	req := httptest.NewRequest(http.MethodGet, "/x?ns=a&ns=b", nil)
	req.Header.Set("X-Org", "c")
	params := CollectRewriteParams(req, rw)
	if len(params) != 3 {
		t.Fatalf("params=%v want len 3", params)
	}
}

func TestMatchEndpoint_CapturesNamedSegments(t *testing.T) {
	cases := []struct {
		pattern string
		path    string
		want    map[string]string
	}{
		{"/api/v1/tenants/{tenant}/metrics", "/api/v1/tenants/tenant-a/metrics", map[string]string{"tenant": "tenant-a"}},
		{"/api/{version}/tenants/{tenant}/jobs/{job}", "/api/v2/tenants/my-ns/jobs/job-1", map[string]string{"version": "v2", "tenant": "my-ns", "job": "job-1"}},
		{"/api/v1/jobs/*/{id}", "/api/v1/jobs/queue/123", map[string]string{"id": "123"}},
		{"/api/v1/jobs", "/api/v1/jobs", map[string]string{}},
	}
	for _, c := range cases {
		ep := Endpoint{Path: c.pattern, PathParts: strings.Split(c.pattern, "/")}
		if !MatchEndpoint(c.path, ep) {
			t.Errorf("MatchEndpoint(%q, %q): expected match", c.path, c.pattern)
			continue
		}
		captured := extractPathCaptures(c.path, ep)
		if !reflect.DeepEqual(captured, c.want) {
			t.Errorf("extractPathCaptures(%q, %q) captured=%v, want %v", c.path, c.pattern, captured, c.want)
		}
	}
}

func TestEndpointAttributesFromRequest_NamedPathCaptures(t *testing.T) {
	cfg := &Config{
		Endpoints: []Endpoint{{
			Path: "/api/v1/tenants/{tenant}/reports/{report}",
			Mappings: []EndpointMapping{{
				Methods: []string{"get"},
				Resources: []EndpointResourceRule{{
					ResourceAttributes: ResourceAttributes{
						Namespace: "{{ index .PathParams \"tenant\" }}",
						Name:      "{{ index .PathParams \"report\" }}",
						APIGroup:  "reports.example.io",
						Resource:  "reports",
					},
				}},
			}},
		}},
	}
	cfg.PrepareEndpoints()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/tenants/tenant-a/reports/report-17", nil)
	attrs, matched, err := EndpointAttributesFromRequest(testUser("u"), req, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !matched {
		t.Fatal("expected path to match")
	}
	if len(attrs) != 1 {
		t.Fatalf("len(attrs)=%d, want 1", len(attrs))
	}
	rec := attrs[0].(authorizer.AttributesRecord)
	if rec.Namespace != "tenant-a" || rec.Name != "report-17" {
		t.Fatalf("unexpected resource identity: namespace=%q name=%q", rec.Namespace, rec.Name)
	}
	if rec.APIGroup != "reports.example.io" || rec.Resource != "reports" {
		t.Fatalf("unexpected resource: apiGroup=%q resource=%q", rec.APIGroup, rec.Resource)
	}
}

func TestEndpointAttributesFromRequest_PathDoesNotPopulateValue(t *testing.T) {
	cfg := &Config{
		Endpoints: []Endpoint{{
			Path: "/api/v1/namespaces/{namespace}/pods",
			Mappings: []EndpointMapping{{
				Methods: []string{"get"},
				Resources: []EndpointResourceRule{{
					ResourceAttributes: ResourceAttributes{
						Namespace: "{{.Value}}",
						Resource:  "pods",
					},
				}},
			}},
		}},
	}
	cfg.PrepareEndpoints()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/namespaces/kube-system/pods", nil)
	attrs, matched, err := EndpointAttributesFromRequest(testUser("u"), req, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !matched {
		t.Fatal("expected match")
	}
	rec := attrs[0].(authorizer.AttributesRecord)
	if rec.Namespace != "" {
		t.Fatalf("Namespace=%q, want empty because .Value is reserved for rewrites", rec.Namespace)
	}
}

func TestEndpointAttributesFromRequest_LegacyWildcardHeaderRewrite(t *testing.T) {
	// Legacy '*' segments still match, while the header supplies .Value for the SAR template.
	cfg := &Config{
		Endpoints: []Endpoint{{
			Path: "/api/v1/tenants/*/events",
			Mappings: []EndpointMapping{{
				Methods: []string{"post"},
				Resources: []EndpointResourceRule{{
					Rewrites: SubjectAccessReviewRewrites{
						ByHTTPHeader: &HTTPHeaderRewriteConfig{Name: "X-Tenant"},
					},
					ResourceAttributes: ResourceAttributes{
						Namespace: "{{.Value}}",
						Resource:  "events",
						Verb:      "create",
					},
				}},
			}},
		}},
	}
	cfg.PrepareEndpoints()

	req := httptest.NewRequest(http.MethodPost, "/api/v1/tenants/path-ns/events", nil)
	req.Header.Set("X-Tenant", "header-ns")

	attrs, _, err := EndpointAttributesFromRequest(testUser("u"), req, cfg)
	if err != nil {
		t.Fatal(err)
	}
	rec := attrs[0].(authorizer.AttributesRecord)
	if rec.Namespace != "header-ns" {
		t.Fatalf("Namespace=%q, want %q (legacy wildcard must not replace header .Value)", rec.Namespace, "header-ns")
	}
}

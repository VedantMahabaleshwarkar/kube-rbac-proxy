/*
Copyright 2025 the kube-rbac-proxy maintainers All rights reserved.

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
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/endpoints/request"
)

type testAuditEntry struct {
	Time     string `json:"time"`
	Level    string `json:"level"`
	Msg      string `json:"msg"`
	Request  struct {
		Method     string `json:"method"`
		Path       string `json:"path"`
		RemoteAddr string `json:"remote_addr"`
	} `json:"request"`
	Identity struct {
		User   string   `json:"user"`
		Groups []string `json:"groups"`
	} `json:"identity"`
	Response struct {
		StatusCode   int     `json:"status_code"`
		LatencyMs    float64 `json:"latency_ms"`
		BytesWritten int64   `json:"bytes_written"`
	} `json:"response"`
	Resource *struct {
		Name      string `json:"name"`
		Namespace string `json:"namespace"`
	} `json:"resource,omitempty"`
}

func parseAuditEntry(t *testing.T, buf *bytes.Buffer) testAuditEntry {
	t.Helper()
	var entry testAuditEntry
	raw := strings.TrimSpace(buf.String())
	if raw == "" {
		t.Fatal("audit log buffer is empty")
	}
	if err := json.Unmarshal([]byte(raw), &entry); err != nil {
		t.Fatalf("failed to unmarshal audit entry: %v\nraw: %s", err, raw)
	}
	return entry
}

func newTestConfig(buf *bytes.Buffer, resourceName, resourceNS string) *Config {
	return &Config{
		Enabled:      true,
		logger:       log.New(buf, "", 0),
		ResourceName: resourceName,
		ResourceNS:   resourceNS,
	}
}

func TestWithAuditLog(t *testing.T) {
	for _, tt := range []struct {
		name     string
		cfg      *Config
		handler  http.HandlerFunc
		reqSetup func(*http.Request) *http.Request
		check    func(*testing.T, *bytes.Buffer, *httptest.ResponseRecorder)
	}{
		{
			name: "success_with_identity",
			handler: func(w http.ResponseWriter, r *http.Request) {
				PopulateAuditData(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusOK)
					w.Write([]byte("ok"))
				}).ServeHTTP(w, r)
			},
			reqSetup: func(r *http.Request) *http.Request {
				ctx := request.WithUser(r.Context(), &user.DefaultInfo{
					Name:   "testuser",
					Groups: []string{"g1", "g2"},
				})
				return r.WithContext(ctx)
			},
			check: func(t *testing.T, buf *bytes.Buffer, rec *httptest.ResponseRecorder) {
				entry := parseAuditEntry(t, buf)
				if entry.Identity.User != "testuser" {
					t.Errorf("want user=testuser, have %s", entry.Identity.User)
				}
				if len(entry.Identity.Groups) != 2 || entry.Identity.Groups[0] != "g1" || entry.Identity.Groups[1] != "g2" {
					t.Errorf("want groups=[g1,g2], have %v", entry.Identity.Groups)
				}
				if entry.Response.StatusCode != 200 {
					t.Errorf("want status_code=200, have %d", entry.Response.StatusCode)
				}
				if entry.Response.BytesWritten != 2 {
					t.Errorf("want bytes_written=2, have %d", entry.Response.BytesWritten)
				}
			},
		},
		{
			name: "authn_failure_401",
			handler: func(w http.ResponseWriter, r *http.Request) {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
			},
			check: func(t *testing.T, buf *bytes.Buffer, rec *httptest.ResponseRecorder) {
				entry := parseAuditEntry(t, buf)
				if entry.Identity.User != "" {
					t.Errorf("want user=\"\", have %s", entry.Identity.User)
				}
				if len(entry.Identity.Groups) != 0 {
					t.Errorf("want groups=[], have %v", entry.Identity.Groups)
				}
				if entry.Response.StatusCode != 401 {
					t.Errorf("want status_code=401, have %d", entry.Response.StatusCode)
				}
			},
		},
		{
			name: "authz_denial_403",
			handler: func(w http.ResponseWriter, r *http.Request) {
				PopulateAuditData(func(w http.ResponseWriter, r *http.Request) {
					http.Error(w, "Forbidden", http.StatusForbidden)
				}).ServeHTTP(w, r)
			},
			reqSetup: func(r *http.Request) *http.Request {
				ctx := request.WithUser(r.Context(), &user.DefaultInfo{
					Name:   "denieduser",
					Groups: []string{"viewers"},
				})
				return r.WithContext(ctx)
			},
			check: func(t *testing.T, buf *bytes.Buffer, rec *httptest.ResponseRecorder) {
				entry := parseAuditEntry(t, buf)
				if entry.Identity.User != "denieduser" {
					t.Errorf("want user=denieduser, have %s", entry.Identity.User)
				}
				if entry.Response.StatusCode != 403 {
					t.Errorf("want status_code=403, have %d", entry.Response.StatusCode)
				}
			},
		},
		{
			name: "disabled",
			cfg:  &Config{Enabled: false},
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			},
			check: func(t *testing.T, buf *bytes.Buffer, rec *httptest.ResponseRecorder) {
				if buf.Len() != 0 {
					t.Errorf("want no output, have %s", buf.String())
				}
			},
		},
		{
			name: "nil_config",
			cfg:  nil,
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			},
			check: func(t *testing.T, buf *bytes.Buffer, rec *httptest.ResponseRecorder) {
				if rec.Code != http.StatusOK {
					t.Errorf("want status 200, have %d", rec.Code)
				}
			},
		},
		{
			name: "resource_present",
			cfg: &Config{
				Enabled:      true,
				ResourceName: "mymodel",
				ResourceNS:   "mynamespace",
			},
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			},
			check: func(t *testing.T, buf *bytes.Buffer, rec *httptest.ResponseRecorder) {
				entry := parseAuditEntry(t, buf)
				if entry.Resource == nil {
					t.Fatal("want resource present, have nil")
				}
				if entry.Resource.Name != "mymodel" {
					t.Errorf("want resource.name=mymodel, have %s", entry.Resource.Name)
				}
				if entry.Resource.Namespace != "mynamespace" {
					t.Errorf("want resource.namespace=mynamespace, have %s", entry.Resource.Namespace)
				}
			},
		},
		{
			name: "resource_absent",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			},
			check: func(t *testing.T, buf *bytes.Buffer, rec *httptest.ResponseRecorder) {
				entry := parseAuditEntry(t, buf)
				if entry.Resource != nil {
					t.Errorf("want resource absent, have %+v", entry.Resource)
				}
				raw := strings.TrimSpace(buf.String())
				if strings.Contains(raw, `"resource"`) {
					t.Error("want no resource key in JSON output")
				}
			},
		},
		{
			name: "groups_empty_not_null",
			handler: func(w http.ResponseWriter, r *http.Request) {
				PopulateAuditData(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusOK)
				}).ServeHTTP(w, r)
			},
			reqSetup: func(r *http.Request) *http.Request {
				ctx := request.WithUser(r.Context(), &user.DefaultInfo{
					Name:   "nogroups",
					Groups: nil,
				})
				return r.WithContext(ctx)
			},
			check: func(t *testing.T, buf *bytes.Buffer, rec *httptest.ResponseRecorder) {
				raw := strings.TrimSpace(buf.String())
				var rawMap map[string]any
				if err := json.Unmarshal([]byte(raw), &rawMap); err != nil {
					t.Fatalf("failed to unmarshal: %v", err)
				}
				identity := rawMap["identity"].(map[string]any)
				groups := identity["groups"]
				if groups == nil {
					t.Fatal("want groups=[], have null")
				}
				groupSlice, ok := groups.([]any)
				if !ok {
					t.Fatalf("want groups to be array, have %T", groups)
				}
				if len(groupSlice) != 0 {
					t.Errorf("want groups=[], have %v", groupSlice)
				}
			},
		},
		{
			name: "latency_recorded",
			handler: func(w http.ResponseWriter, r *http.Request) {
				time.Sleep(5 * time.Millisecond)
				w.WriteHeader(http.StatusOK)
			},
			check: func(t *testing.T, buf *bytes.Buffer, rec *httptest.ResponseRecorder) {
				entry := parseAuditEntry(t, buf)
				if entry.Response.LatencyMs <= 0 {
					t.Errorf("want latency_ms > 0, have %f", entry.Response.LatencyMs)
				}
			},
		},
		{
			name: "bytes_counted",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("hello world"))
			},
			check: func(t *testing.T, buf *bytes.Buffer, rec *httptest.ResponseRecorder) {
				entry := parseAuditEntry(t, buf)
				if entry.Response.BytesWritten != 11 {
					t.Errorf("want bytes_written=11, have %d", entry.Response.BytesWritten)
				}
			},
		},
		{
			name: "path_not_requesturi",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			},
			reqSetup: func(r *http.Request) *http.Request {
				r, _ = http.NewRequest(http.MethodGet, "http://example.com/api/v1/models?limit=10&offset=0", nil)
				return r
			},
			check: func(t *testing.T, buf *bytes.Buffer, rec *httptest.ResponseRecorder) {
				entry := parseAuditEntry(t, buf)
				if entry.Request.Path != "/api/v1/models" {
					t.Errorf("want path=/api/v1/models, have %s", entry.Request.Path)
				}
				if strings.Contains(entry.Request.Path, "?") {
					t.Error("want path without query string")
				}
			},
		},
		{
			name: "remote_addr",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			},
			reqSetup: func(r *http.Request) *http.Request {
				r.RemoteAddr = "192.168.1.100:54321"
				return r
			},
			check: func(t *testing.T, buf *bytes.Buffer, rec *httptest.ResponseRecorder) {
				entry := parseAuditEntry(t, buf)
				if entry.Request.RemoteAddr != "192.168.1.100:54321" {
					t.Errorf("want remote_addr=192.168.1.100:54321, have %s", entry.Request.RemoteAddr)
				}
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			cfg := tt.cfg
			if cfg == nil && tt.name != "nil_config" {
				cfg = newTestConfig(&buf, "", "")
			} else if cfg != nil && cfg.Enabled && cfg.logger == nil {
				cfg.logger = log.New(&buf, "", 0)
			}

			req := httptest.NewRequest(http.MethodGet, "http://example.com/test", nil)
			if tt.reqSetup != nil {
				req = tt.reqSetup(req)
			}

			rec := httptest.NewRecorder()
			wrapped := WithAuditLog(tt.handler, cfg)
			wrapped.ServeHTTP(rec, req)

			tt.check(t, &buf, rec)
		})
	}
}

func TestPopulateAuditData(t *testing.T) {
	for _, tt := range []struct {
		name       string
		user       *user.DefaultInfo
		wantUser   string
		wantGroups []string
	}{
		{
			name:       "extracts user and groups from context",
			user:       &user.DefaultInfo{Name: "alice", Groups: []string{"admins", "devs"}},
			wantUser:   "alice",
			wantGroups: []string{"admins", "devs"},
		},
		{
			name:       "no user in context",
			user:       nil,
			wantUser:   "",
			wantGroups: nil,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var capturedUser string
			var capturedGroups []string

			var buf bytes.Buffer
			cfg := newTestConfig(&buf, "", "")

			inner := PopulateAuditData(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			})

			handler := WithAuditLog(func(w http.ResponseWriter, r *http.Request) {
				inner.ServeHTTP(w, r)
			}, cfg)

			req := httptest.NewRequest(http.MethodGet, "http://example.com/test", nil)
			if tt.user != nil {
				ctx := request.WithUser(req.Context(), tt.user)
				req = req.WithContext(ctx)
			}

			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			entry := parseAuditEntry(t, &buf)
			capturedUser = entry.Identity.User
			capturedGroups = entry.Identity.Groups

			if capturedUser != tt.wantUser {
				t.Errorf("want user=%s, have %s", tt.wantUser, capturedUser)
			}
			if tt.wantGroups != nil {
				if len(capturedGroups) != len(tt.wantGroups) {
					t.Errorf("want groups=%v, have %v", tt.wantGroups, capturedGroups)
				}
				for i, g := range tt.wantGroups {
					if i < len(capturedGroups) && capturedGroups[i] != g {
						t.Errorf("want groups[%d]=%s, have %s", i, g, capturedGroups[i])
					}
				}
			}
		})
	}
}

func TestStatusRecorder(t *testing.T) {
	t.Run("default status is 200 when Write called without WriteHeader", func(t *testing.T) {
		rec := httptest.NewRecorder()
		sr := &statusRecorder{ResponseWriter: rec, statusCode: http.StatusOK}
		sr.Write([]byte("hello"))

		if sr.statusCode != http.StatusOK {
			t.Errorf("want statusCode=200, have %d", sr.statusCode)
		}
		if !sr.wroteHeader {
			t.Error("want wroteHeader=true after Write")
		}
	})

	t.Run("WriteHeader captures code", func(t *testing.T) {
		rec := httptest.NewRecorder()
		sr := &statusRecorder{ResponseWriter: rec, statusCode: http.StatusOK}
		sr.WriteHeader(http.StatusNotFound)

		if sr.statusCode != http.StatusNotFound {
			t.Errorf("want statusCode=404, have %d", sr.statusCode)
		}
	})

	t.Run("multiple Write calls accumulate bytesWritten", func(t *testing.T) {
		rec := httptest.NewRecorder()
		sr := &statusRecorder{ResponseWriter: rec, statusCode: http.StatusOK}
		sr.Write([]byte("hello"))
		sr.Write([]byte(" world"))

		if sr.bytesWritten != 11 {
			t.Errorf("want bytesWritten=11, have %d", sr.bytesWritten)
		}
	})

	t.Run("Flush delegates to underlying writer", func(t *testing.T) {
		rec := httptest.NewRecorder()
		sr := &statusRecorder{ResponseWriter: rec, statusCode: http.StatusOK}
		sr.Flush()
		if !rec.Flushed {
			t.Error("want underlying writer to be flushed")
		}
	})

	t.Run("double WriteHeader only records first call", func(t *testing.T) {
		rec := httptest.NewRecorder()
		sr := &statusRecorder{ResponseWriter: rec, statusCode: http.StatusOK}
		sr.WriteHeader(http.StatusCreated)
		sr.WriteHeader(http.StatusInternalServerError)

		if sr.statusCode != http.StatusCreated {
			t.Errorf("want statusCode=201, have %d", sr.statusCode)
		}
	})
}

func TestNewConfig(t *testing.T) {
	t.Run("enabled false returns disabled config", func(t *testing.T) {
		cfg, err := NewConfig(false, "", "", "")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cfg.Enabled {
			t.Error("want Enabled=false")
		}
	})

	t.Run("enabled true with empty path uses stdout", func(t *testing.T) {
		cfg, err := NewConfig(true, "", "", "")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !cfg.Enabled {
			t.Error("want Enabled=true")
		}
		if cfg.logger == nil {
			t.Error("want logger to be set")
		}
	})

	t.Run("enabled true with stdout uses stdout", func(t *testing.T) {
		cfg, err := NewConfig(true, "stdout", "", "")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !cfg.Enabled {
			t.Error("want Enabled=true")
		}
	})

	t.Run("enabled true with valid file path", func(t *testing.T) {
		tmpDir := t.TempDir()
		logPath := filepath.Join(tmpDir, "audit.log")
		cfg, err := NewConfig(true, logPath, "myresource", "myns")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !cfg.Enabled {
			t.Error("want Enabled=true")
		}
		if cfg.ResourceName != "myresource" {
			t.Errorf("want ResourceName=myresource, have %s", cfg.ResourceName)
		}
		if cfg.ResourceNS != "myns" {
			t.Errorf("want ResourceNS=myns, have %s", cfg.ResourceNS)
		}
		if _, err := os.Stat(logPath); err != nil {
			t.Errorf("want log file to exist: %v", err)
		}
	})

	t.Run("enabled true with invalid path returns error", func(t *testing.T) {
		_, err := NewConfig(true, "/nonexistent/dir/audit.log", "", "")
		if err == nil {
			t.Error("want error for invalid path, have nil")
		}
	})
}

func TestNoBearerTokenInOutput(t *testing.T) {
	var buf bytes.Buffer
	cfg := newTestConfig(&buf, "", "")

	handler := WithAuditLog(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}, cfg)

	req := httptest.NewRequest(http.MethodGet, "http://example.com/test", nil)
	req.Header.Set("Authorization", "Bearer secret-token")

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	raw := buf.String()
	if strings.Contains(raw, "secret-token") {
		t.Error("audit output must not contain the bearer token value")
	}
	if strings.Contains(raw, "Bearer") {
		t.Error("audit output must not contain 'Bearer'")
	}
}

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
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"time"

	"k8s.io/apiserver/pkg/endpoints/request"
)

type auditEntry struct {
	Time     string        `json:"time"`
	Level    string        `json:"level"`
	Msg      string        `json:"msg"`
	Request  requestInfo   `json:"request"`
	Identity identityInfo  `json:"identity"`
	Response responseInfo  `json:"response"`
	Resource *resourceInfo `json:"resource,omitempty"`
}

type requestInfo struct {
	Method     string `json:"method"`
	Path       string `json:"path"`
	RemoteAddr string `json:"remote_addr"`
}

type identityInfo struct {
	User   string   `json:"user"`
	Groups []string `json:"groups"`
}

type responseInfo struct {
	StatusCode   int     `json:"status_code"`
	LatencyMs    float64 `json:"latency_ms"`
	BytesWritten int64   `json:"bytes_written"`
}

type resourceInfo struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
}

type auditData struct {
	User   string
	Groups []string
}

type contextKey struct{}

type Config struct {
	Enabled      bool
	logger       *log.Logger
	ResourceName string
	ResourceNS   string
}

func NewConfig(enabled bool, logPath string, resourceName string, resourceNamespace string) (*Config, error) {
	if !enabled {
		return &Config{Enabled: false}, nil
	}

	var writer *os.File
	if logPath == "" || logPath == "stdout" {
		writer = os.Stdout
	} else {
		f, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return nil, err
		}
		writer = f
	}

	return &Config{
		Enabled:      true,
		logger:       log.New(writer, "", 0),
		ResourceName: resourceName,
		ResourceNS:   resourceNamespace,
	}, nil
}

func WithAuditLog(handler http.HandlerFunc, cfg *Config) http.HandlerFunc {
	if cfg == nil || !cfg.Enabled {
		return handler
	}

	return func(w http.ResponseWriter, req *http.Request) {
		ad := &auditData{}
		ctx := context.WithValue(req.Context(), contextKey{}, ad)
		req = req.WithContext(ctx)

		rec := &statusRecorder{ResponseWriter: w, statusCode: http.StatusOK}
		start := time.Now()

		handler.ServeHTTP(rec, req)

		groups := ad.Groups
		if groups == nil {
			groups = []string{}
		}

		entry := auditEntry{
			Time:  start.UTC().Format(time.RFC3339Nano),
			Level: "INFO",
			Msg:   "audit",
			Request: requestInfo{
				Method:     req.Method,
				Path:       req.URL.Path,
				RemoteAddr: req.RemoteAddr,
			},
			Identity: identityInfo{
				User:   ad.User,
				Groups: groups,
			},
			Response: responseInfo{
				StatusCode:   rec.statusCode,
				LatencyMs:    float64(time.Since(start).Nanoseconds()) / 1e6,
				BytesWritten: rec.bytesWritten,
			},
		}

		if cfg.ResourceName != "" || cfg.ResourceNS != "" {
			entry.Resource = &resourceInfo{
				Name:      cfg.ResourceName,
				Namespace: cfg.ResourceNS,
			}
		}

		data, err := json.Marshal(entry)
		if err != nil {
			return
		}
		cfg.logger.Println(string(data))
	}
}

func PopulateAuditData(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		if ad, ok := req.Context().Value(contextKey{}).(*auditData); ok {
			if u, uOk := request.UserFrom(req.Context()); uOk {
				ad.User = u.GetName()
				ad.Groups = u.GetGroups()
			}
		}

		handler.ServeHTTP(w, req)
	}
}

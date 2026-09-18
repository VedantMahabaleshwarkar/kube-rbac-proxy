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
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/felixge/httpsnoop"

	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	"k8s.io/apiserver/pkg/endpoints/request"
	"k8s.io/klog/v2"

	"github.com/brancz/kube-rbac-proxy/pkg/authz"
)

type ResourceMetadata struct {
	Name      string
	Namespace string
	Type      string
}

type Options struct {
	Resource              ResourceMetadata
	AuthorizationResource ResourceMetadata
	AIProvider            string
	UseForwardedFor       bool
	UpstreamURL           *url.URL
	ProductVersion        string
}

// StaticResourceMetadata returns authorization resource attributes that do not
// require request-time template resolution.
func StaticResourceMetadata(attrs *authz.ResourceAttributes) ResourceMetadata {
	metadata := ResourceMetadata{}
	if attrs == nil {
		return metadata
	}
	if !containsTemplateDelimiter(attrs.Name) {
		metadata.Name = attrs.Name
	}
	if !containsTemplateDelimiter(attrs.Namespace) {
		metadata.Namespace = attrs.Namespace
	}
	return metadata
}

func containsTemplateDelimiter(value string) bool {
	return strings.Contains(value, "{{") || strings.Contains(value, "}}")
}

type contextKey struct{}

type requestContext struct {
	user                         user.Info
	resource                     ResourceMetadata
	authorizationEndpointMatched bool
	upstreamStatusCode           int
}

const (
	defaultQueueSize          = 1024
	maxAuditEventSize         = 64 << 10
	maxAuditPathSize          = 1024
	maxAuditDynamicStringSize = 256
	auditTruncationMarker     = "[truncated]"
)

// Logger queues OCSF events for a single writer goroutine. The bounded queue
// prevents a slow audit sink from stalling request handlers. Events are
// best-effort; queue overflow and failed record writes are accumulated for
// direct writer reporting.
type Logger struct {
	writer      io.Writer
	options     Options
	events      chan []byte
	done        chan struct{}
	stateMu     sync.RWMutex
	closed      bool
	closeOnce   sync.Once
	dropped     atomic.Uint64
	lastReport  atomic.Int64
	lossMu      sync.Mutex
	pendingLoss lossSnapshot
}

type lossSnapshot struct {
	Count     int64
	StartTime int64
	EndTime   int64
}

func NewLogger(w io.Writer, options Options) *Logger {
	return newLogger(w, options, defaultQueueSize)
}

func newLogger(w io.Writer, options Options, queueSize int) *Logger {
	if options.ProductVersion == "" {
		options.ProductVersion = "unknown"
	}
	logger := &Logger{
		writer:  w,
		options: options,
		events:  make(chan []byte, queueSize),
		done:    make(chan struct{}),
	}
	go logger.run()
	return logger
}

func (l *Logger) run() {
	defer close(l.done)
	for {
		payload, ok := <-l.events
		if !ok {
			l.emitPendingLoss()
			return
		}
		l.emitPendingLoss()
		var event Event
		if err := json.Unmarshal(payload, &event); err != nil {
			l.report("failed to decode queued audit event", err)
			continue
		}
		event.Metadata.LoggedTime = time.Now().UnixMilli()
		if err := l.encode(event); err != nil {
			l.recordLoss(time.Now().UnixMilli())
			l.report("failed to write audit event", err)
		}
	}
}

func (l *Logger) emitPendingLoss() {
	snapshot := l.takePendingLoss()
	if snapshot.Count == 0 {
		return
	}
	event := newGapEvent(snapshot, l.options.ProductVersion, time.Now().UnixMilli())
	if err := l.encode(event); err != nil {
		l.restorePendingLoss(snapshot)
		l.report("failed to write audit event loss summary", err)
	}
}

func (l *Logger) encode(event any) error {
	encoder := json.NewEncoder(l.writer)
	encoder.SetEscapeHTML(false)
	return encoder.Encode(event)
}

func newGapEvent(snapshot lossSnapshot, productVersion string, loggedTime int64) gapEvent {
	return gapEvent{
		ActivityID:   gapActivityID,
		ActivityName: gapActivityName,
		CategoryUID:  gapCategoryUID,
		CategoryName: gapCategoryName,
		ClassUID:     gapClassUID,
		ClassName:    gapClassName,
		TypeUID:      gapTypeUID,
		TypeName:     gapClassName + ": " + gapActivityName,
		SeverityID:   gapSeverityID,
		Severity:     gapSeverityName,
		Time:         snapshot.StartTime,
		StartTime:    snapshot.StartTime,
		EndTime:      snapshot.EndTime,
		Duration:     snapshot.EndTime - snapshot.StartTime,
		Count:        snapshot.Count,
		Metadata: gapMetadata{
			Version: ocsfVersion,
			Product: Product{
				Name:    productName,
				Version: productVersion,
			},
			LoggedTime: loggedTime,
		},
		StatusID:   statusFailureID,
		Status:     statusFailureName,
		StatusCode: gapStatusCode,
	}
}

func (l *Logger) takePendingLoss() lossSnapshot {
	l.lossMu.Lock()
	defer l.lossMu.Unlock()
	snapshot := l.pendingLoss
	l.pendingLoss = lossSnapshot{}
	return snapshot
}

func (l *Logger) restorePendingLoss(snapshot lossSnapshot) {
	if snapshot.Count == 0 {
		return
	}
	l.lossMu.Lock()
	defer l.lossMu.Unlock()
	if l.pendingLoss.Count == 0 {
		l.pendingLoss = snapshot
		return
	}
	l.pendingLoss.Count += snapshot.Count
	if snapshot.StartTime < l.pendingLoss.StartTime {
		l.pendingLoss.StartTime = snapshot.StartTime
	}
	if snapshot.EndTime > l.pendingLoss.EndTime {
		l.pendingLoss.EndTime = snapshot.EndTime
	}
}

// Close stops accepting events, drains queued events, and waits for the writer
// goroutine. Writes to an arbitrary io.Writer cannot be forcibly interrupted.
// When ctx expires, Close returns promptly, but callers that then exit the
// process may lose events still queued behind a blocked writer.
func (l *Logger) Close(ctx context.Context) error {
	l.closeOnce.Do(func() {
		l.stateMu.Lock()
		l.closed = true
		close(l.events)
		l.stateMu.Unlock()
	})

	select {
	case <-l.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// CaptureUser records the authenticated Kubernetes principal for the outer
// audit middleware without changing the authentication filter.
func (l *Logger) CaptureUser(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		if data, ok := req.Context().Value(contextKey{}).(*requestContext); ok {
			if principal, ok := request.UserFrom(req.Context()); ok {
				data.user = principal
			}
		}
		next.ServeHTTP(w, req)
	}
}

// CaptureAuthorizationEndpointMatch records that a Format2 endpoint owns the
// request before authorization attribute resolution can fail.
func (l *Logger) CaptureAuthorizationEndpointMatch(config *authz.Config, next http.HandlerFunc) http.HandlerFunc {
	if config == nil || len(config.Endpoints) == 0 {
		return next
	}

	return func(w http.ResponseWriter, req *http.Request) {
		if data, ok := req.Context().Value(contextKey{}).(*requestContext); ok {
			for _, endpoint := range config.Endpoints {
				if authz.MatchEndpoint(req.URL.Path, endpoint) {
					data.authorizationEndpointMatched = true
					break
				}
			}
		}
		next.ServeHTTP(w, req)
	}
}

// CaptureAuthorizationAttributes records the effective, request-specific
// resource attributes produced by the authorization filter.
func (l *Logger) CaptureAuthorizationAttributes(req *http.Request, attrs []authorizer.Attributes) {
	data, ok := req.Context().Value(contextKey{}).(*requestContext)
	if !ok {
		return
	}
	for _, attr := range attrs {
		if attr.IsResourceRequest() {
			data.resource = ResourceMetadata{Name: attr.GetName(), Namespace: attr.GetNamespace()}
			return
		}
	}
}

// CaptureUpstreamResponse records the upstream status before ReverseProxy
// handles protocol upgrades and bypasses the wrapped response writer.
func (l *Logger) CaptureUpstreamResponse(response *http.Response) error {
	if response == nil || response.Request == nil {
		return nil
	}
	if data, ok := response.Request.Context().Value(contextKey{}).(*requestContext); ok {
		data.upstreamStatusCode = response.StatusCode
	}
	return nil
}

// WithAuditLog captures final response metrics without buffering request or
// response bodies. Audit failures are best-effort and never alter the response.
func (l *Logger) WithAuditLog(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		started := time.Now()
		data := &requestContext{}
		ctx := context.WithValue(req.Context(), contextKey{}, data)
		metrics := httpsnoop.Metrics{Code: http.StatusOK}
		completed := false
		responseCommitted := false
		defer func() {
			metrics.Duration = time.Since(started)
			panicked := !completed
			if panicked && !responseCommitted {
				metrics.Code = http.StatusInternalServerError
			}
			event := l.event(req, data, metrics, started)
			if panicked {
				event.Status = statusFailureName
				event.StatusID = statusFailureID
			}
			l.enqueue(event)
		}()

		tracked := httpsnoop.Wrap(w, httpsnoop.Hooks{
			WriteHeader: func(next httpsnoop.WriteHeaderFunc) httpsnoop.WriteHeaderFunc {
				return func(code int) {
					next(code)
					if code < 100 || code > 199 {
						responseCommitted = true
					}
				}
			},
			Write: func(next httpsnoop.WriteFunc) httpsnoop.WriteFunc {
				return func(payload []byte) (int, error) {
					n, err := next(payload)
					// net/http commits an implicit 200 even when Write is
					// called with an empty payload.
					responseCommitted = true
					return n, err
				}
			},
			ReadFrom: func(next httpsnoop.ReadFromFunc) httpsnoop.ReadFromFunc {
				return func(src io.Reader) (int64, error) {
					n, err := next(src)
					if n > 0 {
						responseCommitted = true
					}
					return n, err
				}
			},
			Flush: func(next httpsnoop.FlushFunc) httpsnoop.FlushFunc {
				return func() {
					next()
					responseCommitted = true
				}
			},
		})
		metrics.CaptureMetrics(tracked, func(wrapped http.ResponseWriter) {
			next.ServeHTTP(wrapped, req.WithContext(ctx))
		})
		completed = true
	}
}

func (l *Logger) enqueue(event Event) {
	payload, err := json.Marshal(event)
	if err != nil {
		l.drop("failed to serialize audit event; dropping event", err)
		return
	}
	if len(payload) > maxAuditEventSize {
		event = boundedAuditEvent(event, len(payload))
		payload, err = json.Marshal(event)
		if err != nil {
			l.drop("failed to serialize bounded audit event; dropping event", err)
			return
		}
		if len(payload) > maxAuditEventSize {
			l.report("bounded audit event exceeds maximum size; dropping event", nil)
			return
		}
	}

	l.stateMu.RLock()
	defer l.stateMu.RUnlock()
	if l.closed {
		return
	}
	select {
	case l.events <- payload:
	default:
		l.recordQueueLoss(time.Now().UnixMilli())
	}
}

func boundedAuditEvent(event Event, originalSize int) Event {
	bounded := Event{
		ActivityID:   event.ActivityID,
		ActivityName: truncateUTF8(event.ActivityName, maxAuditDynamicStringSize),
		CategoryUID:  event.CategoryUID,
		CategoryName: truncateUTF8(event.CategoryName, maxAuditDynamicStringSize),
		ClassUID:     event.ClassUID,
		ClassName:    truncateUTF8(event.ClassName, maxAuditDynamicStringSize),
		TypeUID:      event.TypeUID,
		SeverityID:   event.SeverityID,
		Severity:     truncateUTF8(event.Severity, maxAuditDynamicStringSize),
		Time:         event.Time,
		Metadata: Metadata{
			Version:         truncateUTF8(event.Metadata.Version, maxAuditDynamicStringSize),
			Profiles:        []string{aiOperationProfile},
			IsTruncated:     true,
			UntruncatedSize: (originalSize + 1023) / 1024,
			Product: Product{
				Name:    truncateUTF8(event.Metadata.Product.Name, maxAuditDynamicStringSize),
				Version: truncateUTF8(event.Metadata.Product.Version, maxAuditDynamicStringSize),
			},
		},
		Actor: Actor{User: User{
			Name:   truncateUTF8(event.Actor.User.Name, maxAuditDynamicStringSize),
			UID:    truncateUTF8(event.Actor.User.UID, maxAuditDynamicStringSize),
			TypeID: event.Actor.User.TypeID,
		}},
		API: API{Operation: truncateUTF8(event.API.Operation, maxAuditDynamicStringSize)},
		HTTPRequest: HTTPRequest{
			HTTPMethod: truncateUTF8(event.HTTPRequest.HTTPMethod, maxAuditDynamicStringSize),
			Version:    truncateUTF8(event.HTTPRequest.Version, maxAuditDynamicStringSize),
			URL:        URL{Path: truncateUTF8(event.HTTPRequest.URL.Path, maxAuditPathSize)},
		},
		HTTPResponse: event.HTTPResponse,
		SrcEndpoint: Endpoint{
			Name:     truncateUTF8(event.SrcEndpoint.Name, maxAuditDynamicStringSize),
			Hostname: truncateUTF8(event.SrcEndpoint.Hostname, maxAuditDynamicStringSize),
			IP:       truncateUTF8(event.SrcEndpoint.IP, maxAuditDynamicStringSize),
			Port:     event.SrcEndpoint.Port,
		},
		StatusID:   event.StatusID,
		Status:     truncateUTF8(event.Status, maxAuditDynamicStringSize),
		StatusCode: truncateUTF8(event.StatusCode, maxAuditDynamicStringSize),
	}
	if event.DstEndpoint != nil {
		bounded.DstEndpoint = &Endpoint{
			Name:     truncateUTF8(event.DstEndpoint.Name, maxAuditDynamicStringSize),
			Hostname: truncateUTF8(event.DstEndpoint.Hostname, maxAuditDynamicStringSize),
			IP:       truncateUTF8(event.DstEndpoint.IP, maxAuditDynamicStringSize),
			Port:     event.DstEndpoint.Port,
		}
	}
	if len(event.Resources) > 0 {
		resource := event.Resources[0]
		bounded.Resources = []Resource{{
			Name:      truncateUTF8(resource.Name, maxAuditDynamicStringSize),
			Namespace: truncateUTF8(resource.Namespace, maxAuditDynamicStringSize),
			Type:      truncateUTF8(resource.Type, maxAuditDynamicStringSize),
			RoleID:    resource.RoleID,
			Role:      truncateUTF8(resource.Role, maxAuditDynamicStringSize),
		}}
	}
	if event.AIModel != nil {
		bounded.AIModel = &AIModel{
			Name:       truncateUTF8(event.AIModel.Name, maxAuditDynamicStringSize),
			AIProvider: truncateUTF8(event.AIModel.AIProvider, maxAuditDynamicStringSize),
		}
	}
	return bounded
}

func truncateUTF8(value string, limit int) string {
	value = strings.ToValidUTF8(value, "\uFFFD")
	if len(value) <= limit {
		return value
	}
	contentLimit := limit - len(auditTruncationMarker)
	if contentLimit < 0 {
		contentLimit = 0
	}
	cutoff := 0
	for cutoff < len(value) {
		_, size := utf8.DecodeRuneInString(value[cutoff:])
		if cutoff+size > contentLimit {
			break
		}
		cutoff += size
	}
	return value[:cutoff] + auditTruncationMarker
}

func (l *Logger) recordQueueLoss(timestamp int64) {
	l.recordLoss(timestamp)
	l.report("audit event queue is full; dropping event", nil)
}

func (l *Logger) recordLoss(timestamp int64) {
	l.lossMu.Lock()
	if l.pendingLoss.Count == 0 {
		l.pendingLoss.StartTime = timestamp
	}
	l.pendingLoss.Count++
	l.pendingLoss.EndTime = timestamp
	l.lossMu.Unlock()

	l.dropped.Add(1)
}

func (l *Logger) drop(message string, err error) {
	l.dropped.Add(1)
	l.report(message, err)
}

func (l *Logger) report(message string, err error) {
	now := time.Now().UnixNano()
	last := l.lastReport.Load()
	if last != 0 && time.Duration(now-last) < time.Second {
		return
	}
	if !l.lastReport.CompareAndSwap(last, now) {
		return
	}
	if err != nil {
		klog.Errorf("%s: %v", message, err)
		return
	}
	klog.Error(message)
}

func (l *Logger) event(req *http.Request, data *requestContext, metrics httpsnoop.Metrics, started time.Time) Event {
	srcEndpoint, forwardedFor := sourceEndpoint(req, l.options.UseForwardedFor)
	responseCode := metrics.Code
	if data.upstreamStatusCode == http.StatusSwitchingProtocols && metrics.Code == http.StatusOK && metrics.Written == 0 {
		responseCode = data.upstreamStatusCode
	}
	status, statusID := statusSuccessName, statusSuccessID
	if responseCode >= http.StatusBadRequest {
		status, statusID = statusFailureName, statusFailureID
	}

	event := Event{
		ActivityID:   activityID,
		ActivityName: activityName,
		CategoryUID:  categoryUID,
		CategoryName: categoryName,
		ClassUID:     classUID,
		ClassName:    className,
		TypeUID:      typeUID,
		SeverityID:   severityID,
		Severity:     severityName,
		Time:         started.UnixMilli(),
		Metadata: Metadata{
			Version:  ocsfVersion,
			Profiles: []string{aiOperationProfile},
			Product: Product{
				Name:    productName,
				Version: l.options.ProductVersion,
			},
		},
		Actor: Actor{User: ocsfUser(data.user)},
		API: API{
			Operation: strings.TrimSpace(req.Method + " " + req.URL.Path),
		},
		HTTPRequest: HTTPRequest{
			HTTPMethod:    req.Method,
			Version:       strings.TrimPrefix(req.Proto, "HTTP/"),
			URL:           URL{Path: req.URL.Path},
			XForwardedFor: forwardedFor,
		},
		HTTPResponse: HTTPResponse{
			Code:       responseCode,
			BodyLength: metrics.Written,
			Latency:    metrics.Duration.Milliseconds(),
		},
		SrcEndpoint: srcEndpoint,
		DstEndpoint: destinationEndpoint(l.options.UpstreamURL),
		StatusID:    statusID,
		Status:      status,
		StatusCode:  strconv.Itoa(responseCode),
	}

	resource := l.options.Resource
	if resource.Name == "" {
		resource.Name = data.resource.Name
	}
	if resource.Namespace == "" {
		resource.Namespace = data.resource.Namespace
	}
	if !data.authorizationEndpointMatched {
		if resource.Name == "" {
			resource.Name = l.options.AuthorizationResource.Name
		}
		if resource.Namespace == "" {
			resource.Namespace = l.options.AuthorizationResource.Namespace
		}
	}
	if resource.Name != "" {
		event.Resources = []Resource{{
			Name:      resource.Name,
			Namespace: resource.Namespace,
			Type:      resource.Type,
			RoleID:    resourceRoleTargetID,
			Role:      resourceRoleTargetName,
		}}
		if l.options.AIProvider != "" {
			event.AIModel = &AIModel{Name: resource.Name, AIProvider: l.options.AIProvider}
		}
	}

	return event
}

func ocsfUser(principal user.Info) User {
	if principal == nil || principal.GetName() == "" {
		return User{Name: "Unknown", TypeID: 0}
	}

	typeID := 1
	if strings.HasPrefix(principal.GetName(), "system:serviceaccount:") {
		typeID = 4
	}

	groups := principal.GetGroups()
	ocsfGroups := make([]Group, 0, len(groups))
	for _, group := range groups {
		if group != "" {
			ocsfGroups = append(ocsfGroups, Group{Name: group})
		}
	}

	return User{
		Name:   principal.GetName(),
		UID:    principal.GetUID(),
		TypeID: typeID,
		Groups: ocsfGroups,
	}
}

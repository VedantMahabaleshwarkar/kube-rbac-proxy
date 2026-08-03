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

// Authorization config supports Format1 (top-level rewrites and resourceAttributes) and
// Format2 (path-scoped endpoints with per-method resource rules). This file implements
// Format2 matching and attribute construction; Format1 is handled in pkg/proxy.
//
// Format1 example (YAML under authorization:):
//
//	authorization:
//	  rewrites:
//	    byQueryParameter:
//	      name: "namespace"
//	  resourceAttributes:
//	    apiVersion: v1
//	    resource: namespace
//	    subresource: metrics
//	    namespace: "{{ .Value }}"
//
// Format2 example:
//
//	authorization:
//	  endpoints:
//	    - path: /api/v1/evaluations/jobs/*/events
//	      mappings:
//	        - methods: [post]
//	          resources:
//	            - rewrites:
//	                byHttpHeader:
//	                  name: X-Tenant
//	              resourceAttributes:
//	                namespace: "{{.FromHeader}}"
//	                apiGroup: trustyai.opendatahub.io
//	                resource: status-events
//	                verb: create
//
// A single config may include both Format1 and Format2; see EndpointAttributesFromRequest
// and pkg/proxy for how requests choose between them.

package authz

import (
	"bytes"
	"errors"
	"fmt"
	"net/http"
	"path"
	"strings"
	"text/template"

	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/authorization/authorizer"
)

// ErrEndpointMethodNotAllowed is returned by EndpointAttributesFromRequest when the request
// path matches a Format2 endpoint but no mapping lists the request's HTTP method. Callers
// (e.g. filters.WithAuthorization) may map this to HTTP 403 Forbidden.
var ErrEndpointMethodNotAllowed = errors.New("HTTP method not allowed for matched authorization endpoint")

// Endpoint describes path-scoped SAR mappings (Format2).
type Endpoint struct {
	Path      string            `json:"path,omitempty"`
	Mappings  []EndpointMapping `json:"mappings,omitempty"`
	PathParts []string          `json:"-"`
}

// EndpointMapping selects resource rules by HTTP method.
type EndpointMapping struct {
	Methods   []string               `json:"methods,omitempty"`
	Resources []EndpointResourceRule `json:"resources,omitempty"`
}

// EndpointResourceRule is one SAR to evaluate for a matched request.
type EndpointResourceRule struct {
	Rewrites           SubjectAccessReviewRewrites `json:"rewrites,omitempty"`
	ResourceAttributes ResourceAttributes          `json:"resourceAttributes,omitempty"`
}

// TemplateData is passed to text/template when expanding resourceAttributes in Format2 endpoint rules.
// Value is set to FromHeader, FromQueryString, or FromPathSegment when those rewrites are populated
// (supports {{ .Value }} like Format1).
type TemplateData struct {
	Value           string
	FromHeader      string
	FromQueryString string
	FromMethod      string
	FromPathSegment string
}

// PrepareEndpoints must be called exactly once after building or unmarshaling a Config and
// before any Format2 endpoint matching. It populates Endpoint.PathParts from Endpoint.Path
// (via prepareEndpointPatterns) so matchEndpoint can run without splitting paths per request.
// The main binary calls this from Complete after parseAuthorizationConfigFile; tests and any
// library user that constructs Config with non-empty Endpoints must call it too. Omitting
// PrepareEndpoints leaves PathParts nil and endpoint patterns never match.
func (cfg *Config) PrepareEndpoints() {
	cfg.prepareEndpointPatterns()
}

// prepareEndpointPatterns sets PathParts for each entry in cfg.Endpoints. It exists only to
// implement PrepareEndpoints and must not be called from request handlers or tests; call
// PrepareEndpoints on the Config instead.
func (cfg *Config) prepareEndpointPatterns() {
	if cfg == nil {
		return
	}
	for endpointIndex := range cfg.Endpoints {
		cfg.Endpoints[endpointIndex].PathParts = strings.Split(cfg.Endpoints[endpointIndex].Path, "/")
	}
}

// MatchEndpoint reports whether requestPath matches the configured endpoint pattern.
// requestPath is cleaned with path.Clean (collapse duplicate slashes, ".", "..", trailing slash)
// before splitting. Matching is exact by segment count against endpoint.Path (after PrepareEndpoints).
// A pattern segment "*" matches exactly one request segment; it does not match zero or multiple trailing segments.
func MatchEndpoint(requestPath string, endpoint Endpoint) bool {
	return matchEndpoint(requestPath, endpoint)
}

func matchEndpoint(requestPath string, endpoint Endpoint) bool {
	patternParts := endpoint.PathParts
	if len(patternParts) == 0 {
		return false
	}
	if requestPath == "" {
		requestPath = "/"
	}
	requestPath = path.Clean(requestPath)
	endpointParts := strings.Split(requestPath, "/")
	if len(endpointParts) != len(patternParts) {
		return false
	}
	for segmentIndex, patternSegment := range patternParts {
		if patternSegment == "*" {
			continue
		}
		if endpointParts[segmentIndex] != patternSegment {
			return false
		}
	}
	return true
}

func matchMethods(fromRequest string, fromConfig []string) bool {
	if len(fromConfig) == 0 {
		return false
	}
	requestMethod := strings.ToLower(fromRequest)
	for _, configuredMethod := range fromConfig {
		if strings.ToLower(configuredMethod) == requestMethod {
			return true
		}
	}
	return false
}

// ValidateAuthorizationConfig checks Format2 authorization.endpoints for inconsistencies
// that would otherwise fail silently or confusingly at runtime. It is invoked after loading
// the config file.
func ValidateAuthorizationConfig(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	for endpointIndex, endpoint := range cfg.Endpoints {
		if strings.TrimSpace(endpoint.Path) == "" {
			return fmt.Errorf("authorization.endpoints[%d]: path must be non-empty", endpointIndex)
		}
		if len(endpoint.Mappings) == 0 {
			return fmt.Errorf("authorization.endpoints[%d] (path %q): mappings must contain at least one entry", endpointIndex, endpoint.Path)
		}
		for mappingIndex, mapping := range endpoint.Mappings {
			if len(mapping.Methods) == 0 {
				return fmt.Errorf("authorization.endpoints[%d] (path %q): mappings[%d] must specify a non-empty methods list", endpointIndex, endpoint.Path, mappingIndex)
			}
			if len(mapping.Resources) == 0 {
				return fmt.Errorf("authorization.endpoints[%d] (path %q): mappings[%d] must contain at least one resource rule", endpointIndex, endpoint.Path, mappingIndex)
			}
			for resourceIndex, rule := range mapping.Resources {
				if err := validateEndpointResourceRuleRewrites(endpointIndex, endpoint.Path, mappingIndex, resourceIndex, &rule.Rewrites); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func validateEndpointResourceRuleRewrites(endpointIndex int, endpointPath string, mappingIndex, resourceIndex int, rewrites *SubjectAccessReviewRewrites) error {
	if rewrites == nil {
		return nil
	}
	if rewrites.ByHTTPHeader != nil && strings.TrimSpace(rewrites.ByHTTPHeader.Name) == "" {
		return fmt.Errorf(
			"authorization.endpoints[%d] (path %q): mappings[%d].resources[%d].rewrites.byHttpHeader must specify a non-empty name",
			endpointIndex, endpointPath, mappingIndex, resourceIndex,
		)
	}
	if rewrites.ByQueryParameter != nil && strings.TrimSpace(rewrites.ByQueryParameter.Name) == "" {
		return fmt.Errorf(
			"authorization.endpoints[%d] (path %q): mappings[%d].resources[%d].rewrites.byQueryParameter must specify a non-empty name",
			endpointIndex, endpointPath, mappingIndex, resourceIndex,
		)
	}
	if rewrites.ByPathSegment != nil && rewrites.ByPathSegment.Index < 0 {
		return fmt.Errorf(
			"authorization.endpoints[%d] (path %q): mappings[%d].resources[%d].rewrites.byPathSegment.index must be >= 0",
			endpointIndex, endpointPath, mappingIndex, resourceIndex,
		)
	}
	return nil
}

// HTTPToKubeVerb maps an HTTP method to a Kubernetes API verb.
func HTTPToKubeVerb(httpVerb string) string {
	switch httpVerb {
	case http.MethodGet:
		return "get"
	case http.MethodPost:
		return "create"
	case http.MethodPut:
		return "update"
	case http.MethodDelete:
		return "delete"
	case http.MethodPatch:
		return "patch"
	case http.MethodOptions:
		return "options"
	case http.MethodHead:
		return "head"
	default:
		return ""
	}
}

func applyEndpointFieldTemplate(templateString string, values TemplateData) (string, error) {
	if templateString == "" {
		return "", nil
	}
	tmpl, err := template.New("endpointField").Parse(templateString)
	if err != nil {
		return "", fmt.Errorf("parse template %q: %w", templateString, err)
	}
	output := bytes.NewBuffer(nil)
	if err := tmpl.Execute(output, values); err != nil {
		return "", fmt.Errorf("execute template %q: %w", templateString, err)
	}
	return output.String(), nil
}

func expandEndpointResourceField(fieldName, templateString string, templateData TemplateData) (string, error) {
	s, err := applyEndpointFieldTemplate(templateString, templateData)
	if err != nil {
		return "", fmt.Errorf("resourceAttributes.%s: %w", fieldName, err)
	}
	return s, nil
}

// rulesForEndpointMethod returns the resource rules from the first mapping that accepts
// request.Method. The second return value is false when the endpoint path matched but no
// mapping listed the HTTP method (caller should treat as method not allowed for that path).
func rulesForEndpointMethod(request *http.Request, endpoint Endpoint) ([]EndpointResourceRule, bool) {
	for _, mapping := range endpoint.Mappings {
		if matchMethods(request.Method, mapping.Methods) {
			return mapping.Resources, true
		}
	}
	return nil, false
}

// EndpointAttributesFromRequest derives SAR attributes from authorization.endpoints (Format2).
// If the request path matches any endpoint entry, matched is true and Format1 top-level
// resourceAttributes/rewrites must not be used for that request (even when attrs is empty or err is set).
// If the path matches but no mapping accepts the request HTTP method, it returns matched==true
// and err==ErrEndpointMethodNotAllowed (use errors.Is).
func EndpointAttributesFromRequest(userInfo user.Info, request *http.Request, cfg *Config) (attrs []authorizer.Attributes, matched bool, err error) {
	if cfg == nil || len(cfg.Endpoints) == 0 {
		return nil, false, nil
	}
	for _, endpoint := range cfg.Endpoints {
		if !matchEndpoint(request.URL.Path, endpoint) {
			continue
		}
		rules, methodOK := rulesForEndpointMethod(request, endpoint)
		if !methodOK {
			return nil, true, ErrEndpointMethodNotAllowed
		}
		attrs, err := attributesFromEndpointResourceRules(userInfo, request, rules)
		return attrs, true, err
	}
	return nil, false, nil
}

func attributesFromEndpointResourceRules(userInfo user.Info, request *http.Request, rules []EndpointResourceRule) ([]authorizer.Attributes, error) {
	var attrsOut []authorizer.Attributes
	for _, rule := range rules {
		templateData := TemplateData{FromMethod: HTTPToKubeVerb(request.Method)}

		if rule.Rewrites.ByHTTPHeader != nil && rule.Rewrites.ByHTTPHeader.Name != "" {
			headerValue := request.Header.Get(rule.Rewrites.ByHTTPHeader.Name)
			if headerValue == "" {
				return nil, fmt.Errorf("required header %q is missing", rule.Rewrites.ByHTTPHeader.Name)
			}
			templateData.FromHeader = headerValue
		}
		queryParamName := rewriteQueryParamName(&rule.Rewrites)
		if queryParamName != "" {
			queryValues, ok := request.URL.Query()[queryParamName]
			if !ok || len(queryValues) == 0 {
				return nil, fmt.Errorf("required query parameter %q is missing", queryParamName)
			}
			templateData.FromQueryString = queryValues[0]
		}
		if rule.Rewrites.ByPathSegment != nil {
			segments := strings.Split(path.Clean(request.URL.Path), "/")
			idx := rule.Rewrites.ByPathSegment.Index + 1 // +1 for leading "/" empty segment
			if idx >= 0 && idx < len(segments) {
				templateData.FromPathSegment = segments[idx]
			}
		}
		if templateData.FromHeader != "" {
			templateData.Value = templateData.FromHeader
		} else if templateData.FromQueryString != "" {
			templateData.Value = templateData.FromQueryString
		} else if templateData.FromPathSegment != "" {
			templateData.Value = templateData.FromPathSegment
		}

		resAttrs := rule.ResourceAttributes
		verb, err := expandEndpointResourceField("verb", resAttrs.Verb, templateData)
		if err != nil {
			return nil, err
		}
		if verb == "" {
			verb = templateData.FromMethod
		}

		namespace, err := expandEndpointResourceField("namespace", resAttrs.Namespace, templateData)
		if err != nil {
			return nil, err
		}
		apiGroup, err := expandEndpointResourceField("apiGroup", resAttrs.APIGroup, templateData)
		if err != nil {
			return nil, err
		}
		apiVersion, err := expandEndpointResourceField("apiVersion", resAttrs.APIVersion, templateData)
		if err != nil {
			return nil, err
		}
		resource, err := expandEndpointResourceField("resource", resAttrs.Resource, templateData)
		if err != nil {
			return nil, err
		}
		subresource, err := expandEndpointResourceField("subresource", resAttrs.Subresource, templateData)
		if err != nil {
			return nil, err
		}
		name, err := expandEndpointResourceField("name", resAttrs.Name, templateData)
		if err != nil {
			return nil, err
		}

		attrsOut = append(attrsOut, authorizer.AttributesRecord{
			User:            userInfo,
			Verb:            verb,
			Namespace:       namespace,
			APIGroup:        apiGroup,
			APIVersion:      apiVersion,
			Resource:        resource,
			Subresource:     subresource,
			Name:            name,
			ResourceRequest: true,
		})
	}
	return attrsOut, nil
}

func rewriteQueryParamName(rewrites *SubjectAccessReviewRewrites) string {
	if rewrites.ByQueryParameter != nil && rewrites.ByQueryParameter.Name != "" {
		return rewrites.ByQueryParameter.Name
	}
	return ""
}

// CollectRewriteParams gathers rewrite values for Format1 authorization using the same
// header and query keys as SubjectAccessReviewRewrites.
func CollectRewriteParams(request *http.Request, rewrites *SubjectAccessReviewRewrites) []string {
	if rewrites == nil {
		return nil
	}
	var params []string
	if rewrites.ByQueryParameter != nil && rewrites.ByQueryParameter.Name != "" {
		if queryValues, ok := request.URL.Query()[rewrites.ByQueryParameter.Name]; ok {
			params = append(params, queryValues...)
		}
	}

	if rewrites.ByHTTPHeader != nil && rewrites.ByHTTPHeader.Name != "" {
		headerValues := request.Header.Values(rewrites.ByHTTPHeader.Name)
		if len(headerValues) > 0 {
			params = append(params, headerValues...)
		}
	}

	if rewrites.ByPathSegment != nil {
		segments := strings.Split(path.Clean(request.URL.Path), "/")
		idx := rewrites.ByPathSegment.Index + 1 // +1 for leading "/" empty segment
		if idx >= 0 && idx < len(segments) {
			params = append(params, segments[idx])
		}
	}

	return params
}

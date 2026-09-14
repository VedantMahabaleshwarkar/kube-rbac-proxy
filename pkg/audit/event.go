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

const (
	ocsfVersion = "1.9.0"

	activityID   = 99
	activityName = "Inference"
	categoryUID  = 6
	categoryName = "Application Activity"
	classUID     = 6003
	className    = "API Activity"
	typeUID      = 600399

	severityID   = 1
	severityName = "Informational"

	statusSuccessID = 1
	statusFailureID = 2

	resourceRoleTargetID   = 1
	resourceRoleTargetName = "Target"
)

// Event is an OCSF 1.9.0 API Activity event with the AI Operation profile.
// Fields that kube-rbac-proxy cannot observe safely are intentionally absent.
type Event struct {
	ActivityID   int          `json:"activity_id"`
	ActivityName string       `json:"activity_name"`
	CategoryUID  int          `json:"category_uid"`
	CategoryName string       `json:"category_name"`
	ClassUID     int          `json:"class_uid"`
	ClassName    string       `json:"class_name"`
	TypeUID      int          `json:"type_uid"`
	SeverityID   int          `json:"severity_id"`
	Severity     string       `json:"severity"`
	Time         int64        `json:"time"`
	Metadata     Metadata     `json:"metadata"`
	Actor        Actor        `json:"actor"`
	API          API          `json:"api"`
	HTTPRequest  HTTPRequest  `json:"http_request"`
	HTTPResponse HTTPResponse `json:"http_response"`
	SrcEndpoint  Endpoint     `json:"src_endpoint"`
	DstEndpoint  *Endpoint    `json:"dst_endpoint,omitempty"`
	StatusID     int          `json:"status_id"`
	Status       string       `json:"status"`
	StatusCode   string       `json:"status_code"`
	Resources    []Resource   `json:"resources,omitempty"`
	AIModel      *AIModel     `json:"ai_model,omitempty"`
}

type Metadata struct {
	Version    string   `json:"version"`
	Profiles   []string `json:"profiles"`
	Product    Product  `json:"product"`
	LoggedTime int64    `json:"logged_time"`
}

type Product struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type Actor struct {
	User User `json:"user"`
}

type User struct {
	Name   string  `json:"name"`
	UID    string  `json:"uid,omitempty"`
	TypeID int     `json:"type_id"`
	Groups []Group `json:"groups,omitempty"`
}

type Group struct {
	Name string `json:"name"`
}

type API struct {
	Operation string `json:"operation"`
}

type HTTPRequest struct {
	HTTPMethod    string   `json:"http_method"`
	Version       string   `json:"version"`
	URL           URL      `json:"url"`
	XForwardedFor []string `json:"x_forwarded_for,omitempty"`
}

type URL struct {
	Path string `json:"path"`
}

type HTTPResponse struct {
	Code       int   `json:"code"`
	BodyLength int64 `json:"body_length"`
	Latency    int64 `json:"latency"`
}

type Endpoint struct {
	Name     string `json:"name,omitempty"`
	Hostname string `json:"hostname,omitempty"`
	IP       string `json:"ip,omitempty"`
	Port     int    `json:"port,omitempty"`
}

type Resource struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace,omitempty"`
	Type      string `json:"type"`
	RoleID    int    `json:"role_id"`
	Role      string `json:"role"`
}

type AIModel struct {
	Name       string `json:"name"`
	AIProvider string `json:"ai_provider"`
}

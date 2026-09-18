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

package app

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"path"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/ghodss/yaml"
	"github.com/oklog/run"
	"github.com/spf13/cobra"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"

	"k8s.io/apiserver/pkg/authentication/authenticator"
	authorizationauthorizer "k8s.io/apiserver/pkg/authorization/authorizer"
	"k8s.io/apiserver/pkg/authorization/union"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	certutil "k8s.io/client-go/util/cert"
	k8sapiflag "k8s.io/component-base/cli/flag"
	"k8s.io/component-base/cli/globalflag"
	"k8s.io/component-base/logs"
	"k8s.io/component-base/term"
	"k8s.io/component-base/version"
	"k8s.io/component-base/version/verflag"
	"k8s.io/klog/v2"

	"github.com/brancz/kube-rbac-proxy/cmd/kube-rbac-proxy/app/options"
	"github.com/brancz/kube-rbac-proxy/pkg/audit"
	"github.com/brancz/kube-rbac-proxy/pkg/authn"
	"github.com/brancz/kube-rbac-proxy/pkg/authz"
	"github.com/brancz/kube-rbac-proxy/pkg/filters"
	"github.com/brancz/kube-rbac-proxy/pkg/hardcodedauthorizer"
	"github.com/brancz/kube-rbac-proxy/pkg/proxy"
	rbac_proxy_tls "github.com/brancz/kube-rbac-proxy/pkg/tls"
)

const auditShutdownTimeout = 5 * time.Second

func NewKubeRBACProxyCommand() *cobra.Command {
	o := options.NewProxyRunOptions()
	cmd := &cobra.Command{
		Use: "kube-rbac-proxy",
		Long: `The kube-rbac-proxy is a small HTTP proxy for a single upstream
that can perform RBAC authorization against the Kubernetes API using SubjectAccessReview.`,

		// stop printing usage when the command errors
		SilenceUsage: true,
		PersistentPreRunE: func(*cobra.Command, []string) error {
			klog.SetLogFilter(&SanitizingFilter{})

			// silence client-go warnings.
			// kube-apiserver loopback clients should not log self-issued warnings.
			rest.SetDefaultWarningHandler(rest.NoWarnings{})
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			verflag.PrintAndExitIfRequested()

			fs := cmd.Flags()

			k8sapiflag.PrintFlags(fs)

			if err := o.Validate(); err != nil {
				return err
			}

			// set default options
			completedOptions, err := Complete(o)
			if err != nil {
				return err
			}

			return Run(completedOptions)
		},
		Args: func(cmd *cobra.Command, args []string) error {
			for _, arg := range args {
				if len(arg) > 0 {
					return fmt.Errorf("%q does not take any arguments, got %q", cmd.CommandPath(), args)
				}
			}
			return nil
		},
	}

	fs := cmd.Flags()
	namedFlagSets := o.Flags()
	verflag.AddFlags(namedFlagSets.FlagSet("global"))
	globalflag.AddGlobalFlags(namedFlagSets.FlagSet("global"), cmd.Name(), logs.SkipLoggingConfigurationFlags())
	for _, f := range namedFlagSets.FlagSets {
		fs.AddFlagSet(f)
	}

	cols, _, _ := term.TerminalSize(cmd.OutOrStdout())
	k8sapiflag.SetUsageAndHelpFunc(cmd, namedFlagSets, cols)

	return cmd
}

type configfile struct {
	AuthorizationConfig *authz.Config `json:"authorization,omitempty"`
}

type completedProxyRunOptions struct {
	insecureListenAddress string // DEPRECATED
	secureListenAddress   string
	proxyEndpointsPort    int

	upstreamURL      *url.URL
	upstreamTimeout  time.Duration
	upstreamForceH2C bool
	upstreamCABundle *x509.CertPool

	http2Options *http2.Server

	auth *proxy.Config
	tls  *options.TLSConfig

	kubeClient *kubernetes.Clientset

	allowPaths  []string
	ignorePaths []string

	auditLogProfile audit.Profile
	auditOptions    audit.Options
}

func Complete(o *options.ProxyRunOptions) (*completedProxyRunOptions, error) {
	var err error
	completed := &completedProxyRunOptions{
		insecureListenAddress: o.InsecureListenAddress,
		secureListenAddress:   o.SecureListenAddress,
		proxyEndpointsPort:    o.ProxyEndpointsPort,
		upstreamTimeout:       o.UpstreamTimeout,
		upstreamForceH2C:      o.UpstreamForceH2C,

		allowPaths:  o.AllowPaths,
		ignorePaths: o.IgnorePaths,
	}

	completed.upstreamURL, err = url.Parse(o.Upstream)
	if err != nil {
		return nil, fmt.Errorf("failed to parse upstream URL: %w", err)
	}

	if upstreamCAPath := o.UpstreamCAFile; len(upstreamCAPath) > 0 {
		upstreamCAPEM, err := os.ReadFile(upstreamCAPath)
		if err != nil {
			return nil, err
		}

		upstreamCACertPool := x509.NewCertPool()
		if ok := upstreamCACertPool.AppendCertsFromPEM(upstreamCAPEM); !ok {
			return nil, errors.New("error parsing upstream CA certificate")
		}
		completed.upstreamCABundle = upstreamCACertPool
	}

	completed.auth = o.Auth
	completed.tls = o.TLS

	if completed.auth == nil {
		return nil, errors.New("authentication/authorization configuration is nil")
	}

	if configFileName := o.ConfigFileName; len(configFileName) > 0 {
		completed.auth.Authorization, err = parseAuthorizationConfigFile(configFileName)
		if err != nil {
			return nil, fmt.Errorf("failed to read the config file: %w", err)
		}
	}

	if completed.auth.Authorization == nil {
		return nil, errors.New("authorization configuration is nil; ensure --config-file does not set authorization to null and that defaults are intact")
	}

	completed.auth.Authorization.PrepareEndpoints()

	completed.auditLogProfile = o.AuditLogProfile
	completed.auditOptions = audit.Options{
		Resource: audit.ResourceMetadata{
			Name:      o.AuditResourceName,
			Namespace: o.AuditResourceNamespace,
			Type:      o.AuditResourceType,
		},
		AuthorizationResource: audit.StaticResourceMetadata(completed.auth.Authorization.ResourceAttributes),
		AIProvider:            o.AuditAIProvider,
		UseForwardedFor:       o.AuditUseForwardedFor,
		UpstreamURL:           completed.upstreamURL,
		ProductVersion:        version.Get().GitVersion,
	}

	kubeconfig, err := initKubeConfig(o.KubeconfigLocation)
	if err != nil {
		return nil, fmt.Errorf("failed to load kubeconfig: %w", err)
	}

	if o.QPS > 0 {
		kubeconfig.QPS = o.QPS
	}
	if o.Burst > 0 {
		kubeconfig.Burst = o.Burst
	}

	completed.kubeClient, err = kubernetes.NewForConfig(kubeconfig)
	if err != nil {
		return nil, fmt.Errorf("failed to instantiate Kubernetes client: %w", err)
	}

	completed.http2Options = &http2.Server{
		IdleTimeout:                  90 * time.Second,
		MaxConcurrentStreams:         o.HTTP2MaxConcurrentStreams,
		MaxReadFrameSize:             o.HTTP2MaxSize,
		MaxUploadBufferPerStream:     int32(o.HTTP2MaxSize),
		MaxUploadBufferPerConnection: int32(o.HTTP2MaxSize) * int32(o.HTTP2MaxConcurrentStreams),
	}

	return completed, nil
}

func Run(cfg *completedProxyRunOptions) error {
	var authenticator authenticator.Request
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// If OIDC configuration provided, use oidc authenticator
	if cfg.auth.Authentication.OIDC.IssuerURL != "" {
		oidcAuthenticator, err := authn.NewOIDCAuthenticator(ctx, cfg.auth.Authentication.OIDC)
		if err != nil {
			return fmt.Errorf("failed to instantiate OIDC authenticator: %w", err)
		}

		go oidcAuthenticator.Run(ctx)
		authenticator = oidcAuthenticator
	} else {
		//Use Delegating authenticator
		klog.Infof("Valid token audiences: %s", strings.Join(cfg.auth.Authentication.Token.Audiences, ", "))

		tokenClient := cfg.kubeClient.AuthenticationV1()
		delegatingAuthenticator, err := authn.NewDelegatingAuthenticator(tokenClient, cfg.auth.Authentication)
		if err != nil {
			return fmt.Errorf("failed to instantiate delegating authenticator: %w", err)
		}

		go delegatingAuthenticator.Run(ctx)
		authenticator = delegatingAuthenticator
	}

	sarClient := cfg.kubeClient.AuthorizationV1()
	sarAuthorizer, err := authz.NewSarAuthorizer(sarClient)
	if err != nil {
		return fmt.Errorf("failed to create sar authorizer: %w", err)
	}

	staticAuthorizer, err := authz.NewStaticAuthorizer(cfg.auth.Authorization.Static)
	if err != nil {
		return fmt.Errorf("failed to create static authorizer: %w", err)
	}

	authorizer := union.New(
		// prefix the authorizer with the permissions for metrics scraping which are well known.
		// openshift RBAC policy will always allow this user to read metrics.
		// TODO: remove this, once CMO lands static authorizer configuration.
		hardcodedauthorizer.NewHardCodedMetricsAuthorizer(),
		staticAuthorizer,
		sarAuthorizer,
	)

	upstreamTransport, err := initTransport(cfg.upstreamCABundle, cfg.tls.UpstreamClientCertFile, cfg.tls.UpstreamClientKeyFile, cfg.upstreamTimeout)
	if err != nil {
		return fmt.Errorf("failed to set up upstream TLS connection: %w", err)
	}

	proxy := httputil.NewSingleHostReverseProxy(cfg.upstreamURL)
	proxy.Transport = upstreamTransport

	if cfg.upstreamForceH2C {
		// Force http/2 for connections to the upstream i.e. do not start with HTTP1.1 UPGRADE req to
		// initialize http/2 session.
		// See https://github.com/golang/go/issues/14141#issuecomment-219212895 for more context
		h2cTransport := &http2.Transport{
			// Allow http schema. This doesn't automatically disable TLS
			AllowHTTP: true,
			// Do disable TLS.
			// In combination with the schema check above. We could enforce h2c against the upstream server
			DialTLSContext: func(ctx context.Context, netw, addr string, cfg *tls.Config) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, netw, addr)
			},
		}
		proxy.Transport = withResponseHeaderTimeout(h2cTransport, cfg.upstreamTimeout)
	}

	auditLogger, err := newAuditLogger(cfg.auditLogProfile, os.Stdout, cfg.auditOptions)
	if err != nil {
		return fmt.Errorf("failed to configure audit logger: %w", err)
	}
	if auditLogger != nil {
		defer func() {
			ctx, cancel := context.WithTimeout(context.Background(), auditShutdownTimeout)
			defer cancel()
			if err := auditLogger.Close(ctx); err != nil {
				klog.Errorf("failed to flush audit log during shutdown: %+v", err)
			}
		}()
	}
	protectedHandler := buildProtectedHandler(proxy.ServeHTTP, cfg.auth, authenticator, authorizer, auditLogger)

	handler := buildRequestHandler(proxy.ServeHTTP, protectedHandler, cfg.allowPaths, cfg.ignorePaths)

	mux := http.NewServeMux()
	mux.Handle("/", handler)

	var gr run.Group
	{
		if cfg.secureListenAddress != "" {
			srv := &http.Server{
				Handler:   mux,
				TLSConfig: &tls.Config{},
			}

			if cfg.tls.CertFile == "" && cfg.tls.KeyFile == "" {
				klog.Info("Generating self signed cert as no cert is provided")
				host, err := os.Hostname()
				if err != nil {
					return fmt.Errorf("failed to retrieve hostname for self-signed cert: %w", err)
				}
				certBytes, keyBytes, err := certutil.GenerateSelfSignedCertKey(host, nil, nil)
				if err != nil {
					return fmt.Errorf("failed to generate self signed cert and key: %w", err)
				}
				cert, err := tls.X509KeyPair(certBytes, keyBytes)
				if err != nil {
					return fmt.Errorf("failed to load generated self signed cert and key: %w", err)
				}

				srv.TLSConfig.Certificates = []tls.Certificate{cert}
			} else {
				klog.Info("Reading certificate files")
				r, err := rbac_proxy_tls.NewCertReloader(cfg.tls.CertFile, cfg.tls.KeyFile, cfg.tls.ReloadInterval)
				if err != nil {
					return fmt.Errorf("failed to initialize certificate reloader: %w", err)
				}

				srv.TLSConfig.GetCertificate = r.GetCertificate

				ctx, cancel := context.WithCancel(context.Background())
				gr.Add(func() error {
					return r.Watch(ctx)
				}, func(error) {
					cancel()
				})
			}

			if err := applyTLSConfig(srv.TLSConfig, cfg.tls); err != nil {
				return err
			}
			srv.TLSConfig.ClientAuth = tls.RequestClientCert

			if err := http2.ConfigureServer(srv, cfg.http2Options); err != nil {
				return fmt.Errorf("failed to configure http2 server: %w", err)
			}
			srv.TLSConfig.NextProtos = []string{"h2", "http/1.1"}

			gr.Add(func() error {
				klog.Infof("Starting TCP socket on %v", cfg.secureListenAddress)
				l, err := net.Listen("tcp", cfg.secureListenAddress)
				if err != nil {
					return fmt.Errorf("failed to listen on secure address: %w", err)
				}
				defer l.Close()

				klog.Infof("Listening securely on %v", cfg.secureListenAddress)
				tlsListener := tls.NewListener(l, srv.TLSConfig)
				return srv.Serve(tlsListener)
			}, func(err error) {
				if err := srv.Shutdown(context.Background()); err != nil {
					klog.Errorf("failed to gracefully shutdown server: %+v", err)
				}
			})

			if cfg.proxyEndpointsPort != 0 {
				proxyEndpointsMux := http.NewServeMux()
				proxyEndpointsMux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("ok")) })

				proxyEndpointsSrv := &http.Server{
					Handler:   proxyEndpointsMux,
					TLSConfig: srv.TLSConfig.Clone(),
				}

				if err := http2.ConfigureServer(proxyEndpointsSrv, cfg.http2Options); err != nil {
					return fmt.Errorf("failed to configure http2 server: %w", err)
				}
				proxyEndpointsSrv.TLSConfig.NextProtos = []string{"h2", "http/1.1"}

				gr.Add(func() error {
					host, _, err := net.SplitHostPort(cfg.secureListenAddress)
					if err != nil {
						return fmt.Errorf("failed to split %q into host and port: %w", cfg.secureListenAddress, err)
					}
					endpointsAddr := net.JoinHostPort(host, strconv.Itoa(cfg.proxyEndpointsPort))

					klog.Infof("Starting TCP socket on %v", endpointsAddr)
					proxyListener, err := net.Listen("tcp", endpointsAddr)
					if err != nil {
						return fmt.Errorf("failed to listen on secure address: %w", err)
					}
					defer proxyListener.Close()

					klog.Infof("Listening securely on %v for proxy endpoints", endpointsAddr)
					tlsListener := tls.NewListener(proxyListener, proxyEndpointsSrv.TLSConfig)
					return proxyEndpointsSrv.Serve(tlsListener)
				}, func(err error) {
					if err := proxyEndpointsSrv.Shutdown(context.Background()); err != nil {
						klog.Errorf("failed to gracefully shutdown proxy endpoints server: %+v", err)
					}
				})
			}
		}
	}
	{
		if cfg.insecureListenAddress != "" {
			srv := &http.Server{
				Handler: h2c.NewHandler(mux, cfg.http2Options),
			}

			l, err := net.Listen("tcp", cfg.insecureListenAddress)
			if err != nil {
				return fmt.Errorf("failed to listen on insecure address: %w", err)
			}

			gr.Add(func() error {
				klog.Infof("Listening insecurely on %v", cfg.insecureListenAddress)
				return srv.Serve(l)
			}, func(err error) {
				if err := srv.Shutdown(context.Background()); err != nil {
					klog.Errorf("failed to gracefully shutdown server: %+v", err)
				}
				if err := l.Close(); err != nil {
					klog.Errorf("failed to gracefully close listener: %+v", err)
				}
			})
		}
	}
	{
		sig := make(chan os.Signal, 1)
		gr.Add(func() error {
			signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
			<-sig
			klog.Info("received interrupt, shutting down")
			return nil
		}, func(err error) {
			close(sig)
		})
	}

	if len(cfg.secureListenAddress) == 0 && len(cfg.insecureListenAddress) == 0 {
		return fmt.Errorf("no listen address provided")
	}

	if err := gr.Run(); err != nil {
		return fmt.Errorf("failed to run groups: %w", err)
	}

	return nil
}

func newAuditLogger(profile audit.Profile, output io.Writer, options audit.Options) (*audit.Logger, error) {
	if err := profile.Validate(); err != nil {
		return nil, err
	}
	switch profile {
	case audit.ProfileNone:
		return nil, nil
	case audit.ProfileMetadata:
		return audit.NewLogger(output, options), nil
	default:
		return nil, fmt.Errorf("audit log profile %q has no logger implementation", profile)
	}
}

func buildProtectedHandler(
	proxyHandler http.HandlerFunc,
	authConfig *proxy.Config,
	requestAuthenticator authenticator.Request,
	requestAuthorizer authorizationauthorizer.Authorizer,
	auditLogger *audit.Logger,
) http.HandlerFunc {
	protectedHandler := filters.WithAuthHeaders(authConfig.Authentication.Header, proxyHandler)
	if auditLogger == nil {
		protectedHandler = filters.WithAuthorization(requestAuthorizer, authConfig.Authorization, protectedHandler)
		return filters.WithAuthentication(requestAuthenticator, authConfig.Authentication.Token.Audiences, protectedHandler)
	}

	protectedHandler = filters.WithAuthorizationAttributesObserver(
		requestAuthorizer,
		authConfig.Authorization,
		auditLogger.CaptureAuthorizationAttributes,
		protectedHandler,
	)
	protectedHandler = auditLogger.CaptureUser(protectedHandler)
	protectedHandler = filters.WithAuthentication(requestAuthenticator, authConfig.Authentication.Token.Audiences, protectedHandler)
	return auditLogger.WithAuditLog(protectedHandler)
}

func buildRequestHandler(proxyHandler, protectedHandler http.HandlerFunc, allowPaths, ignorePaths []string) http.HandlerFunc {
	handler := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		ignorePathFound := false
		for _, pathIgnored := range ignorePaths {
			var err error
			ignorePathFound, err = path.Match(pathIgnored, req.URL.Path)
			if err != nil {
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}
			if ignorePathFound {
				break
			}
		}

		if !ignorePathFound {
			protectedHandler(w, req)
			return
		}

		proxyHandler.ServeHTTP(w, req)
	})

	return filters.WithAllowPaths(allowPaths, handler)
}

func applyTLSConfig(config *tls.Config, options *options.TLSConfig) error {
	version, err := k8sapiflag.TLSVersion(normalizeTLSVersion(options.MinVersion))
	if err != nil {
		return fmt.Errorf("TLS version invalid: %w", err)
	}

	cipherSuiteIDs, err := k8sapiflag.TLSCipherSuites(options.CipherSuites)
	if err != nil {
		return fmt.Errorf("failed to convert TLS cipher suite name to ID: %w", err)
	}

	curvePreferences, err := rbac_proxy_tls.ParseCurvePreferences(options.CurvePreferences)
	if err != nil {
		return fmt.Errorf("failed to convert TLS curve preferences: %w", err)
	}

	config.CipherSuites = cipherSuiteIDs
	config.CurvePreferences = curvePreferences
	config.MinVersion = version
	return nil
}

// Returns intiliazed config, allows local usage (outside cluster) based on provided kubeconfig or in-cluter
func initKubeConfig(kcLocation string) (*rest.Config, error) {
	if kcLocation != "" {
		kubeConfig, err := clientcmd.BuildConfigFromFlags("", kcLocation)
		if err != nil {
			return nil, fmt.Errorf("unable to build rest config based on provided path to kubeconfig file: %w", err)
		}
		return kubeConfig, nil
	}

	kubeConfig, err := rest.InClusterConfig()
	if err != nil {
		return nil, fmt.Errorf("cannot find Service Account in pod to build in-cluster rest config: %w", err)
	}

	return kubeConfig, nil
}

func parseAuthorizationConfigFile(filePath string) (*authz.Config, error) {
	klog.Infof("Reading config file: %s", filePath)
	b, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read resource-attribute file: %w", err)
	}

	configFile := configfile{}

	if err := yaml.Unmarshal(b, &configFile); err != nil {
		return nil, fmt.Errorf("failed to parse config file content: %w", err)
	}

	if configFile.AuthorizationConfig != nil {
		if err := authz.ValidateAuthorizationConfig(configFile.AuthorizationConfig); err != nil {
			return nil, fmt.Errorf("invalid authorization config: %w", err)
		}
	}

	return configFile.AuthorizationConfig, nil
}

// normalizeTLSVersion accepts both kube-auth-proxy style ("TLS1.2", "TLS1.3")
// and k8s component-base style ("VersionTLS12", "VersionTLS13") version names.
func normalizeTLSVersion(input string) string {
	switch input {
	case "TLS1.0":
		return "VersionTLS10"
	case "TLS1.1":
		return "VersionTLS11"
	case "TLS1.2":
		return "VersionTLS12"
	case "TLS1.3":
		return "VersionTLS13"
	default:
		return input
	}
}

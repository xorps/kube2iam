package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts/types"
	"github.com/cenkalti/backoff/v5"
	"github.com/gorilla/mux"
	"github.com/jtblin/kube2iam"
	"github.com/jtblin/kube2iam/iam"
	"github.com/jtblin/kube2iam/k8s"
	"github.com/jtblin/kube2iam/mappings"
	"github.com/jtblin/kube2iam/metrics"
	log "github.com/sirupsen/logrus"
	"k8s.io/client-go/tools/cache"
)

const (
	defaultAppPort                    = "8181"
	defaultCacheSyncAttempts          = 10
	defaultIAMRoleKey                 = "iam.amazonaws.com/role"
	defaultIAMRoleSessionNameKey      = "iam.amazonaws.com/session-name"
	defaultIAMExternalID              = "iam.amazonaws.com/external-id"
	defaultLogLevel                   = "info"
	defaultLogFormat                  = "text"
	defaultMaxElapsedTime             = 2 * time.Second
	defaultIAMRoleSessionTTL          = 15 * time.Minute
	defaultMaxInterval                = 1 * time.Second
	defaultMetadataAddress            = "169.254.169.254"
	defaultNamespaceKey               = "iam.amazonaws.com/allowed-roles"
	defaultCacheResyncPeriod          = 30 * time.Minute
	defaultResolveDupIPs              = false
	defaultNamespaceRestrictionFormat = "glob"
	healthcheckInterval               = 30 * time.Second
)

var tokenRouteRegexp = regexp.MustCompile("^/?[^/]+/api/token$")

// Keeps track of the names of registered handlers for metric value/label initialization
var registeredHandlerNames []string

// Server encapsulates all of the parameters necessary for starting up
// the server. These can either be set via command line or directly.
type Server struct {
	APIServer                  string
	APIToken                   string
	AppPort                    string
	MetricsPort                string
	BaseRoleARN                string
	DefaultIAMRole             string
	IAMRoleKey                 string
	IAMRoleSessionNameKey      string
	IAMExternalID              string
	IAMRoleSessionTTL          time.Duration
	EnablePodIdentityTags      bool
	EksClusterName             string
	EksClusterARN              string
	MetadataAddress            string
	HostInterface              string
	HostIP                     string
	NodeName                   string
	NamespaceKey               string
	CacheResyncPeriod          time.Duration
	LogLevel                   string
	LogFormat                  string
	NamespaceRestrictionFormat string
	ResolveDupIPs              bool
	UseRegionalStsEndpoint     bool
	AddIPTablesRule            bool
	AutoDiscoverBaseArn        bool
	AutoDiscoverDefaultRole    bool
	Debug                      bool
	Insecure                   bool
	NamespaceRestriction       bool
	Verbose                    bool
	Version                    bool
	iam                        *iam.Client
	k8s                        *k8s.Client
	roleMapper                 *mappings.RoleMapper
	BackoffMaxElapsedTime      time.Duration
	BackoffMaxInterval         time.Duration
	InstanceID                 atomic.Pointer[string]
	HealthcheckFailReason      atomic.Pointer[string]
	healthcheckTicker          sync.Once
}

type appHandlerFunc func(*log.Entry, http.ResponseWriter, *http.Request)

type appHandler struct {
	name string
	fn   appHandlerFunc
}

type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

func newResponseWriter(w http.ResponseWriter) *responseWriter {
	return &responseWriter{w, http.StatusOK}
}

// ServeHTTP implements the net/http server Handler interface
// and recovers from panics.
func (h *appHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	logger := log.WithFields(log.Fields{
		"req.method": r.Method,
		"req.path":   r.URL.Path,
		"req.remote": parseRemoteAddr(r.RemoteAddr),
	})
	rw := newResponseWriter(w)

	// Set up a prometheus timer to track the request duration. It returns the timer value when
	// observed and stores it in timeSecs to report in logs. A function polls the Request and responseWriter
	// for the correct labels at observation time.
	var timeSecs float64
	lvsProducer := func() []string {
		return []string{strconv.Itoa(rw.statusCode), r.Method, h.name}
	}
	timer := metrics.NewFunctionTimer(metrics.HTTPRequestSec, lvsProducer, &timeSecs)

	defer func() {
		var err error
		if rec := recover(); rec != nil {
			switch t := rec.(type) {
			case string:
				err = errors.New(t)
			case error:
				err = t
			default:
				err = errors.New("unknown error")
			}
			logger.WithField("res.status", http.StatusInternalServerError).
				Errorf("PANIC error processing request: %+v", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}()
	h.fn(logger, rw, r)
	timer.ObserveDuration()
	latencyMilliseconds := timeSecs * 1e3
	if r.URL.Path != "/healthz" {
		logger.WithFields(log.Fields{"res.duration": latencyMilliseconds, "res.status": rw.statusCode}).
			Infof("%s %s (%d) took %f ms", r.Method, r.URL.Path, rw.statusCode, latencyMilliseconds)
	}
}

func newAppHandler(name string, fn appHandlerFunc) *appHandler {
	registeredHandlerNames = append(registeredHandlerNames, name)
	return &appHandler{name: name, fn: fn}
}

func parseRemoteAddr(addr string) string {
	n := strings.IndexByte(addr, ':')
	if n <= 1 {
		return ""
	}
	hostname := addr[0:n]
	if net.ParseIP(hostname) == nil {
		return ""
	}
	return hostname
}

func (s *Server) getRoleMapping(ctx context.Context, IP string) (*mappings.RoleMappingResult, error) {
	expBackoff := backoff.NewExponentialBackOff()
	expBackoff.MaxInterval = s.BackoffMaxInterval

	return backoff.Retry(ctx, func() (*mappings.RoleMappingResult, error) {
		return s.roleMapper.GetRoleMapping(ctx, IP)
	}, backoff.WithBackOff(expBackoff), backoff.WithMaxElapsedTime(s.BackoffMaxElapsedTime))
}

func (s *Server) getExternalIDMapping(ctx context.Context, IP string) (string, error) {
	expBackoff := backoff.NewExponentialBackOff()
	expBackoff.MaxInterval = s.BackoffMaxInterval

	return backoff.Retry(ctx, func() (string, error) {
		return s.roleMapper.GetExternalIDMapping(ctx, IP)
	}, backoff.WithBackOff(expBackoff), backoff.WithMaxElapsedTime(s.BackoffMaxElapsedTime))
}

func (s *Server) beginPollHealthcheck(ctx context.Context, interval time.Duration) {
	s.healthcheckTicker.Do(func() {
		s.doHealthcheck(ctx)

		go func(ctx context.Context, inteval time.Duration) {
			ticker := time.NewTicker(interval)
			defer ticker.Stop()

			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					s.doHealthcheck(ctx)
				}
			}
		}(ctx, interval)
	})
}

func (s *Server) doHealthcheck(ctx context.Context) {
	// Track the healthcheck status as a metric value. Running this function in the background on a timer
	// allows us to update both the /healthz endpoint and healthcheck metric value at once and keep them in sync.
	var err error
	var errMsg string
	// This deferred function stores the reason for failure in a Server struct member by parsing the error object
	// produced during the healthcheck, if any. It also stores a different metric value for the healthcheck depending
	// on whether it passed or failed.
	defer func() {
		var healthcheckResult float64 = 1
		s.HealthcheckFailReason.Store(aws.String(errMsg)) // Is empty if no error
		if err != nil || len(errMsg) > 0 {
			healthcheckResult = 0
		}
		metrics.HealthcheckStatus.Set(healthcheckResult)
	}()

	instanceId, err := s.iam.GetInstanceId(ctx)
	if err != nil {
		errMsg = fmt.Sprintf("Error getting instance id %+v", err)
		log.Errorf("%s", errMsg)
		return
	}

	s.InstanceID.Store(aws.String(instanceId))
}

// HealthResponse represents a response for the health check.
type HealthResponse struct {
	HostIP     string `json:"hostIP"`
	InstanceID string `json:"instanceId"`
}

func (s *Server) healthHandler(logger *log.Entry, w http.ResponseWriter, r *http.Request) {
	// healthHandler reports the last result of a timed healthcheck that repeats in the background.
	// The healthcheck logic is performed in doHealthcheck and saved into Server struct fields.
	// This "caching" of results allows the healthcheck to be monitored at a high request rate by external systems
	// without fear of overwhelming any rate limits with AWS or other dependencies.
	reason := aws.ToString(s.HealthcheckFailReason.Load())
	if len(reason) > 0 {
		http.Error(w, reason, http.StatusInternalServerError)
		return
	}

	instanceId := aws.ToString(s.InstanceID.Load())
	health := &HealthResponse{InstanceID: instanceId, HostIP: s.HostIP}
	w.Header().Add("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(health); err != nil {
		log.Errorf("Error sending json %+v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (s *Server) debugStoreHandler(logger *log.Entry, w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	o, err := json.Marshal(s.roleMapper.DumpDebugInfo(ctx))
	if err != nil {
		log.Errorf("Error converting debug map to json: %+v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	write(logger, w, string(o))
}

func (s *Server) securityCredentialsHandler(logger *log.Entry, w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	w.Header().Set("Server", "EC2ws")
	remoteIP := parseRemoteAddr(r.RemoteAddr)
	roleMapping, err := s.getRoleMapping(ctx, remoteIP)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	// If a base ARN has been supplied and this is not cross-account then
	// return a simple role-name, otherwise return the full ARN
	if s.iam.BaseARN != "" && strings.HasPrefix(roleMapping.Role, s.iam.BaseARN) {
		write(logger, w, strings.TrimPrefix(roleMapping.Role, s.iam.BaseARN))
		return
	}
	write(logger, w, roleMapping.Role)
}

func (s *Server) roleHandler(logger *log.Entry, w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	w.Header().Set("Server", "EC2ws")
	remoteIP := parseRemoteAddr(r.RemoteAddr)

	roleMapping, err := s.getRoleMapping(ctx, remoteIP)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	externalID, err := s.getExternalIDMapping(ctx, remoteIP)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	roleLogger := logger.WithFields(log.Fields{
		"pod.iam.role": roleMapping.Role,
		"ns.name":      roleMapping.Namespace,
	})

	wantedRole := mux.Vars(r)["role"]
	wantedRoleARN := s.iam.RoleARN(wantedRole)

	if wantedRoleARN != roleMapping.Role {
		roleLogger.WithField("params.iam.role", wantedRole).
			Error("Invalid role: does not match annotated role")
		http.Error(w, fmt.Sprintf("Invalid role %s", wantedRole), http.StatusForbidden)
		return
	}

	// these are a clone of EKS Pod Identity Session Tags
	// https://docs.aws.amazon.com/eks/latest/userguide/pod-id-abac.html#pod-id-abac-tags
	var tags []types.Tag
	if s.EnablePodIdentityTags {
		tags = []types.Tag{
			{
				Key:   aws.String("eks-cluster-arn"),
				Value: aws.String(s.EksClusterARN),
			},
			{
				Key:   aws.String("eks-cluster-name"),
				Value: aws.String(s.EksClusterName),
			},
			{
				Key:   aws.String("kubernetes-namespace"),
				Value: aws.String(roleMapping.Namespace),
			},
			{
				Key:   aws.String("kubernetes-service-account"),
				Value: aws.String(roleMapping.PodServiceAccountName),
			},
			{
				Key:   aws.String("kubernetes-pod-name"),
				Value: aws.String(roleMapping.PodName),
			},
			{
				Key:   aws.String("kubernetes-pod-uid"),
				Value: aws.String(roleMapping.PodUID),
			},
		}
	}

	credentials, err := s.iam.AssumeRole(ctx, wantedRoleARN, roleMapping.SessionName, externalID, remoteIP, s.IAMRoleSessionTTL, tags)
	if err != nil {
		roleLogger.Errorf("Error assuming role %+v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	roleLogger.Debugf("retrieved credentials from sts endpoint: %s", s.iam.Endpoint)

	if err := json.NewEncoder(w).Encode(credentials); err != nil {
		roleLogger.Errorf("Error sending json %+v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (s *Server) reverseProxyHandler(logger *log.Entry, w http.ResponseWriter, r *http.Request) {
	// Remove remoteaddr to prevent issues with new IMDSv2 to fail when x-forwarded-for header is present
	// for more details please see: https://github.com/aws/aws-sdk-ruby/issues/2177 https://github.com/uswitch/kiam/issues/359
	token := r.Header.Get("X-aws-ec2-metadata-token")
	if (r.Method == http.MethodPut && tokenRouteRegexp.MatchString(r.URL.Path)) || (r.Method == http.MethodGet && token != "") {
		r.RemoteAddr = ""
	}

	proxy := httputil.NewSingleHostReverseProxy(&url.URL{Scheme: "http", Host: s.MetadataAddress})
	proxy.ServeHTTP(w, r)
	logger.WithField("metadata.url", s.MetadataAddress).Debug("Proxy ec2 metadata request")
}

func write(logger *log.Entry, w http.ResponseWriter, s string) {
	if _, err := w.Write([]byte(s)); err != nil {
		logger.Errorf("Error writing response: %+v", err)
	}
}

// Run runs the specified Server.
func (s *Server) Run(ctx context.Context, host, token, nodeName string, insecure bool) error {
	k, err := k8s.NewClient(host, token, nodeName, insecure, s.ResolveDupIPs)
	if err != nil {
		return err
	}

	s.k8s = k
	s.iam = iam.NewClient(s.BaseRoleARN, s.UseRegionalStsEndpoint)

	log.Debugln("Caches have been synced.  Proceeding with server.")

	s.roleMapper = mappings.NewRoleMapper(s.IAMRoleKey, s.IAMRoleSessionNameKey, s.IAMExternalID, s.DefaultIAMRole, s.NamespaceRestriction, s.NamespaceKey, s.iam, s.k8s, s.NamespaceRestrictionFormat)

	log.Debugf("Starting pod and namespace sync jobs with %s resync period", s.CacheResyncPeriod.String())

	podSynched := s.k8s.WatchForPods(kube2iam.NewPodHandler(s.IAMRoleKey), s.CacheResyncPeriod)
	namespaceSynched := s.k8s.WatchForNamespaces(kube2iam.NewNamespaceHandler(s.NamespaceKey), s.CacheResyncPeriod)

	synced := false
	for i := 0; i < defaultCacheSyncAttempts && !synced; i++ {
		synced = cache.WaitForCacheSync(nil, podSynched, namespaceSynched)
	}

	if !synced {
		return fmt.Errorf("Attempted to wait for caches to be synced for %d however it is not done.  Giving up.", defaultCacheSyncAttempts)
	} else {
		log.Debugln("Caches have been synced.  Proceeding with server.")
	}

	// Begin healthchecking
	s.beginPollHealthcheck(ctx, healthcheckInterval)

	r := mux.NewRouter()
	securityHandler := newAppHandler("securityCredentialsHandler", s.securityCredentialsHandler)

	if s.Debug {
		// This is a potential security risk if enabled in some clusters, hence the flag
		r.Handle("/debug/store", newAppHandler("debugStoreHandler", s.debugStoreHandler))
	}
	r.Handle("/{version}/meta-data/iam/security-credentials", securityHandler)
	r.Handle("/{version}/meta-data/iam/security-credentials/", securityHandler)
	r.Handle(
		"/{version}/meta-data/iam/security-credentials/{role:.*}",
		newAppHandler("roleHandler", s.roleHandler))
	r.Handle("/healthz", newAppHandler("healthHandler", s.healthHandler))

	if s.MetricsPort == s.AppPort {
		r.Handle("/metrics", metrics.GetHandler())
	} else {
		metrics.StartMetricsServer(s.MetricsPort)
	}

	// This has to be registered last so that it catches fall-throughs
	r.Handle("/{path:.*}", newAppHandler("reverseProxyHandler", s.reverseProxyHandler))

	log.Infof("Listening on port %s", s.AppPort)

	if err := http.ListenAndServe(":"+s.AppPort, r); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("Error creating kube2iam http server: %+v", err)
	}

	return nil
}

// NewServer will create a new Server with default values.
func NewServer() *Server {
	s := &Server{
		AppPort:                    defaultAppPort,
		MetricsPort:                defaultAppPort,
		BackoffMaxElapsedTime:      defaultMaxElapsedTime,
		IAMRoleKey:                 defaultIAMRoleKey,
		IAMRoleSessionNameKey:      defaultIAMRoleSessionNameKey,
		IAMExternalID:              defaultIAMExternalID,
		BackoffMaxInterval:         defaultMaxInterval,
		LogLevel:                   defaultLogLevel,
		LogFormat:                  defaultLogFormat,
		MetadataAddress:            defaultMetadataAddress,
		NamespaceKey:               defaultNamespaceKey,
		CacheResyncPeriod:          defaultCacheResyncPeriod,
		ResolveDupIPs:              defaultResolveDupIPs,
		NamespaceRestrictionFormat: defaultNamespaceRestrictionFormat,
		IAMRoleSessionTTL:          defaultIAMRoleSessionTTL,
	}

	s.HealthcheckFailReason.Store(aws.String("Healthcheck not yet performed"))

	return s
}

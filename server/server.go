package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/cenk/backoff"
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
	defaultCacheSyncAttempts = 10
	healthcheckInterval      = 30 * time.Second
)

// Keeps track of the names of registered handlers for metric value/label initialization
var registeredHandlerNames []string

// Server encapsulates all of the parameters necessary for starting up
// the server. These can either be set via command line or directly.
type Server struct {
	iamRoleKey            string
	iamRoleSessionTTL     time.Duration
	backoffMaxInterval    time.Duration
	backoffMaxElapsedTime time.Duration
	metadataAddress       string
	namespaceKey          string
	instanceID            string
	appPort               int
	metricsPort           int
	metricsBindIP         string
	bindIP                string
	debug                 bool
	iam                   *iam.Client
	k8s                   *k8s.Client
	roleMapper            *mappings.RoleMapper
	healthcheckTicker     *time.Ticker
	HealthcheckFailReason string
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
	latencyNanoseconds := timeSecs * 1e9
	if r.URL.Path != "/healthz" {
		logger.WithFields(log.Fields{"res.duration": latencyNanoseconds, "res.status": rw.statusCode}).
			Infof("%s %s (%d) took %f ns", r.Method, r.URL.Path, rw.statusCode, latencyNanoseconds)
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

// NewServer will create a new Server with default values.
func NewServer(config *Config) (error, *Server) {
	k, err := k8s.NewClient(config.APIServer, config.APIToken, config.APIToken, config.Insecure)
	if err != nil {
		return err, nil
	}

	iamClient := iam.NewClient(config.BaseRoleARN, config.UseRegionalStsEndpoint)
	log.Debugln("Caches have been synced.  Proceeding with server.")
	roleMapper := mappings.NewRoleMapper(config.IAMRoleKey, config.DefaultIAMRole, config.NamespaceRestriction, config.NamespaceKey, iamClient, k, config.NamespaceRestrictionFormat)

	if config.BaseRoleARN != "" {
		if !iam.IsValidBaseARN(config.BaseRoleARN) {
			return fmt.Errorf("invalid --base-role-arn specified, expected: %s", iam.ARNRegexp.String()), nil
		}
		if !strings.HasSuffix(config.BaseRoleARN, "/") {
			config.BaseRoleARN += "/"
		}
	}

	if config.AutoDiscoverBaseArn {
		if config.BaseRoleARN != "" {
			return fmt.Errorf("--auto-discover-base-arn cannot be used if --base-role-arn is specified"), nil
		}
		arn, err := iam.GetBaseArn()
		if err != nil {
			return fmt.Errorf("%s", err), nil
		}
		log.WithField("arn", arn).Info("base ARN autodetected")
		config.BaseRoleARN = arn
	}

	if config.AutoDiscoverDefaultRole {
		if config.DefaultIAMRole != "" {
			return fmt.Errorf("you cannot use --default-role and --auto-discover-default-role at the same time"), nil
		}
		arn, err := iam.GetBaseArn()
		if err != nil {
			return fmt.Errorf("%s", err), nil
		}
		config.BaseRoleARN = arn
		instanceIAMRole, err := iam.GetInstanceIAMRole()
		if err != nil {
			return fmt.Errorf("%s", err), nil
		}
		config.DefaultIAMRole = instanceIAMRole
		log.WithFields(log.Fields{"baseArn": config.BaseRoleARN, "defaultIAMRole": config.DefaultIAMRole}).Info("Using instance IAMRole as default")
	}

	return nil, &Server{
		k8s:                   k,
		iam:                   iamClient,
		roleMapper:            roleMapper,
		bindIP:                config.BindIP,
		appPort:               config.AppPort,
		metricsBindIP:         config.MetricsBindIP,
		metricsPort:           config.MetricsPort,
		debug:                 config.Debug,
		namespaceKey:          config.NamespaceKey,
		iamRoleKey:            config.IAMRoleKey,
		iamRoleSessionTTL:     config.IAMRoleSessionTTL,
		metadataAddress:       config.MetadataAddress,
		backoffMaxElapsedTime: config.BackoffMaxElapsedTime,
		backoffMaxInterval:    config.BackoffMaxInterval,
		HealthcheckFailReason: "Healthcheck not yet performed",
	}
}

func (s *Server) getRoleMapping(IP string) (*mappings.RoleMappingResult, error) {
	var roleMapping *mappings.RoleMappingResult
	var err error
	operation := func() error {
		roleMapping, err = s.roleMapper.GetRoleMapping(IP)
		return err
	}

	expBackoff := backoff.NewExponentialBackOff()
	expBackoff.MaxInterval = s.backoffMaxInterval
	expBackoff.MaxElapsedTime = s.backoffMaxElapsedTime

	err = backoff.Retry(operation, expBackoff)
	if err != nil {
		return nil, err
	}

	return roleMapping, nil
}

func (s *Server) beginPollHealthcheck(interval time.Duration) {
	if s.healthcheckTicker == nil {
		s.doHealthcheck()
		s.healthcheckTicker = time.NewTicker(interval)
		go func() {
			for {
				<-s.healthcheckTicker.C
				s.doHealthcheck()
			}
		}()
	}
}

func (s *Server) doHealthcheck() {
	// Track the healthcheck status as a metric value. Running this function in the background on a timer
	// allows us to update both the /healthz endpoint and healthcheck metric value at once and keep them in sync.
	var err error
	var errMsg string
	// This deferred function stores the reason for failure in a Server struct member by parsing the error object
	// produced during the healthcheck, if any. It also stores a different metric value for the healthcheck depending
	// on whether it passed or failed.
	defer func() {
		var healthcheckResult float64 = 1
		s.HealthcheckFailReason = errMsg // Is empty if no error
		if err != nil || len(errMsg) > 0 {
			healthcheckResult = 0
		}
		metrics.HealthcheckStatus.Set(healthcheckResult)
	}()

	resp, err := http.Get(fmt.Sprintf("http://%s/latest/meta-data/instance-id", s.metadataAddress))
	if err != nil {
		errMsg = fmt.Sprintf("Error getting instance id %+v", err)
		log.Errorf(errMsg)
		return
	}
	if resp.StatusCode != 200 {
		errMsg = fmt.Sprintf("Error getting instance id, got status: %+s", resp.Status)
		log.Error(errMsg)
		return
	}
	defer resp.Body.Close()
	instanceID, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		errMsg = fmt.Sprintf("Error reading response body %+v", err)
		log.Errorf(errMsg)
		return
	}
	s.instanceID = string(instanceID)
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
	if len(s.HealthcheckFailReason) > 0 {
		http.Error(w, s.HealthcheckFailReason, http.StatusInternalServerError)
		return
	}

	health := &HealthResponse{InstanceID: s.instanceID, HostIP: s.bindIP}
	w.Header().Add("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(health); err != nil {
		log.Errorf("Error sending json %+v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (s *Server) debugStoreHandler(logger *log.Entry, w http.ResponseWriter, r *http.Request) {
	o, err := json.Marshal(s.roleMapper.DumpDebugInfo())
	if err != nil {
		log.Errorf("Error converting debug map to json: %+v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	write(logger, w, string(o))
}

func (s *Server) securityCredentialsHandler(logger *log.Entry, w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Server", "EC2ws")
	remoteIP := parseRemoteAddr(r.RemoteAddr)
	roleMapping, err := s.getRoleMapping(remoteIP)
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
	w.Header().Set("Server", "EC2ws")
	remoteIP := parseRemoteAddr(r.RemoteAddr)

	roleMapping, err := s.getRoleMapping(remoteIP)
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

	credentials, err := s.iam.AssumeRole(wantedRoleARN, remoteIP, s.iamRoleSessionTTL)
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
	proxy := httputil.NewSingleHostReverseProxy(&url.URL{Scheme: "http", Host: s.metadataAddress})
	proxy.ServeHTTP(w, r)
	logger.WithField("metadata.url", s.metadataAddress).Debug("Proxy ec2 metadata request")
}

func write(logger *log.Entry, w http.ResponseWriter, s string) {
	if _, err := w.Write([]byte(s)); err != nil {
		logger.Errorf("Error writing response: %+v", err)
	}
}

// Run runs the specified Server.
func (s *Server) Init() error {
	podSynched := s.k8s.WatchForPods(kube2iam.NewPodHandler(s.iamRoleKey))
	namespaceSynched := s.k8s.WatchForNamespaces(kube2iam.NewNamespaceHandler(s.namespaceKey))

	synced := false
	for i := 0; i < defaultCacheSyncAttempts && !synced; i++ {
		synced = cache.WaitForCacheSync(nil, podSynched, namespaceSynched)
	}

	if !synced {
		return fmt.Errorf("attempted to wait for caches to be synced for %d however it is not done.  Giving up.", defaultCacheSyncAttempts)
	}
	log.Debugln("Caches have been synced.  Proceeding with server.")

	// Begin healthchecking
	s.beginPollHealthcheck(healthcheckInterval)
	return nil
}

// Run runs the specified Server.
func (s *Server) Serve(ctx context.Context) error {
	r := mux.NewRouter()
	securityHandler := newAppHandler("securityCredentialsHandler", s.securityCredentialsHandler)

	if s.debug {
		// This is a potential security risk if enabled in some clusters, hence the flag
		r.Handle("/debug/store", newAppHandler("debugStoreHandler", s.debugStoreHandler))
	}
	r.Handle("/{version}/meta-data/iam/security-credentials", securityHandler)
	r.Handle("/{version}/meta-data/iam/security-credentials/", securityHandler)
	r.Handle(
		"/{version}/meta-data/iam/security-credentials/{role:.*}",
		newAppHandler("roleHandler", s.roleHandler))
	r.Handle("/healthz", newAppHandler("healthHandler", s.healthHandler))

	if s.metricsPort == s.appPort && s.metricsBindIP == s.bindIP {
		r.Handle("/metrics", metrics.GetHandler())
	} else {
		metrics.StartMetricsServer(s.metricsBindIP, s.metricsPort)
	}

	// This has to be registered last so that it catches fall-throughs
	r.Handle("/{path:.*}", newAppHandler("reverseProxyHandler", s.reverseProxyHandler))

	errs := make(chan error)
	listeningAddr := fmt.Sprintf("%s:%d", s.bindIP, s.appPort)
	server := &http.Server{
		Addr:         listeningAddr,
		Handler:      r,
		WriteTimeout: 15 * time.Second,
		ReadTimeout:  15 * time.Second,
	}
	go func() {
		log.WithFields(log.Fields{"bindIp": s.bindIP, "appPort": s.appPort}).Info("kube2iam listening")
		if err := server.ListenAndServe(); err != nil {
			errs <- err
		}
	}()
	select {
	case err := <-errs:
		return err

	case <-ctx.Done():
		log.Info("kube2iam shutting down")
		shutdown, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()

		return server.Shutdown(shutdown)
	}
	return nil
}

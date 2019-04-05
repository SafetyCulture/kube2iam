package server

import (
	"time"

	"github.com/pkg/errors"
)

// Config encapsulates all of the parameters necessary for starting up
// They will be set via commandline
type Config struct {
	APIServer                  string
	APIToken                   string
	AppPort                    int
	MetricsPort                int
	MetricsBindIP              string
	BaseRoleARN                string
	Debug                      bool
	DefaultIAMRole             string
	IAMRoleKey                 string
	IAMRoleSessionTTL          time.Duration
	MetadataAddress            string
	HostInterface              string
	BindIP                     string
	NodeName                   string
	NamespaceKey               string
	LogLevel                   string
	LogFormat                  string
	Insecure                   bool
	AddIPTablesRule            bool
	AutoDiscoverBaseArn        bool
	AutoDiscoverDefaultRole    bool
	NamespaceRestriction       bool
	NamespaceRestrictionFormat string
	UseRegionalStsEndpoint     bool
	Version                    bool
	BackoffMaxElapsedTime      time.Duration
	BackoffMaxInterval         time.Duration
}

const (
	DefaultAppPort                    = 8181
	DefaultBindIP                     = "127.0.0.1"
	DefaultIAMRoleKey                 = "iam.amazonaws.com/role"
	DefaultLogLevel                   = "info"
	DefaultLogFormat                  = "text"
	DefaultMaxElapsedTime             = 2 * time.Second
	DefaultIAMRoleSessionTTL          = 15 * time.Minute
	DefaultMaxInterval                = 1 * time.Second
	DefaultMetadataAddress            = "169.254.169.254"
	DefaultNamespaceKey               = "iam.amazonaws.com/allowed-roles"
	DefaultNamespaceRestrictionFormat = "glob"
)

func (c *Config) Validate() error {
	if c.MetricsPort == c.AppPort &&
		c.BindIP != c.MetricsBindIP {
		return errors.New("metrics-bind-ip can't be equal to bind-ip when app-port == metric-port")
	}
	return nil
}

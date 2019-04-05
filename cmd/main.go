package main

import (
	"context"
	"os"
	"os/signal"
	"strings"
	"syscall"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/pflag"

	"github.com/jtblin/kube2iam/iptables"
	"github.com/jtblin/kube2iam/server"
	"github.com/jtblin/kube2iam/version"
)

// addFlags adds the command line flags.
func addFlags(s *server.Config, fs *pflag.FlagSet) {
	fs.StringVar(&s.APIServer, "api-server", "", "Endpoint for the api server")
	fs.StringVar(&s.APIToken, "api-token", "", "Token to authenticate with the api server")
	fs.IntVar(&s.AppPort, "app-port", server.DefaultAppPort, "Kube2iam server http port")
	fs.IntVar(&s.MetricsPort, "metrics-port", server.DefaultAppPort, "Metrics server http port (default: same as kube2iam server port)")
	fs.StringVar(&s.MetricsBindIP, "metrics-bind-ip", server.DefaultBindIP, "Metrics server http port (default: same as kube2iam server port)")
	fs.StringVar(&s.BaseRoleARN, "base-role-arn", "", "Base role ARN")
	fs.BoolVar(&s.Debug, "debug", false, "Enable debug features")
	fs.StringVar(&s.DefaultIAMRole, "default-role", "", "Fallback role to use when annotation is not set")
	fs.StringVar(&s.IAMRoleKey, "iam-role-key", server.DefaultIAMRoleKey, "Pod annotation key used to retrieve the IAM role")
	fs.DurationVar(&s.IAMRoleSessionTTL, "iam-role-session-ttl", server.DefaultIAMRoleSessionTTL, "TTL for the assume role session")
	fs.BoolVar(&s.Insecure, "insecure", false, "Kubernetes server should be accessed without verifying the TLS. Testing only")
	fs.StringVar(&s.MetadataAddress, "metadata-addr", server.DefaultMetadataAddress, "Address for the ec2 metadata")
	fs.BoolVar(&s.AddIPTablesRule, "iptables", false, "Add iptables rule (also requires --bind-ip)")
	fs.BoolVar(&s.AutoDiscoverBaseArn, "auto-discover-base-arn", false, "Queries EC2 Metadata to determine the base ARN")
	fs.BoolVar(&s.AutoDiscoverDefaultRole, "auto-discover-default-role", false, "Queries EC2 Metadata to determine the default Iam Role and base ARN, cannot be used with --default-role, overwrites any previous setting for --base-role-arn")
	fs.StringVar(&s.HostInterface, "host-interface", "docker0", "Host interface for proxying AWS metadata")
	fs.BoolVar(&s.NamespaceRestriction, "namespace-restrictions", false, "Enable namespace restrictions")
	fs.StringVar(&s.NamespaceRestrictionFormat, "namespace-restriction-format", server.DefaultNamespaceRestrictionFormat, "Namespace Restriction Format (glob/regexp)")
	fs.StringVar(&s.NamespaceKey, "namespace-key", server.DefaultNamespaceKey, "Namespace annotation key used to retrieve the IAM roles allowed (value in annotation should be json array)")
	fs.StringVar(&s.BindIP, "bind-ip", server.DefaultBindIP, "IP address to listen on (default to 127.0.0.1)")
	fs.StringVar(&s.NodeName, "node", "", "Name of the node where kube2iam is running")
	fs.DurationVar(&s.BackoffMaxInterval, "backoff-max-interval", server.DefaultMaxInterval, "Max interval for backoff when querying for role.")
	fs.DurationVar(&s.BackoffMaxElapsedTime, "backoff-max-elapsed-time", server.DefaultMaxElapsedTime, "Max elapsed time for backoff when querying for role.")
	fs.StringVar(&s.LogFormat, "log-format", server.DefaultLogFormat, "Log format (text/json)")
	fs.StringVar(&s.LogLevel, "log-level", server.DefaultLogLevel, "Log level")
	fs.BoolVar(&s.UseRegionalStsEndpoint, "use-regional-sts-endpoint", false, "use the regional sts endpoint if AWS_REGION is set")
	fs.BoolVar(&s.Version, "version", false, "Print the version and exits")
}

func main() {
	config := &server.Config{}
	addFlags(config, pflag.CommandLine)
	pflag.Parse()

	if config.Version {
		version.PrintVersionAndExit()
	}

	logLevel, err := log.ParseLevel(config.LogLevel)
	if err != nil {
		log.Fatalf("%s", err)
	}
	log.SetLevel(logLevel)

	if strings.ToLower(config.LogFormat) == "json" {
		log.SetFormatter(&log.JSONFormatter{})
	}

	if err = config.Validate(); err != nil {
		log.WithError(err).Fatal("failed to validate config")
	}

	if config.AddIPTablesRule {
		if err := iptables.ClearRules(); err != nil {
			log.Fatalf("%s", err)
		}

		if err := iptables.AddRule(config.AppPort, config.MetadataAddress, config.HostInterface, config.BindIP); err != nil {
			log.Fatalf("%s", err)
		}
		defer func() {
			err = iptables.ClearChain()
			if err != nil {
				log.WithError(err).Errorf("failed to clean iptables chain")
			}
		}()
	}

	err, s := server.NewServer(config)
	if err != nil {
		log.WithError(err).Fatal("failed to create server")
	}

	if err = s.Init(); err != nil {
		log.WithError(err).Fatal("failed to init")
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error)
	go func() {
		done <- s.Serve(ctx)
	}()

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigs
		log.WithField("sig", sig).Info("received signal, cleaning up")
		cancel()
	}()

	<-done
}

package main

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/pflag"

	"github.com/jtblin/kube2iam/iam"
	"github.com/jtblin/kube2iam/iptables"
	"github.com/jtblin/kube2iam/server"
	"github.com/jtblin/kube2iam/version"
)

const (
	defaultAppPort                    = "8181"
	defaultCacheSyncAttempts          = 10
	defaultIAMRoleKey                 = "iam.amazonaws.com/role"
	defaultIAMRoleSessionNameKey      = "iam.amazonaws.com/session-name"
	defaultIAMExternalIDKey           = "iam.amazonaws.com/external-id"
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
	defaultHealthcheckInterval        = 30 * time.Second
)

func run(ctx context.Context) error {
	var (
		apiServer                  string
		apiToken                   string
		appPort                    string
		metricsPort                string
		baseRoleARN                string
		debug                      bool
		defaultIAMRole             string
		iamRoleKey                 string
		iamRoleSessionNameKey      string
		iamExternalIDKey           string
		iamRoleSessionTTL          time.Duration
		enablePodIdentityTags      bool
		eksClusterARN              string
		eksClusterName             string
		insecure                   bool
		metadataAddress            string
		addIPTablesRule            bool
		autoDiscoverBaseArn        bool
		autoDiscoverDefaultRole    bool
		hostInterface              string
		namespaceRestriction       bool
		namespaceRestrictionFormat string
		namespaceKey               string
		cacheResyncPeriod          time.Duration
		resolveDupIPs              bool
		hostIP                     string
		nodeName                   string
		backoffMaxInterval         time.Duration
		backoffMaxElapsedTime      time.Duration
		logFormat                  string
		logLevel                   string
		useRegionalStsEndpoint     bool
		verbose                    bool
		printVersion               bool
		assumeRoleArn              string
		cacheSyncAttempts          int
		healthcheckInterval        time.Duration
	)

	fs := pflag.CommandLine

	fs.StringVar(&apiServer, "api-server", "", "Endpoint for the api server")
	fs.StringVar(&apiToken, "api-token", "", "Token to authenticate with the api server")
	fs.StringVar(&appPort, "app-port", defaultAppPort, "Kube2iam server http port")
	fs.StringVar(&metricsPort, "metrics-port", defaultAppPort, "Metrics server http port (default: same as kube2iam server port)")
	fs.StringVar(&baseRoleARN, "base-role-arn", "", "Base role ARN")
	fs.BoolVar(&debug, "debug", false, "Enable debug features")
	fs.StringVar(&defaultIAMRole, "default-role", "", "Fallback role to use when annotation is not set")
	fs.StringVar(&iamRoleKey, "iam-role-key", defaultIAMRoleKey, "Pod annotation key used to retrieve the IAM role")
	fs.StringVar(&iamRoleSessionNameKey, "iam-role-session-name-key", defaultIAMRoleSessionNameKey, "Pod annotation key used to set IAM Role Session Name")
	fs.StringVar(&iamExternalIDKey, "iam-external-id", defaultIAMExternalIDKey, "Pod annotation key used to retrieve the IAM ExternalId")
	fs.DurationVar(&iamRoleSessionTTL, "iam-role-session-ttl", defaultIAMRoleSessionTTL, "TTL for the assume role session")
	fs.BoolVar(&enablePodIdentityTags, "iam-enable-pod-identity-tags", false, "Enable EKS Pod Identity Session tagging")
	fs.StringVar(&eksClusterARN, "eks-cluster-arn", "", "Sets EKS Cluster Arn for Pod Identity Tagging")
	fs.StringVar(&eksClusterName, "eks-cluster-name", "", "Sets EKS Cluster Name for Pod Identity Tagging")
	fs.BoolVar(&insecure, "insecure", false, "Kubernetes server should be accessed without verifying the TLS. Testing only")
	fs.StringVar(&metadataAddress, "metadata-addr", defaultMetadataAddress, "Address for the ec2 metadata")
	fs.BoolVar(&addIPTablesRule, "iptables", false, "Add iptables rule (also requires --host-ip)")
	fs.BoolVar(&autoDiscoverBaseArn, "auto-discover-base-arn", false, "Queries EC2 Metadata to determine the base ARN")
	fs.BoolVar(&autoDiscoverDefaultRole, "auto-discover-default-role", false, "Queries EC2 Metadata to determine the default Iam Role and base ARN, cannot be used with --default-role, overwrites any previous setting for --base-role-arn")
	fs.StringVar(&hostInterface, "host-interface", "docker0", "Host interface for proxying AWS metadata")
	fs.BoolVar(&namespaceRestriction, "namespace-restrictions", false, "Enable namespace restrictions")
	fs.StringVar(&namespaceRestrictionFormat, "namespace-restriction-format", defaultNamespaceRestrictionFormat, "Namespace Restriction Format (glob/regexp)")
	fs.StringVar(&namespaceKey, "namespace-key", defaultNamespaceKey, "Namespace annotation key used to retrieve the IAM roles allowed (value in annotation should be json array)")
	fs.DurationVar(&cacheResyncPeriod, "cache-resync-period", defaultCacheResyncPeriod, "Kubernetes caches resync period")
	fs.BoolVar(&resolveDupIPs, "resolve-duplicate-cache-ips", false, "Queries the k8s api server to find the source of truth when the pod cache contains multiple pods with the same IP")
	fs.StringVar(&hostIP, "host-ip", "", "IP address of host")
	fs.StringVar(&nodeName, "node", "", "Name of the node where kube2iam is running")
	fs.DurationVar(&backoffMaxInterval, "backoff-max-interval", defaultMaxInterval, "Max interval for backoff when querying for role.")
	fs.DurationVar(&backoffMaxElapsedTime, "backoff-max-elapsed-time", defaultMaxElapsedTime, "Max elapsed time for backoff when querying for role.")
	fs.StringVar(&logFormat, "log-format", defaultLogFormat, "Log format (text/json)")
	fs.StringVar(&logLevel, "log-level", defaultLogLevel, "Log level")
	fs.BoolVar(&useRegionalStsEndpoint, "use-regional-sts-endpoint", false, "use the regional sts endpoint if AWS_REGION is set")
	fs.BoolVar(&verbose, "verbose", false, "Verbose")
	fs.BoolVar(&printVersion, "version", false, "Print the version and exits")
	fs.StringVar(&assumeRoleArn, "assume-role-arn", "", "role to assume")
	fs.IntVar(&cacheSyncAttempts, "cache-sync-attempts", defaultCacheSyncAttempts, "number of attempts to wait for cache sync")
	fs.DurationVar(&healthcheckInterval, "healthcheck-interval", defaultHealthcheckInterval, "health check interval")

	pflag.Parse()

	l, err := log.ParseLevel(logLevel)
	if err != nil {
		return err
	}

	if verbose {
		log.SetLevel(log.DebugLevel)
	} else {
		log.SetLevel(l)
	}

	if strings.ToLower(logFormat) == "json" {
		log.SetFormatter(&log.JSONFormatter{})
	}

	if printVersion {
		version.PrintVersionAndExit()
	}

	if baseRoleARN != "" {
		if !iam.IsValidBaseARN(baseRoleARN) {
			return fmt.Errorf("Invalid --base-role-arn specified, expected: %s", iam.ARNRegexp.String())
		}

		if !strings.HasSuffix(baseRoleARN, "/") {
			baseRoleARN += "/"
		}
	}

	if autoDiscoverBaseArn {
		if baseRoleARN != "" {
			return errors.New("--auto-discover-base-arn cannot be used if --base-role-arn is specified")
		}

		arn, err := iam.GetBaseArn(ctx)
		if err != nil {
			return err
		}

		log.Infof("base ARN autodetected, %s", arn)

		baseRoleARN = arn
	}

	if autoDiscoverDefaultRole {
		if defaultIAMRole != "" {
			return errors.New("You cannot use --default-role and --auto-discover-default-role at the same time")
		}

		arn, err := iam.GetBaseArn(ctx)
		if err != nil {
			return err
		}

		baseRoleARN = arn

		instanceIAMRole, err := iam.GetInstanceIAMRole(ctx)
		if err != nil {
			return err
		}

		defaultIAMRole = instanceIAMRole

		log.Infof("Using instance IAMRole %s%s as default", baseRoleARN, defaultIAMRole)
	}

	if addIPTablesRule {
		if err := iptables.AddRule(appPort, metadataAddress, hostInterface, hostIP); err != nil {
			return fmt.Errorf("failed to add iptable rule: %w", err)
		}
	}

	if enablePodIdentityTags {
		if eksClusterARN == "" {
			return errors.New("--eks-cluster-arn is required when using pod identity tags")
		}
		if eksClusterName == "" {
			return errors.New("--eks-cluster-name is required when using pod identity tags")
		}
	}

	s, err := server.New(ctx, &server.Args{
		IAMRoleKey:            iamRoleKey,
		IAMRoleSessionNameKey: iamRoleSessionNameKey,
		IAMExternalIDKey:      iamExternalIDKey,
		Host:                  hostIP,
		Token:                 apiToken,
		NodeName:              nodeName,
		Insecure:              insecure,
		ResolveDupIPs:         resolveDupIPs,
		AssumeRoleARN:         assumeRoleArn,
	})
	if err != nil {
		return fmt.Errorf("failed to create server: %w", err)
	}

	return s.Run(ctx)
}

func main() {
	if err := run(context.Background()); err != nil {
		log.Fatal(err)
	}
}

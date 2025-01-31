package iam

import (
	"context"
	"errors"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/aws-sdk-go-v2/service/sts/types"
	"github.com/jtblin/kube2iam/metrics"
	"github.com/karlseguin/ccache/v3"
)

type Credentials struct {
	AccessKeyID     string `json:"AccessKeyId"`
	Code            string
	Expiration      string
	LastUpdated     string
	SecretAccessKey string
	Token           string
	Type            string
}

type AssumeRoleArgs struct {
	SessionTTL      time.Duration
	RoleARN         string
	RoleSessionName string
	ExternalID      string
	RemoteIP        string
	Tags            []types.Tag
}

type Client interface {
	AssumeRole(ctx context.Context, args *AssumeRoleArgs) (*Credentials, error)
	Endpoint() string
	RoleARN(role string) string
	BaseRoleARN() string
}

type DefaultClient struct {
	svc     *sts.Client
	cache   *ccache.Cache[*Credentials]
	baseARN string
}

// type check
var _ Client = (*DefaultClient)(nil)

func (c *DefaultClient) AssumeRole(ctx context.Context, args *AssumeRoleArgs) (*Credentials, error) {
	if c == nil {
		return nil, errors.New("iam DefaultClient: nil receiver")
	}

	if args == nil {
		args = &AssumeRoleArgs{} //nolint:exhaustruct
	}

	creds, cacheHit, err := cacheFetch(c.cache, args.RoleARN, args.SessionTTL, func() (*Credentials, error) {
		// Set up a prometheus timer to track the AWS request duration. It stores the timer value when
		// observed. A function gets err at observation time to report the status of the request after the function returns.
		var err error
		timer := metrics.NewFunctionTimer(metrics.IamRequestSec, func() []string {
			return []string{getIAMCode(err), args.RoleARN}
		}, nil)
		defer timer.ObserveDuration()

		input := sts.AssumeRoleInput{ //nolint:exhaustruct
			DurationSeconds: aws.Int32(int32(args.SessionTTL.Seconds() * 2)),
			RoleArn:         aws.String(args.RoleARN),
			RoleSessionName: aws.String(sessionName(args.RoleARN, args.RoleSessionName, args.RemoteIP)),
		}

		if args.ExternalID != "" {
			input.ExternalId = aws.String(args.ExternalID)
		}

		if len(args.Tags) > 0 {
			input.Tags = args.Tags
		}

		resp, err := c.svc.AssumeRole(ctx, &input)
		if err != nil {
			return nil, err
		}

		creds := Credentials{
			AccessKeyID:     aws.ToString(resp.Credentials.AccessKeyId),
			Code:            "Success",
			Expiration:      resp.Credentials.Expiration.Format("2006-01-02T15:04:05Z"),
			LastUpdated:     time.Now().Format("2006-01-02T15:04:05Z"),
			SecretAccessKey: aws.ToString(resp.Credentials.SecretAccessKey),
			Token:           aws.ToString(resp.Credentials.SessionToken),
			Type:            "AWS-HMAC",
		}

		return &creds, nil
	})

	if cacheHit {
		metrics.IamCacheHitCount.WithLabelValues(args.RoleARN).Inc()
	}

	if err != nil {
		return nil, err
	}

	return creds, nil
}

func (s *DefaultClient) Endpoint() string {
	if s == nil {
		return ""
	}

	// FIXME: proper endpoint resolver
	return aws.ToString(s.svc.Options().BaseEndpoint)
}

func (s *DefaultClient) RoleARN(role string) string {
	if s == nil {
		return ""
	}

	return RoleARN(s.baseARN, role)
}

func (s *DefaultClient) BaseRoleARN() string {
	if s == nil {
		return ""
	}

	return s.baseARN
}

type Args struct {
	BaseRoleARN   string
	AssumeRoleARN string
}

func New(ctx context.Context, args *Args) (*DefaultClient, error) {
	if args == nil {
		args = &Args{} //nolint:exhaustruct
	}

	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, err
	}

	if args.AssumeRoleARN != "" {
		svc := sts.NewFromConfig(cfg)
		provider := stscreds.NewAssumeRoleProvider(svc, args.AssumeRoleARN)
		cfg.Credentials = aws.NewCredentialsCache(provider)
	}

	svc := sts.NewFromConfig(cfg)

	client := DefaultClient{
		svc:     svc,
		cache:   ccache.New(ccache.Configure[*Credentials]()),
		baseARN: args.BaseRoleARN,
	}

	return &client, nil
}

func cacheFetch[T any](c *ccache.Cache[T], key string, duration time.Duration, fetch func() (T, error)) (value T, cacheHit bool, err error) {
	if c == nil {
		err = errors.New("cache is nil")
		return
	}

	item := c.Get(key)
	if item != nil && !item.Expired() {
		cacheHit = true
		value = item.Value()
		return
	}

	value, err = fetch()
	if err != nil {
		return
	}

	c.Set(key, value, duration)

	return
}

package iam

import (
	"context"
	"fmt"
	"io"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/feature/ec2/imds"
)

func getInstanceMetadata(ctx context.Context, path string) (string, error) {
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return "", err
	}

	client := imds.NewFromConfig(cfg)

	metadataResult, err := client.GetMetadata(ctx, &imds.GetMetadataInput{
		Path: path,
	})
	if err != nil {
		return "", fmt.Errorf("EC2 Metadata [%s] response error, got %v", err, path)
	}
	defer metadataResult.Content.Close()

	instanceId, err := io.ReadAll(metadataResult.Content)
	if err != nil {
		return "", fmt.Errorf("Expect to read content [%s] from bytes, got %v", err, path)
	}

	id := string(instanceId)
	if id == "" {
		return "", fmt.Errorf("EC2 Metadata didn't returned [%s], got empty string", path)
	}

	return id, nil
}

func GetInstanceIAMRole(ctx context.Context) (string, error) {
	return getInstanceMetadata(ctx, "iam/security-credentials/")
}

// Get InstanceId for healthcheck
func GetInstanceId(ctx context.Context) (string, error) {
	return getInstanceMetadata(ctx, "instance-id")
}

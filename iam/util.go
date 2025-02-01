package iam

import (
	"errors"
	"fmt"
	"hash/fnv"
	"strings"

	"github.com/aws/smithy-go"
	"github.com/jtblin/kube2iam/metrics"
)

const (
	maxSessNameLength = 64
)

// Helper to format IAM return codes for metric labeling
//
// https://aws.github.io/aws-sdk-go-v2/docs/handling-errors/#api-error-responses
// All service API response errors implement the smithy.APIError interface type.
// This interface can be used to handle both modeled or un-modeled service error responses
func getIAMCode(err error) string {
	if err != nil {
		var apiErr smithy.APIError
		if errors.As(err, &apiErr) {
			return apiErr.ErrorCode()
		}
		return metrics.IamUnknownFailCode
	}
	return metrics.IamSuccessCode
}

func getHash(text string) string {
	h := fnv.New32a()
	_, err := h.Write([]byte(text))
	if err != nil {
		return text
	}
	return fmt.Sprintf("%x", h.Sum32())
}

func sessionName(roleARN, roleSessionName, remoteIP string) string {
	if roleSessionName != "" {
		return roleSessionName
	}

	idx := strings.LastIndex(roleARN, "/")
	name := fmt.Sprintf("%s-%s", getHash(remoteIP), roleARN[idx+1:])
	return fmt.Sprintf("%.[2]*[1]s", name, maxSessNameLength)
}

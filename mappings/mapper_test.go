package mappings

import (
	"context"
	"fmt"
	"testing"

	"github.com/jtblin/kube2iam/iam"
	v1 "k8s.io/api/core/v1"
)

const (
	defaultBaseRole = "arn:aws:iam::123456789012:role/"
	roleKey         = "roleKey"
	externalIDKey   = "externalIDKey"
	namespaceKey    = "namespaceKey"
)

type mockIamclient struct {
	baseARN string
}

var _ iam.Client = (*mockIamclient)(nil)

func (c *mockIamclient) AssumeRole(
	ctx context.Context, //nolint: unused
	args *iam.AssumeRoleArgs, //nolint: unused
) (*iam.Credentials, error) {
	return nil, nil
}

func (c *mockIamclient) BaseRoleARN() string {
	if c == nil {
		return ""
	}

	return c.baseARN
}

func (c *mockIamclient) Endpoint() string {
	return ""
}

func (c *mockIamclient) RoleARN(role string) string {
	return iam.RoleARN(c.baseARN, role)
}

func TestExtractRoleARN(t *testing.T) {
	var roleExtractionTests = []struct {
		test        string
		annotations map[string]string
		expectedARN string
		expectError bool
	}{
		{ //nolint:exhaustruct
			test:        "No default, no annotation",
			annotations: map[string]string{},
			expectError: true,
		},
		{ //nolint:exhaustruct
			test:        "No default, has annotation",
			annotations: map[string]string{roleKey: "explicit-role"},
			expectedARN: "arn:aws:iam::123456789012:role/explicit-role",
		},
		{ //nolint:exhaustruct
			test:        "Default present, has annotations",
			annotations: map[string]string{roleKey: "something"},
			expectedARN: "arn:aws:iam::123456789012:role/something",
		},
		{ //nolint:exhaustruct
			test:        "Default present, has full arn annotations",
			annotations: map[string]string{roleKey: "arn:aws:iam::999999999999:role/explicit-arn"},
			expectedARN: "arn:aws:iam::999999999999:role/explicit-arn",
		},
		{ //nolint:exhaustruct
			test:        "Default present, has annotations, has externalID",
			annotations: map[string]string{roleKey: "something", externalIDKey: "externalID"},
			expectedARN: "arn:aws:iam::123456789012:role/something",
		},
	}
	for _, tt := range roleExtractionTests {
		t.Run(tt.test, func(t *testing.T) {
			rp := RoleMapper{} //nolint:exhaustruct
			rp.iamRoleKey = "roleKey"
			rp.iamExternalIDKey = "externalIDKey"
			rp.iam = &mockIamclient{baseARN: defaultBaseRole}

			pod := &v1.Pod{} //nolint:exhaustruct
			pod.Annotations = tt.annotations

			resp, err := rp.extractRoleARN(pod)
			if tt.expectError && err == nil {
				t.Error("Expected error however didn't recieve one")
				return
			}
			if !tt.expectError && err != nil {
				t.Errorf("Didn't expect error but recieved %s", err)
				return
			}
			if resp != tt.expectedARN {
				t.Errorf("Response [%s] did not equal expected [%s]", resp, tt.expectedARN)
				return
			}
		})
	}
}

func TestCheckRoleForNamespace(t *testing.T) {
	var roleCheckTests = []struct {
		test                       string
		namespaceRestriction       bool
		namespace                  string
		namespaceAnnotations       map[string]string
		roleARN                    string
		externalID                 string
		namespaceRestrictionFormat string
		expectedResult             bool
	}{
		{ //nolint:exhaustruct
			test:                 "No restrictions",
			namespaceRestriction: false,
			roleARN:              "arn:aws:iam::123456789012:role/explicit-role",
			namespace:            "default",
			expectedResult:       true,
		},
		// glob restrictions
		{ //nolint:exhaustruct
			test:                       "Restrictions enabled, partial arn in annotation",
			namespaceRestriction:       true,
			roleARN:                    "arn:aws:iam::123456789012:role/explicit-role",
			namespace:                  "default",
			namespaceAnnotations:       map[string]string{namespaceKey: "[\"explicit-role\"]"},
			namespaceRestrictionFormat: "glob",
			expectedResult:             true,
		},
		{ //nolint:exhaustruct
			test:                       "Restrictions enabled, partial glob in annotation",
			namespaceRestriction:       true,
			roleARN:                    "arn:aws:iam::123456789012:role/path/explicit-role",
			namespace:                  "default",
			namespaceAnnotations:       map[string]string{namespaceKey: "[\"path/*\"]"},
			namespaceRestrictionFormat: "glob",
			expectedResult:             true,
		},
		{ //nolint:exhaustruct
			test:                       "Restrictions enabled, full arn in annotation",
			namespaceRestriction:       true,
			roleARN:                    "arn:aws:iam::123456789012:role/explicit-role",
			namespace:                  "default",
			namespaceAnnotations:       map[string]string{namespaceKey: "[\"arn:aws:iam::123456789012:role/explicit-role\"]"},
			namespaceRestrictionFormat: "glob",
			expectedResult:             true,
		},
		{ //nolint:exhaustruct
			test:                       "Restrictions enabled, full arn with glob in annotation",
			namespaceRestriction:       true,
			roleARN:                    "arn:aws:iam::123456789012:role/path/explicit-role",
			namespace:                  "default",
			namespaceAnnotations:       map[string]string{namespaceKey: "[\"arn:aws:iam::123456789012:role/path/*-role\"]"},
			namespaceRestrictionFormat: "glob",
			expectedResult:             true,
		},
		{ //nolint:exhaustruct
			test:                       "Restrictions enabled, full arn not in annotation",
			namespaceRestriction:       true,
			roleARN:                    "arn:aws:iam::123456789012:role/test-role",
			namespace:                  "default",
			namespaceAnnotations:       map[string]string{namespaceKey: "[\"arn:aws:iam::123456789012:role/explicit-role\"]"},
			namespaceRestrictionFormat: "glob",
			expectedResult:             false,
		},
		{ //nolint:exhaustruct
			test:                       "Restrictions enabled, no annotations",
			namespaceRestriction:       true,
			roleARN:                    "arn:aws:iam::123456789012:role/explicit-role",
			namespace:                  "default",
			namespaceAnnotations:       map[string]string{namespaceKey: ""},
			namespaceRestrictionFormat: "glob",
			expectedResult:             false,
		},
		{ //nolint:exhaustruct
			test:                       "Restrictions enabled, multiple annotations, no match",
			namespaceRestriction:       true,
			roleARN:                    "arn:aws:iam::123456789012:role/test-role",
			namespace:                  "default",
			namespaceAnnotations:       map[string]string{namespaceKey: "[\"explicit-role\", \"explicit-role2\"]"},
			namespaceRestrictionFormat: "glob",
			expectedResult:             false,
		},
		{ //nolint:exhaustruct
			test:                       "Restrictions enabled, multiple annotations, matches exact 1st",
			namespaceRestriction:       true,
			roleARN:                    "arn:aws:iam::123456789012:role/explicit-role",
			namespace:                  "default",
			namespaceAnnotations:       map[string]string{namespaceKey: "[\"explicit-role\", \"explicit-role2\"]"},
			namespaceRestrictionFormat: "glob",
			expectedResult:             true,
		},
		{ //nolint:exhaustruct
			test:                       "Restrictions enabled, multiple annotations, matches exact 2nd",
			namespaceRestriction:       true,
			roleARN:                    "arn:aws:iam::123456789012:role/explicit-role",
			namespace:                  "default",
			namespaceAnnotations:       map[string]string{namespaceKey: "[\"explicit-role2\", \"explicit-role\"]"},
			namespaceRestrictionFormat: "glob",
			expectedResult:             true,
		},
		{ //nolint:exhaustruct
			test:                       "Restrictions enabled, multiple annotations, matches glob 1st",
			namespaceRestriction:       true,
			roleARN:                    "arn:aws:iam::123456789012:role/glob-role",
			namespace:                  "default",
			namespaceAnnotations:       map[string]string{namespaceKey: "[\"glob-*\", \"explicit-role\"]"},
			namespaceRestrictionFormat: "glob",
			expectedResult:             true,
		},
		{ //nolint:exhaustruct
			test:                       "Restrictions enabled, multiple annotations, matches glob 2nd",
			namespaceRestriction:       true,
			roleARN:                    "arn:aws:iam::123456789012:role/glob-role",
			namespace:                  "default",
			namespaceAnnotations:       map[string]string{namespaceKey: "[\"explicit-role\", \"glob-*\"]"},
			namespaceRestrictionFormat: "glob",
			expectedResult:             true,
		},
		// regexp restrictions
		{ //nolint:exhaustruct
			test:                       "Restrictions enabled (regexp), partial arn in annotation",
			namespaceRestriction:       true,
			roleARN:                    "arn:aws:iam::123456789012:role/explicit-role",
			namespace:                  "default",
			namespaceAnnotations:       map[string]string{namespaceKey: "[\"explicit-role\"]"},
			namespaceRestrictionFormat: "regexp",
			expectedResult:             true,
		},
		{ //nolint:exhaustruct
			test:                       "Restrictions enabled (regexp), partial regexp in annotation",
			namespaceRestriction:       true,
			roleARN:                    "arn:aws:iam::123456789012:role/path/explicit-role",
			namespace:                  "default",
			namespaceAnnotations:       map[string]string{namespaceKey: "[\"path/.*\"]"},
			namespaceRestrictionFormat: "regexp",
			expectedResult:             true,
		},
		{ //nolint:exhaustruct
			test:                       "Restrictions enabled (regexp), full arn in annotation",
			namespaceRestriction:       true,
			roleARN:                    "arn:aws:iam::123456789012:role/explicit-role",
			namespace:                  "default",
			namespaceAnnotations:       map[string]string{namespaceKey: "[\"arn:aws:iam::123456789012:role/explicit-role\"]"},
			namespaceRestrictionFormat: "regexp",
			expectedResult:             true,
		},
		{ //nolint:exhaustruct
			test:                       "Restrictions enabled (regexp), full arn with regexp in annotation",
			namespaceRestriction:       true,
			roleARN:                    "arn:aws:iam::123456789012:role/path/explicit-role",
			namespace:                  "default",
			namespaceAnnotations:       map[string]string{namespaceKey: "[\"arn:aws:iam::123456789012:role/path/.*-role\"]"},
			namespaceRestrictionFormat: "regexp",
			expectedResult:             true,
		},
		{ //nolint:exhaustruct
			test:                       "Restrictions enabled (regexp), full arn not in annotation",
			namespaceRestriction:       true,
			roleARN:                    "arn:aws:iam::123456789012:role/test-role",
			namespace:                  "default",
			namespaceAnnotations:       map[string]string{namespaceKey: "[\"arn:aws:iam::123456789012:role/explicit-role\"]"},
			namespaceRestrictionFormat: "regexp",
			expectedResult:             false,
		},
		{ //nolint:exhaustruct
			test:                       "Restrictions enabled (regexp), no annotations",
			namespaceRestriction:       true,
			roleARN:                    "arn:aws:iam::123456789012:role/explicit-role",
			namespace:                  "default",
			namespaceAnnotations:       map[string]string{namespaceKey: ""},
			namespaceRestrictionFormat: "regexp",
			expectedResult:             false,
		},
		{ //nolint:exhaustruct
			test:                       "Restrictions enabled (regexp), multiple annotations, no match",
			namespaceRestriction:       true,
			roleARN:                    "arn:aws:iam::123456789012:role/test-role",
			namespace:                  "default",
			namespaceAnnotations:       map[string]string{namespaceKey: "[\"explicit-role\", \"explicit-role2\"]"},
			namespaceRestrictionFormat: "regexp",
			expectedResult:             false,
		},
		{ //nolint:exhaustruct
			test:                       "Restrictions enabled (regexp), multiple annotations, matches exact 1st",
			namespaceRestriction:       true,
			roleARN:                    "arn:aws:iam::123456789012:role/explicit-role",
			namespace:                  "default",
			namespaceAnnotations:       map[string]string{namespaceKey: "[\"explicit-role\", \"explicit-role2\"]"},
			namespaceRestrictionFormat: "regexp",
			expectedResult:             true,
		},
		{ //nolint:exhaustruct
			test:                       "Restrictions enabled (regexp), multiple annotations, matches exact 2nd",
			namespaceRestriction:       true,
			roleARN:                    "arn:aws:iam::123456789012:role/explicit-role",
			namespace:                  "default",
			namespaceAnnotations:       map[string]string{namespaceKey: "[\"explicit-role2\", \"explicit-role\"]"},
			namespaceRestrictionFormat: "regexp",
			expectedResult:             true,
		},
		{ //nolint:exhaustruct
			test:                       "Restrictions enabled (regexp), multiple annotations, matches regexp 1st",
			namespaceRestriction:       true,
			roleARN:                    "arn:aws:iam::123456789012:role/glob-role",
			namespace:                  "default",
			namespaceAnnotations:       map[string]string{namespaceKey: "[\"glob-.*\", \"explicit-role\"]"},
			namespaceRestrictionFormat: "regexp",
			expectedResult:             true,
		},
		{ //nolint:exhaustruct
			test:                       "Restrictions enabled (regexp), multiple annotations, matches regexp 2nd",
			namespaceRestriction:       true,
			roleARN:                    "arn:aws:iam::123456789012:role/glob-role",
			namespace:                  "default",
			namespaceAnnotations:       map[string]string{namespaceKey: "[\"explicit-role\", \"glob-.*\"]"},
			namespaceRestrictionFormat: "regexp",
			expectedResult:             true,
		},
	}

	for _, tt := range roleCheckTests {
		t.Run(tt.test, func(t *testing.T) {
			rp := New(&RoleMapperArgs{
				RoleKey:              roleKey,
				RoleSessionNameKey:   "",
				ExternalIDKey:        externalIDKey,
				NamespaceRestriction: tt.namespaceRestriction,
				NamespaceKey:         namespaceKey,
				IamInstance:          &mockIamclient{baseARN: defaultBaseRole},
				KubeStore: &storeMock{
					namespace:   tt.namespace,
					annotations: tt.namespaceAnnotations,
				},
				NamespaceRestrictionFormat: tt.namespaceRestrictionFormat,
			})

			resp := rp.checkRoleForNamespace(tt.roleARN, tt.namespace)
			if resp != tt.expectedResult {
				t.Errorf("Expected [%t] for test but recieved [%t]", tt.expectedResult, resp)
			}
		})
	}
}

type storeMock struct {
	namespace   string
	annotations map[string]string
}

func (k *storeMock) ListPodIPs() []string {
	return nil
}
func (k *storeMock) PodByIP(context.Context, string) (*v1.Pod, error) {
	return nil, nil
}
func (k *storeMock) ListNamespaces() []string {
	return nil
}
func (k *storeMock) NamespaceByName(ns string) (*v1.Namespace, error) {
	if ns == k.namespace {
		nns := &v1.Namespace{} //nolint:exhaustruct
		nns.Name = k.namespace
		nns.Annotations = k.annotations
		return nns, nil
	}
	return nil, fmt.Errorf("namespace isn't present")
}

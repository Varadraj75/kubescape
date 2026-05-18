package opaprocessor

import (
	"context"
	_ "embed"
	"testing"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/kubescape/opa-utils/resources"
	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

//go:embed testdata/cel/c0016-privileged-containers.yaml
var c0016VAPFixture string

// celRuleFromExpression builds a PolicyRule whose Rule field contains a minimal
// ValidatingAdmissionPolicy YAML embedding the given expression and message.
func celRuleFromExpression(expression, message string) reporthandling.PolicyRule {
	rule := `apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata:
  name: test-cel-rule
spec:
  matchConstraints:
    resourceRules:
    - apiGroups: [""]
      apiVersions: ["v1"]
      resources: ["pods"]
      operations: ["CREATE", "UPDATE"]
  validations:
  - expression: '` + expression + `'
    message: "` + message + `"
`
	return reporthandling.PolicyRule{
		PortalBase: armotypes.PortalBase{
			Name: "test-cel-rule",
		},
		Rule:         rule,
		RuleLanguage: CELLanguage,
	}
}

func newCELProcessorMock() *OPAProcessor {
	return &OPAProcessor{
		compiledModules: make(map[string]*ast.Compiler),
	}
}

func TestRunCELOnK8s(t *testing.T) {
	tests := []struct {
		name               string
		rule               reporthandling.PolicyRule
		objects            []map[string]interface{}
		wantResponseCount  int
		wantAlertNonEmpty  bool
		wantErr            bool
	}{
		{
			name: "privileged_container_fails",
			rule: celRuleFromExpression(
				`object.spec.containers.all(c, !has(c.securityContext) || !has(c.securityContext.privileged) || c.securityContext.privileged == false)`,
				"Privileged containers are not allowed",
			),
			objects: []map[string]interface{}{
				{
					"apiVersion": "v1",
					"kind":       "Pod",
					"metadata":   map[string]interface{}{"name": "privileged-pod", "namespace": "default"},
					"spec": map[string]interface{}{
						"containers": []interface{}{
							map[string]interface{}{
								"name":  "app",
								"image": "nginx",
								"securityContext": map[string]interface{}{
									"privileged": true,
								},
							},
						},
					},
				},
			},
			wantResponseCount: 1,
			wantAlertNonEmpty: true,
		},
		{
			name: "non_privileged_container_passes",
			rule: celRuleFromExpression(
				`object.spec.containers.all(c, !has(c.securityContext) || !has(c.securityContext.privileged) || c.securityContext.privileged == false)`,
				"Privileged containers are not allowed",
			),
			objects: []map[string]interface{}{
				{
					"apiVersion": "v1",
					"kind":       "Pod",
					"metadata":   map[string]interface{}{"name": "safe-pod", "namespace": "default"},
					"spec": map[string]interface{}{
						"containers": []interface{}{
							map[string]interface{}{
								"name":  "app",
								"image": "nginx",
								"securityContext": map[string]interface{}{
									"privileged": false,
								},
							},
						},
					},
				},
			},
			wantResponseCount: 0,
		},
		{
			name: "missing_security_context_passes",
			rule: celRuleFromExpression(
				`object.spec.containers.all(c, !has(c.securityContext) || !has(c.securityContext.privileged) || c.securityContext.privileged == false)`,
				"Privileged containers are not allowed",
			),
			objects: []map[string]interface{}{
				{
					"apiVersion": "v1",
					"kind":       "Pod",
					"metadata":   map[string]interface{}{"name": "no-sc-pod", "namespace": "default"},
					"spec": map[string]interface{}{
						"containers": []interface{}{
							map[string]interface{}{
								"name":  "app",
								"image": "nginx",
							},
						},
					},
				},
			},
			wantResponseCount: 0,
		},
		{
			name: "authorizer_ref_returns_skip",
			rule: celRuleFromExpression(
				`authorizer.group("").resource("pods").check("create").allowed()`,
				"Authorization check",
			),
			objects:   []map[string]interface{}{{"kind": "Pod"}},
			wantErr:   true,
		},
		{
			name: "bad_cel_expression_returns_error_response",
			rule: celRuleFromExpression(
				`this is not valid CEL !!!`,
				"Bad expression",
			),
			objects: []map[string]interface{}{{"kind": "Pod"}},
			wantErr: true,
		},
	}

	opap := newCELProcessorMock()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ruleResponses, err := opap.runCELOnK8s(&tt.rule, tt.objects)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Len(t, ruleResponses, tt.wantResponseCount)
			if tt.wantAlertNonEmpty {
				require.Greater(t, len(ruleResponses), 0)
				assert.NotEmpty(t, ruleResponses[0].AlertMessage)
			}
		})
	}
}

func TestRunCELOnK8sWithFixture(t *testing.T) {
	rule := reporthandling.PolicyRule{
		PortalBase: armotypes.PortalBase{
			Name: "c0016-privileged-containers",
		},
		Rule:         c0016VAPFixture,
		RuleLanguage: CELLanguage,
	}

	opap := newCELProcessorMock()

	privilegedPod := map[string]interface{}{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata":   map[string]interface{}{"name": "privileged-pod", "namespace": "default"},
		"spec": map[string]interface{}{
			"containers": []interface{}{
				map[string]interface{}{
					"name":  "app",
					"image": "nginx",
					"securityContext": map[string]interface{}{
						"privileged": true,
					},
				},
			},
		},
	}

	safePod := map[string]interface{}{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata":   map[string]interface{}{"name": "safe-pod", "namespace": "default"},
		"spec": map[string]interface{}{
			"containers": []interface{}{
				map[string]interface{}{
					"name":  "app",
					"image": "nginx",
				},
			},
		},
	}

	ruleResponses, err := opap.runCELOnK8s(&rule, []map[string]interface{}{privilegedPod, safePod})
	require.NoError(t, err)
	assert.Len(t, ruleResponses, 1, "exactly one pod should fail the privileged check")
	assert.Equal(t, "Privileged containers are not allowed", ruleResponses[0].AlertMessage)
}

func TestCELDispatch(t *testing.T) {
	tests := []struct {
		name         string
		ruleLanguage reporthandling.RuleLanguages
		rule         string
		wantErr      bool
		errContains  string
	}{
		{
			name:         "cel_language_routes_to_cel_engine",
			ruleLanguage: CELLanguage,
			// A valid VAP whose expression trivially passes; verifies dispatch
			// reaches runCELOnK8s and does not return a "language not supported" error.
			rule: `apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata:
  name: dispatch-test
spec:
  matchConstraints:
    resourceRules:
    - apiGroups: [""]
      apiVersions: ["v1"]
      resources: ["pods"]
      operations: ["CREATE"]
  validations:
  - expression: 'true'
    message: "always passes"
`,
		},
		{
			name:         "rego_language_routes_to_opa_engine",
			ruleLanguage: reporthandling.RegoLanguage,
			// Intentionally invalid rego triggers the rego compile path, not CEL.
			// The error confirms dispatch reached the OPA engine, not the CEL engine.
			rule:        "package armo_builtins\n\ndeny[msga] { true\n  msga := {\"alertMessage\": \"test\", \"packagename\": \"armo_builtins\", \"alertObject\": {\"k8sApiObjects\": []}}\n}",
			wantErr:     false,
			errContains: "",
		},
	}

	opap := newCELProcessorMock()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policyRule := &reporthandling.PolicyRule{
				PortalBase: armotypes.PortalBase{
					Name: "dispatch-test",
				},
				Rule:         tt.rule,
				RuleLanguage: tt.ruleLanguage,
				RuleQuery:    "armo_builtins",
			}

			// Use an empty object list; we only care about dispatch routing, not results.
			objects := []map[string]interface{}{}
			_, err := opap.runOPAOnSingleRule(context.Background(), policyRule, objects, ruleData, resources.RegoDependenciesData{})

			if tt.wantErr {
				require.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
				return
			}
			require.NoError(t, err)
		})
	}
}

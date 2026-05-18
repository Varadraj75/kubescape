// Package opaprocessor evaluates OPA and CEL security rules against Kubernetes objects
package opaprocessor

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/google/cel-go/cel"
	"github.com/kubescape/opa-utils/reporthandling"
	admissionv1 "k8s.io/api/admissionregistration/v1"
	"k8s.io/apimachinery/pkg/util/yaml"
)

// CELLanguage identifies rules whose body is a ValidatingAdmissionPolicy YAML.
// It extends the RuleLanguages type defined in opa-utils without modifying
// the upstream package.
const CELLanguage reporthandling.RuleLanguages = "cel"

// runCELOnK8s evaluates a CEL-based PolicyRule against a batch of Kubernetes objects.
//
// The rule's Rule field must contain the YAML of a ValidatingAdmissionPolicy.
// Every validation entry in spec.validations is compiled once and evaluated for
// each object; an object that causes any expression to return false is reported
// as a failed resource.
func (opap *OPAProcessor) runCELOnK8s(rule *reporthandling.PolicyRule, k8sObjects []map[string]interface{}) ([]reporthandling.RuleResponse, error) {
	var vap admissionv1.ValidatingAdmissionPolicy
	if err := yaml.NewYAMLOrJSONDecoder(strings.NewReader(rule.Rule), 4096).Decode(&vap); err != nil {
		return nil, fmt.Errorf("rule '%s': failed to decode VAP YAML: %w", rule.Name, err)
	}

	if len(vap.Spec.Validations) == 0 {
		return nil, fmt.Errorf("rule '%s': ValidatingAdmissionPolicy contains no validations", rule.Name)
	}

	// Build the CEL environment once; object is bound as map(string, dyn) which
	// matches the unstructured representation Kubescape already works with.
	env, err := cel.NewEnv(
		cel.Variable("object", cel.MapType(cel.StringType, cel.DynType)),
	)
	if err != nil {
		return nil, fmt.Errorf("rule '%s': failed to create CEL environment: %w", rule.Name, err)
	}

	type compiledValidation struct {
		prg     cel.Program
		message string
	}

	compiled := make([]compiledValidation, 0, len(vap.Spec.Validations))
	for _, v := range vap.Spec.Validations {
		// Expressions that reference authorizer or request.userInfo cannot be
		// evaluated offline. Surface a clear error rather than silently passing
		// or failing; the rule should be deployed as a live VAP for enforcement.
		if strings.Contains(v.Expression, "authorizer.") || strings.Contains(v.Expression, "request.userInfo") {
			return nil, fmt.Errorf("rule '%s': CEL expression references authorizer or request.userInfo — offline evaluation not supported; deploy as VAP for full enforcement", rule.Name)
		}

		ast, issues := env.Compile(v.Expression)
		if issues != nil && issues.Err() != nil {
			return nil, fmt.Errorf("rule '%s': failed to compile CEL expression: %w", rule.Name, issues.Err())
		}
		prg, err := env.Program(ast)
		if err != nil {
			return nil, fmt.Errorf("rule '%s': failed to build CEL program: %w", rule.Name, err)
		}

		msg := v.Message
		if msg == "" {
			msg = fmt.Sprintf("failed rule: %s", rule.Name)
		}
		compiled = append(compiled, compiledValidation{prg: prg, message: msg})
	}

	var ruleResponses []reporthandling.RuleResponse
	for _, obj := range k8sObjects {
		activation := map[string]any{"object": obj}

		for _, cv := range compiled {
			out, _, err := cv.prg.Eval(activation)
			if err != nil {
				// Runtime error: treat as a failure so the object is not
				// silently passed. The alert message carries the error detail.
				raw, _ := json.Marshal(obj)
				ruleResponses = append(ruleResponses, reporthandling.RuleResponse{
					AlertMessage: fmt.Sprintf("CEL runtime error for rule '%s': %s", rule.Name, err.Error()),
					AlertObject: reporthandling.AlertObject{
						K8SApiObjects: []map[string]interface{}{obj},
					},
					RuleStatus: string(raw),
				})
				break
			}

			passed, ok := out.Value().(bool)
			if !ok || !passed {
				ruleResponses = append(ruleResponses, reporthandling.RuleResponse{
					AlertMessage: cv.message,
					AlertObject: reporthandling.AlertObject{
						K8SApiObjects: []map[string]interface{}{obj},
					},
				})
				break
			}
		}
	}

	return ruleResponses, nil
}

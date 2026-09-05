package filter

import (
	"testing"

	"github.com/akozadaev/guardian/internal/models"
)

func TestEngineBlockByIPAndMethod(t *testing.T) {
	e := NewEngine()
	rule := models.Rule{
		Name:     "block",
		Priority: 100,
		Enabled:  true,
		Action:   models.ActionBlock,
		Response: &models.RuleResponse{Status: 403, Body: "denied"},
		Conditions: models.ConditionNode{
			Operator: models.OpAND,
			Rules: []models.ConditionNode{
				{Field: "ip", Op: models.FieldIn, Value: []byte(`["1.2.3.4"]`)},
				{Field: "method", Op: models.FieldIn, Value: []byte(`["POST","PUT"]`)},
			},
		},
	}
	e.SetRules([]models.Rule{rule})

	res := e.Evaluate(&models.RequestContext{IP: "1.2.3.4", Method: "POST"})
	if !res.Matched || res.Action != models.ActionBlock {
		t.Fatalf("expected block, got %+v", res)
	}

	res = e.Evaluate(&models.RequestContext{IP: "1.2.3.4", Method: "GET"})
	if res.Matched {
		t.Fatalf("expected allow for GET")
	}
}

func TestValidateRejectsEmptyAND(t *testing.T) {
	err := ValidateRule(&models.Rule{
		Name:   "bad",
		Action: models.ActionBlock,
		Conditions: models.ConditionNode{
			Operator: models.OpAND,
			Rules:    nil,
		},
	})
	if err == nil {
		t.Fatal("expected validation error")
	}
}

func TestEngineEmptyANDDoesNotMatch(t *testing.T) {
	e := NewEngine()
	e.SetRules([]models.Rule{{
		Name:       "empty",
		Enabled:    true,
		Action:     models.ActionBlock,
		Conditions: models.ConditionNode{Operator: models.OpAND},
		Response:   &models.RuleResponse{Status: 403, Body: "x"},
	}})
	res := e.Evaluate(&models.RequestContext{Method: "GET"})
	if res.Matched {
		t.Fatal("empty AND must not match")
	}
}

func TestEngineRegexPath(t *testing.T) {
	e := NewEngine()
	e.SetRules([]models.Rule{{
		Name:     "admin",
		Priority: 10,
		Enabled:  true,
		Action:   models.ActionBlock,
		Conditions: models.ConditionNode{
			Field: "path", Op: models.FieldRegex, Value: []byte(`"^/admin/.*"`),
		},
		Response: &models.RuleResponse{Status: 403, Body: "no"},
	}})
	res := e.Evaluate(&models.RequestContext{Path: "/admin/users"})
	if !res.Matched {
		t.Fatal("expected match")
	}
}

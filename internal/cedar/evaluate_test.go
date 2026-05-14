package cedar

import (
	"slices"
	"testing"

	"github.com/bensyverson/kura/internal/identity"
	"github.com/bensyverson/kura/internal/pii"
)

func testEvaluator(t *testing.T) *Evaluator {
	t.Helper()
	e, err := NewEvaluator(DefaultPolicy(testManifest(t)))
	if err != nil {
		t.Fatalf("NewEvaluator: %v", err)
	}
	return e
}

func principal(id string) identity.Principal {
	return identity.Principal{Type: identity.PrincipalUser, ID: id, Email: id, Domain: "client.com"}
}

func contains(cs []pii.Category, want pii.Category) bool {
	return slices.Contains(cs, want)
}

func TestEvaluatorAllowsByRole(t *testing.T) {
	e := testEvaluator(t)

	d, err := e.Decide(Request{Principal: principal("a@client.com"), Roles: []string{"admin"}, Action: ActionCreate, Entity: "customer", ResourceID: "c1"})
	if err != nil {
		t.Fatal(err)
	}
	if !d.Allowed {
		t.Error("admin should be allowed to create a customer")
	}

	d, _ = e.Decide(Request{Principal: principal("b@client.com"), Roles: []string{"auditor"}, Action: ActionCreate, Entity: "customer", ResourceID: "c1"})
	if d.Allowed {
		t.Error("auditor should not be allowed to create a customer")
	}

	d, _ = e.Decide(Request{Principal: principal("b@client.com"), Roles: []string{"auditor"}, Action: ActionRead, Entity: "customer", ResourceID: "c1"})
	if !d.Allowed {
		t.Error("auditor should be allowed to read a customer")
	}
}

func TestEvaluatorDeniesPrincipalWithNoRole(t *testing.T) {
	e := testEvaluator(t)
	d, err := e.Decide(Request{Principal: principal("nobody@client.com"), Action: ActionRead, Entity: "customer", ResourceID: "c1"})
	if err != nil {
		t.Fatal(err)
	}
	if d.Allowed {
		t.Error("a principal holding no role must be denied")
	}
}

// WF5: the evaluator decides visibility per detected PII category — keyed
// on the category, never on a column name. The request carries detected
// categories; nothing about column names enters the decision.
func TestEvaluatorDecidesPIIByCategory(t *testing.T) {
	e := testEvaluator(t)
	detected := []pii.Category{pii.CategoryEmail, pii.CategoryAccountNumber}

	d, err := e.Decide(Request{Principal: principal("a@client.com"), Roles: []string{"admin"}, Action: ActionRead, Entity: "customer", ResourceID: "c1", DetectedPII: detected})
	if err != nil {
		t.Fatal(err)
	}
	if len(d.VisibleCategories) != 2 || len(d.MaskedCategories) != 0 {
		t.Errorf("admin: want all visible, got visible=%v masked=%v", d.VisibleCategories, d.MaskedCategories)
	}

	d, _ = e.Decide(Request{Principal: principal("u@client.com"), Roles: []string{"user"}, Action: ActionRead, Entity: "customer", ResourceID: "c1", DetectedPII: detected})
	if !contains(d.VisibleCategories, pii.CategoryEmail) {
		t.Errorf("user should see private_email, visible=%v", d.VisibleCategories)
	}
	if !contains(d.MaskedCategories, pii.CategoryAccountNumber) {
		t.Errorf("user should have account_number masked, masked=%v", d.MaskedCategories)
	}

	d, _ = e.Decide(Request{Principal: principal("x@client.com"), Roles: []string{"auditor"}, Action: ActionRead, Entity: "customer", ResourceID: "c1", DetectedPII: detected})
	if !d.Allowed {
		t.Fatal("auditor should be allowed to read")
	}
	if len(d.VisibleCategories) != 0 || len(d.MaskedCategories) != 2 {
		t.Errorf("auditor: want all masked, got visible=%v masked=%v", d.VisibleCategories, d.MaskedCategories)
	}
}

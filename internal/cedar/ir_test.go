package cedar

import (
	"strings"
	"testing"

	"github.com/bensyverson/kura/internal/manifest"
	"github.com/bensyverson/kura/internal/pii"
)

func testManifest(t *testing.T) *manifest.Manifest {
	t.Helper()
	m, err := manifest.ParseFile("../manifest/testdata/valid.json")
	if err != nil {
		t.Fatalf("load test manifest: %v", err)
	}
	return m
}

func TestActionValid(t *testing.T) {
	for _, a := range AllActions() {
		if !a.Valid() {
			t.Errorf("%q should be a valid action", a)
		}
	}
	for _, a := range []Action{"", "READ", "purge"} {
		if a.Valid() {
			t.Errorf("%q should not be a valid action", a)
		}
	}
}

// N2d: the default three-role model is expressible in the IR.
func TestDefaultPolicyHasThreeRoles(t *testing.T) {
	p := DefaultPolicy(testManifest(t))
	want := map[string]bool{"admin": false, "user": false, "auditor": false}
	for _, r := range p.Roles {
		if _, ok := want[r.Name]; !ok {
			t.Errorf("unexpected role %q", r.Name)
		}
		want[r.Name] = true
	}
	for name, found := range want {
		if !found {
			t.Errorf("default policy is missing the %q role", name)
		}
	}
}

// ScS: the IR's axes (roles x entities x PII-categories x actions) come
// from the manifest, and the IR validates against it.
func TestDefaultPolicyValidatesAgainstManifest(t *testing.T) {
	m := testManifest(t)
	p := DefaultPolicy(m)
	if err := p.ValidateAgainst(m); err != nil {
		t.Fatalf("default policy should validate against its own manifest: %v", err)
	}
	for _, g := range p.Grants {
		if _, ok := m.Entity(g.Entity); !ok {
			t.Errorf("grant references entity %q absent from the manifest", g.Entity)
		}
	}
	for _, e := range m.Entities {
		covered := false
		for _, g := range p.Grants {
			if g.Entity == e.Name {
				covered = true
				break
			}
		}
		if !covered {
			t.Errorf("default policy does not cover manifest entity %q", e.Name)
		}
	}
}

func TestPolicyValidationCatchesBadReferences(t *testing.T) {
	m := testManifest(t)

	good := &Policy{
		Roles:  []Role{{Name: "user"}},
		Grants: []Grant{{Role: "user", Entity: "customer", Action: ActionRead}},
	}
	if err := good.ValidateAgainst(m); err != nil {
		t.Fatalf("base policy should be valid: %v", err)
	}

	bad := map[string]*Policy{
		"unknown role": {
			Roles:  []Role{{Name: "user"}},
			Grants: []Grant{{Role: "ghost", Entity: "customer", Action: ActionRead}},
		},
		"unknown entity": {
			Roles:  []Role{{Name: "user"}},
			Grants: []Grant{{Role: "user", Entity: "ghost", Action: ActionRead}},
		},
		"invalid action": {
			Roles:  []Role{{Name: "user"}},
			Grants: []Grant{{Role: "user", Entity: "customer", Action: "purge"}},
		},
		"invalid pii category": {
			Roles:  []Role{{Name: "user"}},
			Grants: []Grant{{Role: "user", Entity: "customer", Action: ActionRead, VisiblePII: []pii.Category{"ssn"}}},
		},
		"visible pii on a write action": {
			Roles:  []Role{{Name: "user"}},
			Grants: []Grant{{Role: "user", Entity: "customer", Action: ActionUpdate, VisiblePII: []pii.Category{pii.CategoryEmail}}},
		},
		"duplicate role": {
			Roles:  []Role{{Name: "user"}, {Name: "user"}},
			Grants: nil,
		},
		"empty role name": {
			Roles:  []Role{{Name: ""}},
			Grants: nil,
		},
	}
	for name, p := range bad {
		if err := p.ValidateAgainst(m); err == nil {
			t.Errorf("%s: expected a validation error, got nil", name)
		}
	}
}

// An append-only entity (order, per the test manifest) is insert-only:
// a policy granting update or delete on it is rejected with a matchable
// error, while create/read/list stay grantable and update/delete on a
// non-append-only entity remain fine.
func TestAppendOnlyRejectsUpdateDeleteGrants(t *testing.T) {
	m := testManifest(t) // order is append_only

	for _, a := range []Action{ActionUpdate, ActionDelete} {
		p := &Policy{
			Roles:  []Role{{Name: "admin"}},
			Grants: []Grant{{Role: "admin", Entity: "order", Action: a}},
		}
		err := p.ValidateAgainst(m)
		if err == nil {
			t.Errorf("granting %q on append-only entity should be rejected", a)
			continue
		}
		if !strings.Contains(err.Error(), "append-only") ||
			!strings.Contains(err.Error(), "order") ||
			!strings.Contains(err.Error(), string(a)) {
			t.Errorf("error should name the append-only entity and action %q: %v", a, err)
		}
	}

	for _, a := range []Action{ActionCreate, ActionRead, ActionList} {
		p := &Policy{
			Roles:  []Role{{Name: "admin"}},
			Grants: []Grant{{Role: "admin", Entity: "order", Action: a}},
		}
		if err := p.ValidateAgainst(m); err != nil {
			t.Errorf("granting %q on append-only entity should be allowed: %v", a, err)
		}
	}

	// update/delete on a non-append-only entity remain valid.
	p := &Policy{
		Roles:  []Role{{Name: "admin"}},
		Grants: []Grant{{Role: "admin", Entity: "customer", Action: ActionUpdate}},
	}
	if err := p.ValidateAgainst(m); err != nil {
		t.Errorf("update on non-append-only entity should be allowed: %v", err)
	}
}

// DefaultPolicy never emits update/delete grants for an append-only
// entity; create/read/list remain, and non-append-only entities keep the
// full action set.
func TestDefaultPolicyOmitsMutationForAppendOnly(t *testing.T) {
	m := testManifest(t)
	p := DefaultPolicy(m)

	can := func(role, entity string, a Action) bool {
		for _, g := range p.Grants {
			if g.Role == role && g.Entity == entity && g.Action == a {
				return true
			}
		}
		return false
	}

	for _, role := range []string{"admin", "user"} {
		if can(role, "order", ActionUpdate) {
			t.Errorf("%s should not have update on append-only order", role)
		}
		if can(role, "order", ActionDelete) {
			t.Errorf("%s should not have delete on append-only order", role)
		}
		if !can(role, "order", ActionCreate) {
			t.Errorf("%s should still have create on append-only order", role)
		}
		if !can(role, "order", ActionRead) {
			t.Errorf("%s should still have read on append-only order", role)
		}
	}

	// A non-append-only entity keeps the full mutation set.
	if !can("admin", "customer", ActionUpdate) || !can("admin", "customer", ActionDelete) {
		t.Error("admin should retain update/delete on non-append-only customer")
	}
}

// ForRoles projects a policy to the effective policy a principal holding
// the named roles actually has: only those role definitions, and only the
// grants attached to them — the union of the roles' permissions.
func TestForRolesProjectsToHeldRoles(t *testing.T) {
	p := DefaultPolicy(testManifest(t))

	eff := p.ForRoles("user")

	for _, r := range eff.Roles {
		if r.Name != "user" {
			t.Errorf("ForRoles(\"user\") leaked role %q", r.Name)
		}
	}
	if len(eff.Roles) != 1 {
		t.Errorf("ForRoles(\"user\") = %d roles, want 1", len(eff.Roles))
	}
	for _, g := range eff.Grants {
		if g.Role != "user" {
			t.Errorf("ForRoles(\"user\") leaked a grant for role %q", g.Role)
		}
	}
	if len(eff.Grants) == 0 {
		t.Error("ForRoles(\"user\") returned no grants; the user role has permissions")
	}
}

// A principal with several roles gets the union of every role's grants.
func TestForRolesUnionsMultipleRoles(t *testing.T) {
	p := DefaultPolicy(testManifest(t))

	eff := p.ForRoles("user", "auditor")

	gotRoles := map[string]bool{}
	for _, r := range eff.Roles {
		gotRoles[r.Name] = true
	}
	if !gotRoles["user"] || !gotRoles["auditor"] || len(gotRoles) != 2 {
		t.Errorf("ForRoles(user, auditor) roles = %v, want exactly {user, auditor}", gotRoles)
	}

	var userGrants, auditorGrants, other int
	for _, g := range eff.Grants {
		switch g.Role {
		case "user":
			userGrants++
		case "auditor":
			auditorGrants++
		default:
			other++
		}
	}
	if other != 0 {
		t.Errorf("ForRoles(user, auditor) included %d grants for other roles", other)
	}
	if userGrants == 0 || auditorGrants == 0 {
		t.Errorf("union missing grants: user=%d auditor=%d", userGrants, auditorGrants)
	}
}

// A role the policy does not define contributes nothing, and asking for no
// roles yields an empty (no-access) policy. ForRoles never mutates the
// receiver.
func TestForRolesUnknownAndEmpty(t *testing.T) {
	p := DefaultPolicy(testManifest(t))
	rolesBefore, grantsBefore := len(p.Roles), len(p.Grants)

	if eff := p.ForRoles("nonexistent"); len(eff.Roles) != 0 || len(eff.Grants) != 0 {
		t.Errorf("ForRoles(unknown) = %d roles / %d grants, want 0/0", len(eff.Roles), len(eff.Grants))
	}
	if eff := p.ForRoles(); len(eff.Roles) != 0 || len(eff.Grants) != 0 {
		t.Errorf("ForRoles() = %d roles / %d grants, want 0/0", len(eff.Roles), len(eff.Grants))
	}

	if len(p.Roles) != rolesBefore || len(p.Grants) != grantsBefore {
		t.Error("ForRoles mutated the receiver policy")
	}
}

func TestDefaultRoleSemantics(t *testing.T) {
	m := testManifest(t)
	p := DefaultPolicy(m)

	visible := func(role, entity string) []pii.Category {
		for _, g := range p.Grants {
			if g.Role == role && g.Entity == entity && g.Action == ActionRead {
				return g.VisiblePII
			}
		}
		return nil
	}
	can := func(role, entity string, a Action) bool {
		for _, g := range p.Grants {
			if g.Role == role && g.Entity == entity && g.Action == a {
				return true
			}
		}
		return false
	}

	if got := len(visible("admin", "customer")); got != len(pii.Categories()) {
		t.Errorf("admin should see all %d PII categories, sees %d", len(pii.Categories()), got)
	}
	for _, c := range visible("user", "customer") {
		if c.HighSensitivity() {
			t.Errorf("user should not see high-sensitivity category %q", c)
		}
	}
	if len(visible("user", "customer")) == 0 {
		t.Error("user should see the non-high-sensitivity categories")
	}
	if len(visible("auditor", "customer")) != 0 {
		t.Error("auditor should see no PII categories")
	}
	if can("auditor", "customer", ActionCreate) || can("auditor", "customer", ActionDelete) {
		t.Error("auditor should be read-only")
	}
	if !can("auditor", "customer", ActionRead) || !can("auditor", "customer", ActionList) {
		t.Error("auditor should be able to read and list")
	}
}

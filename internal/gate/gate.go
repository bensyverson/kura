package gate

import (
	"context"
	"errors"
	"fmt"

	"github.com/bensyverson/kura/internal/audit"
	"github.com/bensyverson/kura/internal/cedar"
	"github.com/bensyverson/kura/internal/identity"
	"github.com/bensyverson/kura/internal/manifest"
	"github.com/bensyverson/kura/internal/pii"
)

// Errors returned by the gate.
var (
	// ErrDenied is returned when the authorization step denies the
	// request. The caller learns the request was refused; it learns
	// nothing about the resource.
	ErrDenied = errors.New("gate: request denied")
	// ErrUnknownEntity is returned when the request names an entity the
	// manifest does not declare.
	ErrUnknownEntity = errors.New("gate: unknown entity")
	// ErrMissingDependency is returned by New when a required
	// collaborator is nil.
	ErrMissingDependency = errors.New("gate: requires an authenticator, evaluator, role resolver, manifest, scanner, and recorder")
)

// AccessRequest is one request to read data through the gate.
type AccessRequest struct {
	// Token is the raw authentication token; the gate resolves it to a
	// principal.
	Token string
	// Action is the operation being attempted.
	Action cedar.Action
	// Entity and ResourceID name the resource.
	Entity     string
	ResourceID string
}

// Fetcher performs the actual data read. The gate invokes it only after
// authorization passes, and masks whatever it returns before any caller
// sees it — so a Fetcher cannot be a way around the gate. It returns the
// record as a field-name-to-value map.
type Fetcher func(ctx context.Context) (map[string]string, error)

// AccessResult is what a caller gets back from a successful Access: the
// resolved principal and the record, with every PII span the
// authorization decision did not make visible already redacted.
type AccessResult struct {
	Principal identity.Principal
	Fields    map[string]string
}

// Gate is the single core enforcement entrypoint. Every adapter — the
// HTTP API, the CLI's --local path, the dashboard, the MCP server —
// calls Access and nothing else; none may reconstruct the steps it
// chains. The chain is authenticate -> authorize -> access -> mask ->
// audit, and it is welded into one method: there is no public surface
// that performs a subset.
type Gate struct {
	auth      *identity.Authenticator
	evaluator *cedar.Evaluator
	roles     RoleResolver
	manifest  *manifest.Manifest
	scanner   *pii.Scanner
	recorder  *audit.Recorder
}

// New assembles a Gate from its collaborators. Every collaborator is
// required; New returns ErrMissingDependency if any is nil.
func New(
	auth *identity.Authenticator,
	evaluator *cedar.Evaluator,
	roles RoleResolver,
	m *manifest.Manifest,
	scanner *pii.Scanner,
	recorder *audit.Recorder,
) (*Gate, error) {
	if auth == nil || evaluator == nil || roles == nil || m == nil || scanner == nil || recorder == nil {
		return nil, ErrMissingDependency
	}
	return &Gate{
		auth:      auth,
		evaluator: evaluator,
		roles:     roles,
		manifest:  m,
		scanner:   scanner,
		recorder:  recorder,
	}, nil
}

// Access runs the full enforcement chain for one request:
//
//	authenticate -> authorize -> access -> mask -> audit
//
// Every step happens, in order, every time. The fetch callback supplies
// the data but cannot be a way around the gate: it runs only after
// authorization passes, and its output is masked and audited before any
// caller sees it. A denied request never reaches fetch; a request whose
// authentication, authorization, or access cannot be audited fails
// closed, returning an error and no data.
func (g *Gate) Access(ctx context.Context, req AccessRequest, fetch Fetcher) (AccessResult, error) {
	// 1. Authenticate.
	principal, err := g.auth.Resolve(req.Token)
	if err != nil {
		if recErr := g.recorder.RecordAuthentication(ctx, identity.Principal{}, audit.OutcomeDenied); recErr != nil {
			return AccessResult{}, fmt.Errorf("gate: recording failed authentication: %w", recErr)
		}
		return AccessResult{}, fmt.Errorf("gate: authentication: %w", err)
	}
	if err := g.recorder.RecordAuthentication(ctx, principal, audit.OutcomeAllowed); err != nil {
		return AccessResult{}, fmt.Errorf("gate: recording authentication: %w", err)
	}

	// 2. Authorize. The PII categories the evaluator reasons about are
	// the ones the manifest declares for the entity — categories, never
	// column names, and resolved without touching the data.
	entity, ok := g.manifest.Entity(req.Entity)
	if !ok {
		return AccessResult{}, fmt.Errorf("%w: %q", ErrUnknownEntity, req.Entity)
	}
	roles, err := g.roles.Roles(ctx, principal)
	if err != nil {
		return AccessResult{}, fmt.Errorf("gate: resolving roles: %w", err)
	}
	decision, err := g.evaluator.Decide(cedar.Request{
		Principal:   principal,
		Roles:       roles,
		Action:      req.Action,
		Entity:      req.Entity,
		ResourceID:  req.ResourceID,
		DetectedPII: declaredCategories(entity),
	})
	if err != nil {
		return AccessResult{}, fmt.Errorf("gate: authorization: %w", err)
	}
	resource := audit.Resource{Entity: req.Entity, ID: req.ResourceID}
	if !decision.Allowed {
		if err := g.recorder.RecordAuthorization(ctx, principal, string(req.Action), resource, audit.OutcomeDenied); err != nil {
			return AccessResult{}, fmt.Errorf("gate: recording denied authorization: %w", err)
		}
		return AccessResult{}, ErrDenied
	}
	if err := g.recorder.RecordAuthorization(ctx, principal, string(req.Action), resource, audit.OutcomeAllowed); err != nil {
		return AccessResult{}, fmt.Errorf("gate: recording authorization: %w", err)
	}

	// 3. Access.
	fields, err := fetch(ctx)
	if err != nil {
		return AccessResult{}, fmt.Errorf("gate: data access: %w", err)
	}

	// 4. Mask. The data is re-scanned at access time — catching detector
	// drift since ingestion — and every span whose category the decision
	// did not make visible is redacted. A category detected here that
	// the decision never classified is, by definition, not visible.
	spansByField, err := g.scanner.ScanRecord(ctx, fields)
	if err != nil {
		return AccessResult{}, fmt.Errorf("gate: scanning for masking: %w", err)
	}
	masked := maskFields(spansByField, fields, categorySet(decision.VisibleCategories))

	// 5. Audit the access.
	if err := g.recorder.RecordAccess(ctx, principal, string(req.Action), resource); err != nil {
		return AccessResult{}, fmt.Errorf("gate: recording access: %w", err)
	}

	return AccessResult{Principal: principal, Fields: masked}, nil
}

// declaredCategories returns the PII categories the manifest declares for
// the entity's fields, in canonical category order.
func declaredCategories(e *manifest.Entity) []pii.Category {
	present := make(map[pii.Category]bool)
	for _, f := range e.Fields {
		if f.PII != nil {
			present[*f.PII] = true
		}
	}
	var out []pii.Category
	for _, c := range pii.Categories() {
		if present[c] {
			out = append(out, c)
		}
	}
	return out
}

// categorySet collects cats into a set for membership tests.
func categorySet(cats []pii.Category) map[pii.Category]bool {
	s := make(map[pii.Category]bool, len(cats))
	for _, c := range cats {
		s[c] = true
	}
	return s
}

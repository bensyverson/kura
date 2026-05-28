package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/bensyverson/kura/internal/clio"
	"github.com/bensyverson/kura/internal/data"
	"github.com/bensyverson/kura/internal/identity"
	"github.com/bensyverson/kura/internal/pii"
	"github.com/spf13/cobra"
)

// newDevCmd builds the hidden `kura dev` group: the affordances a local
// bring-up needs that have no place on the public surface. It is hidden —
// excluded from help and from `kura agent-context` — because each
// subcommand is a development or bootstrap shortcut, not a product verb:
//
//   - token        mint a signed token headlessly (no browser OAuth)
//   - pii-detector run a stub PII detection service for offline scanning
//   - seed-users   bootstrap the first users and roles into the store
//
// None grants privilege beyond what the holder of the signing secret or
// the database credentials already has; they package those capabilities so
// scripts/dev-instance.sh can stand up a populated Kura in one command.
func newDevCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:    "dev",
		Short:  "Development and bootstrap helpers (hidden)",
		Hidden: true,
	}
	cmd.AddCommand(newDevTokenCmd())
	cmd.AddCommand(newDevPIIDetectorCmd())
	cmd.AddCommand(newDevSeedUsersCmd())
	return cmd
}

// newDevTokenCmd builds `kura dev token`: mint a signed identity token
// from KURA_SIGNING_SECRET without the interactive OAuth flow. It is the
// headless counterpart to `kura login` — for CI, the dev instance, and
// bootstrapping the first admin. The signing secret already lets its
// holder forge any token, so this adds convenience, not privilege.
func newDevTokenCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "token",
		Short: "Mint a signed token from KURA_SIGNING_SECRET (headless)",
		Long: `Mint a signed identity token from KURA_SIGNING_SECRET, without the
browser OAuth flow.

The principal is built from the flags: human types (user, admin,
consultant) require --email and --tenant and default --id to the email;
the service type needs only --id. The token is printed to stdout. With
--save it is also written to the token cache for --server, so subsequent
verbs (ingest, query, dashboard) are signed in.`,
		RunE: devTokenRun,
	}
	cmd.Flags().String("type", "admin", "principal type: user, admin, consultant, or service")
	cmd.Flags().String("email", "", "principal email (required for human types)")
	cmd.Flags().String("tenant", "", "principal tenant/domain (required for human types)")
	cmd.Flags().String("id", "", "principal id (defaults to --email for human types; required for service)")
	cmd.Flags().Duration("ttl", 24*time.Hour, "token lifetime")
	cmd.Flags().Bool("save", false, "also write the token to the cache for --server")
	return cmd
}

// devTokenRun assembles the principal from flags, mints a token, prints
// it, and optionally caches it.
func devTokenRun(cmd *cobra.Command, _ []string) error {
	secret := os.Getenv("KURA_SIGNING_SECRET")
	if secret == "" {
		return clio.UsageError("dev token", "KURA_SIGNING_SECRET is not set — nothing to sign with")
	}

	typ, _ := cmd.Flags().GetString("type")
	email, _ := cmd.Flags().GetString("email")
	tenant, _ := cmd.Flags().GetString("tenant")
	id, _ := cmd.Flags().GetString("id")
	ttl, _ := cmd.Flags().GetDuration("ttl")

	p := identity.Principal{
		Type:   identity.PrincipalType(typ),
		ID:     id,
		Email:  email,
		Tenant: tenant,
	}
	// For human principals the id is the email; default it so callers need
	// not repeat themselves. Issue rejects a still-malformed principal.
	if p.ID == "" {
		p.ID = email
	}

	token, err := identity.NewAuthenticator([]byte(secret)).Issue(p, ttl)
	if err != nil {
		return clio.UsageError("dev token", "%v", err)
	}

	if save, _ := cmd.Flags().GetBool("save"); save {
		server, _ := cmd.Flags().GetString("server")
		if server == "" {
			return clio.UsageError("dev token", "--save requires --server to know which deployment the token is for")
		}
		cache, err := defaultTokenCache()
		if err != nil {
			return err
		}
		if err := cache.save(server, token); err != nil {
			return err
		}
	}

	fmt.Fprintln(cmd.OutOrStdout(), token)
	return nil
}

// newDevPIIDetectorCmd builds `kura dev pii-detector`: a stub PII
// detection service so a local Kura can scan, classify, and mask without
// the production model service. It serves the same HTTP contract
// KURA_PII_DETECTOR_URL points kura serve at, backed by the regex
// PatternDetector — point serve at it for offline development.
func newDevPIIDetectorCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "pii-detector",
		Short: "Run a stub PII detection service for offline development",
		Long: `Run a stub PII detection service backed by the regex pattern detector.

It serves the same JSON contract as the production detector, so kura
serve can point KURA_PII_DETECTOR_URL at it for offline development. It
detects email addresses, US phone numbers, and US SSNs (as the
high-sensitivity account_number category). It is not a real detector and
must never be used in production.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			addr, _ := cmd.Flags().GetString("addr")
			return runDevPIIDetector(cmd.Context(), addr, cmd.ErrOrStderr())
		},
	}
	cmd.Flags().String("addr", "127.0.0.1:8089", "TCP address to bind, in host:port form")
	return cmd
}

// devPIIDetectorHandler builds the stub detector's HTTP handler over the
// default pattern detector. Factored out so the wiring is testable without
// binding a socket.
func devPIIDetectorHandler() http.Handler {
	return pii.Handler(pii.DefaultPatternDetector())
}

// runDevPIIDetector serves the stub detector until the context is
// cancelled (SIGINT/SIGTERM), then shuts down gracefully.
func runDevPIIDetector(parent context.Context, addr string, logw io.Writer) error {
	ctx, stop := signal.NotifyContext(parent, syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	srv := &http.Server{Addr: addr, Handler: devPIIDetectorHandler()}
	errc := make(chan error, 1)
	go func() {
		fmt.Fprintf(logw, "dev pii-detector listening on %s\n", addr)
		errc <- srv.ListenAndServe()
	}()

	select {
	case err := <-errc:
		if err != nil && err != http.ErrServerClosed {
			return clio.InternalError("dev pii-detector", "%v", err)
		}
		return nil
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	}
}

// newDevSeedUsersCmd builds `kura dev seed-users`: bootstrap the first
// users and their roles directly into the configured store. A fresh
// deployment has no admin, and every admin API mutation needs the admin
// role — so the first role assignment cannot go through the API. This
// writes it straight to the store, the same way a production deployment
// bootstraps its first admin.
func newDevSeedUsersCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "seed-users",
		Short: "Bootstrap users and roles directly into the configured store",
		Long: `Bootstrap users and their roles directly into the store kura serve uses.

Reads the same KURA_DATABASE_URL / KURA_DB_TENANT_ID environment as
kura serve and writes role assignments straight to the store — the
bootstrap that breaks the no-admin-yet chicken-and-egg, since every admin
API mutation itself needs the admin role. Repeatable: each --admin,
--user, and --auditor flag names an email granted that role.`,
		RunE: devSeedUsersRun,
	}
	cmd.Flags().StringArray("admin", nil, "email to grant the admin role (repeatable)")
	cmd.Flags().StringArray("user", nil, "email to grant the user role (repeatable)")
	cmd.Flags().StringArray("auditor", nil, "email to grant the auditor role (repeatable)")
	return cmd
}

// devSeedUsersRun builds the store from the environment and applies the
// role seeds named by the flags.
func devSeedUsersRun(cmd *cobra.Command, _ []string) error {
	if os.Getenv("KURA_DATABASE_URL") == "" {
		return clio.UsageError("dev seed-users", "KURA_DATABASE_URL is not set — seeding needs the same Postgres kura serve uses")
	}
	_, _, users, _, err := buildStores(os.Getenv)
	if err != nil {
		return clio.InternalError("dev seed-users", "%v", err)
	}

	admins, _ := cmd.Flags().GetStringArray("admin")
	plain, _ := cmd.Flags().GetStringArray("user")
	auditors, _ := cmd.Flags().GetStringArray("auditor")
	seeds := buildRoleSeeds(admins, plain, auditors)
	if len(seeds) == 0 {
		return clio.UsageError("dev seed-users", "no users to seed — pass at least one --admin, --user, or --auditor")
	}

	if err := applyRoleSeeds(cmd.Context(), users, seeds); err != nil {
		return clio.InternalError("dev seed-users", "%v", err)
	}
	for _, s := range seeds {
		fmt.Fprintf(cmd.OutOrStdout(), "seeded %s: %v\n", s.email, s.roles)
	}
	return nil
}

// roleSeed is one user to bootstrap and the roles to grant it.
type roleSeed struct {
	email string
	roles []string
}

// buildRoleSeeds turns the per-role email lists into one seed per email,
// merging roles when the same email appears under more than one flag.
func buildRoleSeeds(admins, users, auditors []string) []roleSeed {
	order := []string{}
	byEmail := map[string][]string{}
	add := func(emails []string, role string) {
		for _, e := range emails {
			if _, seen := byEmail[e]; !seen {
				order = append(order, e)
			}
			byEmail[e] = append(byEmail[e], role)
		}
	}
	add(admins, "admin")
	add(users, "user")
	add(auditors, "auditor")

	seeds := make([]roleSeed, 0, len(order))
	for _, e := range order {
		seeds = append(seeds, roleSeed{email: e, roles: byEmail[e]})
	}
	return seeds
}

// applyRoleSeeds adds each user to the store and assigns its roles. AddUser
// is idempotent and AssignRoles requires the user to exist first, so the
// pair runs in that order — and the whole thing is safe to re-run.
func applyRoleSeeds(ctx context.Context, users data.UserStore, seeds []roleSeed) error {
	for _, s := range seeds {
		if err := users.AddUser(ctx, s.email); err != nil {
			return fmt.Errorf("adding %s: %w", s.email, err)
		}
		if err := users.AssignRoles(ctx, s.email, s.roles...); err != nil {
			return fmt.Errorf("assigning roles to %s: %w", s.email, err)
		}
	}
	return nil
}

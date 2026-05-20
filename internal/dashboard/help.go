package dashboard

import (
	"net/http"
	"strings"
)

// helpView is the view-model the programmatic-access page renders. It
// carries only the configured server URL, so the page's examples — the
// `kura login` target and the HTTP API base — are concrete. The page is
// otherwise static reference content; it holds no secret, and never the
// bearer token.
type helpView struct {
	ServerURL string
}

// handleHelp renders the programmatic-access page: how to drive Kura
// without the dashboard, through the CLI, the HTTP API, and the MCP server,
// plus the token-issuance flow. It authenticates like every page so an
// unauthenticated visitor gets the sign-in prompt (which itself documents
// `kura login`).
func (s *Server) handleHelp(w http.ResponseWriter, r *http.Request) {
	principal, err := s.api.whoami(r.Context())
	if err != nil {
		s.renderAuthOrError(w, "/help", err)
		return
	}
	view := helpView{ServerURL: strings.TrimRight(s.cfg.RemoteURL, "/")}
	s.render(w, http.StatusOK, "help", pageData{
		Title:     "Programmatic access",
		Nav:       navFor("/help"),
		Principal: &principal,
		Help:      &view,
	})
}

package dashboard

import (
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/bensyverson/kura/internal/review"
)

// reviewsView is the view-model the access-review list page renders: every
// past review (newest-first) with a progress summary, plus the banners.
type reviewsView struct {
	Reviews []reviewSummary
	Notice  string
	Error   string
}

// reviewSummary is one review on the list: identity, status, who ran it,
// and how many subjects are still undecided.
type reviewSummary struct {
	ID        string
	Href      string
	StartedAt string
	StartedBy string
	Status    string
	Completed bool
	Total     int
	Pending   int
}

// reviewDetailView is the view-model the single-review page renders: the
// subjects with their snapshot roles and decisions, whether the review is
// still open (so decision controls show), and the banners.
type reviewDetailView struct {
	ID          string
	StartedAt   string
	CompletedAt string
	StartedBy   string
	Status      string
	Open        bool
	Items       []reviewItemView
	Pending     int
	Notice      string
	Error       string
}

// reviewItemView is one subject on the detail page.
type reviewItemView struct {
	Email    string
	Roles    []string
	Decision string
	Note     string
}

// handleReviews renders the access-review list. An auth problem lands on
// sign-in; an unreachable remote on the error page.
func (s *Server) handleReviews(w http.ResponseWriter, r *http.Request) {
	principal, err := s.api.whoami(r.Context())
	if err != nil {
		s.renderAuthOrError(w, "/reviews", err)
		return
	}
	reviews, err := s.api.reviews(r.Context())
	if err != nil {
		s.renderAuthOrError(w, "/reviews", err)
		return
	}
	view := buildReviewsView(reviews)
	view.Notice = reviewNotice(r.URL.Query().Get("ok"))
	view.Error = bannerError(r.URL.Query().Get("err"))
	s.render(w, http.StatusOK, "reviews", pageData{
		Title:     "Access review",
		Nav:       navFor("/reviews"),
		Principal: &principal,
		Reviews:   &view,
	})
}

// handleStartReview starts a new review and redirects to its detail page
// (POST-redirect-GET), guarded by the same-origin check.
func (s *Server) handleStartReview(w http.ResponseWriter, r *http.Request) {
	if !s.sameOrigin(r) {
		http.Error(w, "forbidden: cross-origin request", http.StatusForbidden)
		return
	}
	created, err := s.api.startReview(r.Context())
	if err != nil {
		if errors.Is(err, ErrNotAuthenticated) {
			http.Redirect(w, r, "/reviews", http.StatusSeeOther)
			return
		}
		if errors.Is(err, ErrForbidden) {
			http.Redirect(w, r, "/reviews?err=forbidden", http.StatusSeeOther)
			return
		}
		s.cfg.Logger.Error("dashboard: starting review failed", "err", err)
		http.Redirect(w, r, "/reviews?err=unreachable", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/reviews/"+url.PathEscape(created.ID)+"?ok=started", http.StatusSeeOther)
}

// handleReviewDetail renders one review.
func (s *Server) handleReviewDetail(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	principal, err := s.api.whoami(r.Context())
	if err != nil {
		s.renderAuthOrError(w, "/reviews", err)
		return
	}
	rv, err := s.api.reviewByID(r.Context(), id)
	if err != nil {
		if errors.Is(err, ErrRemoteNotFound) {
			s.renderNotFound(w, &principal, "No such review", "No access review with that id exists.")
			return
		}
		s.renderAuthOrError(w, "/reviews", err)
		return
	}
	view := buildReviewDetail(rv)
	view.Notice = reviewNotice(r.URL.Query().Get("ok"))
	view.Error = bannerError(r.URL.Query().Get("err"))
	s.render(w, http.StatusOK, "review", pageData{
		Title:     "Access review",
		Nav:       navFor("/reviews"),
		Principal: &principal,
		Review:    &view,
	})
}

// handleReviewDecide records one approve/remove decision and redirects back
// to the detail page.
func (s *Server) handleReviewDecide(w http.ResponseWriter, r *http.Request) {
	if !s.sameOrigin(r) {
		http.Error(w, "forbidden: cross-origin request", http.StatusForbidden)
		return
	}
	id := r.PathValue("id")
	email := strings.TrimSpace(r.FormValue("email"))
	decision := r.FormValue("decision")
	note := strings.TrimSpace(r.FormValue("note"))
	if email == "" || (decision != "approved" && decision != "removed") {
		s.redirectReview(w, r, id, "err", "input")
		return
	}
	s.afterReviewMutation(w, r, id, s.api.decideReview(r.Context(), id, email, decision, note), "decided")
}

// handleReviewComplete archives a review and redirects back to its detail.
func (s *Server) handleReviewComplete(w http.ResponseWriter, r *http.Request) {
	if !s.sameOrigin(r) {
		http.Error(w, "forbidden: cross-origin request", http.StatusForbidden)
		return
	}
	id := r.PathValue("id")
	s.afterReviewMutation(w, r, id, s.api.completeReview(r.Context(), id), "completed")
}

// afterReviewMutation completes the POST-redirect-GET for a review action,
// mapping the remote error to a fixed banner code.
func (s *Server) afterReviewMutation(w http.ResponseWriter, r *http.Request, id string, err error, okCode string) {
	if err == nil {
		s.redirectReview(w, r, id, "ok", okCode)
		return
	}
	switch {
	case errors.Is(err, ErrNotAuthenticated):
		http.Redirect(w, r, "/reviews", http.StatusSeeOther)
	case errors.Is(err, ErrForbidden):
		s.redirectReview(w, r, id, "err", "forbidden")
	case errors.Is(err, ErrRemoteNotFound):
		s.redirectReview(w, r, id, "err", "notfound")
	default:
		s.cfg.Logger.Error("dashboard: review mutation failed", "err", err)
		s.redirectReview(w, r, id, "err", "unreachable")
	}
}

// redirectReview issues the 303 back to a review's detail with a status code.
func (s *Server) redirectReview(w http.ResponseWriter, r *http.Request, id, key, code string) {
	http.Redirect(w, r, "/reviews/"+url.PathEscape(id)+"?"+key+"="+url.QueryEscape(code), http.StatusSeeOther)
}

// buildReviewsView projects reviews into the list view-model.
func buildReviewsView(reviews []review.Review) reviewsView {
	view := reviewsView{Reviews: make([]reviewSummary, 0, len(reviews))}
	for _, rv := range reviews {
		view.Reviews = append(view.Reviews, reviewSummary{
			ID:        rv.ID,
			Href:      "/reviews/" + rv.ID,
			StartedAt: rv.StartedAt.Format("2006-01-02 15:04"),
			StartedBy: rv.StartedBy,
			Status:    string(rv.Status),
			Completed: rv.Status == review.StatusCompleted,
			Total:     len(rv.Items),
			Pending:   pendingCount(rv),
		})
	}
	return view
}

// buildReviewDetail projects one review into the detail view-model.
func buildReviewDetail(rv review.Review) reviewDetailView {
	view := reviewDetailView{
		ID:        rv.ID,
		StartedAt: rv.StartedAt.Format("2006-01-02 15:04"),
		StartedBy: rv.StartedBy,
		Status:    string(rv.Status),
		Open:      rv.Status == review.StatusOpen,
		Pending:   pendingCount(rv),
		Items:     make([]reviewItemView, 0, len(rv.Items)),
	}
	if rv.CompletedAt != nil {
		view.CompletedAt = rv.CompletedAt.Format("2006-01-02 15:04")
	}
	for _, it := range rv.Items {
		view.Items = append(view.Items, reviewItemView{
			Email:    it.Email,
			Roles:    it.RolesAtReview,
			Decision: string(it.Decision),
			Note:     it.Note,
		})
	}
	return view
}

// pendingCount returns how many of a review's subjects are still undecided.
func pendingCount(rv review.Review) int {
	n := 0
	for _, it := range rv.Items {
		if it.Decision == review.DecisionPending {
			n++
		}
	}
	return n
}

// reviewNotice maps a success code to a fixed message.
func reviewNotice(code string) string {
	switch code {
	case "started":
		return "Review started — the authorized list was snapshotted. Approve or remove each person, then complete the review."
	case "decided":
		return "Decision recorded."
	case "completed":
		return "Review completed and archived."
	default:
		return ""
	}
}

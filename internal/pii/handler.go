package pii

import (
	"encoding/json"
	"net/http"
)

// Handler returns an http.Handler that serves d over the detect HTTP
// contract — the server side of exactly what ServiceDetector calls. It
// lives next to ServiceDetector so the request and response shapes can
// never drift apart: the dev PII stub (and any future in-process detector)
// wraps a Detector with this and is reachable at a URL ServiceDetector
// understands.
//
// A body that is not a detect request is a 400; a Detector failure is a
// 500. Both mirror what ServiceDetector classifies on the client side.
func Handler(d Detector) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req detectRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "pii: undecodable detect request", http.StatusBadRequest)
			return
		}
		spans, err := d.Detect(r.Context(), req.Text)
		if err != nil {
			http.Error(w, "pii: detection failed", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(detectResponse{Spans: spans})
	})
}

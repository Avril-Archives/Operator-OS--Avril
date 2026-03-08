package secaudit

import (
	"encoding/json"
	"net/http"
	"strings"
)

// Handler returns an HTTP handler that runs the security audit and returns results.
// Requires admin authentication. Pass nil for auditor to get a 503 response.
func Handler(auditor *Auditor) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodPost {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{
				"code":    "method_not_allowed",
				"message": "Use GET or POST",
			})
			return
		}

		if auditor == nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{
				"code":    "audit_not_configured",
				"message": "Security audit is not configured",
			})
			return
		}

		// Optional category filter via query param.
		if cats := r.URL.Query().Get("categories"); cats != "" {
			var filter []Category
			for _, c := range strings.Split(cats, ",") {
				cat := Category(strings.TrimSpace(c))
				if ValidCategory(cat) {
					filter = append(filter, cat)
				}
			}
			if len(filter) > 0 {
				auditor.FilterCategories(filter...)
				defer auditor.FilterCategories() // reset after
			}
		}

		report := auditor.Run()

		format := r.URL.Query().Get("format")
		if format == "text" {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(report.TextReport()))
			return
		}

		writeJSON(w, http.StatusOK, report)
	}
}

// RegisterRoutes registers the security audit handler on the given mux.
func RegisterRoutes(mux *http.ServeMux, auditor *Auditor) {
	mux.HandleFunc("/api/v1/admin/security-audit", Handler(auditor))
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

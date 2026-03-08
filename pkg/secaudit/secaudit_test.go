package secaudit

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ──────────────────────────────────────────────
// Severity & Category
// ──────────────────────────────────────────────

func TestValidSeverity(t *testing.T) {
	assert.True(t, ValidSeverity(SeverityCritical))
	assert.True(t, ValidSeverity(SeverityHigh))
	assert.True(t, ValidSeverity(SeverityMedium))
	assert.True(t, ValidSeverity(SeverityLow))
	assert.True(t, ValidSeverity(SeverityInfo))
	assert.False(t, ValidSeverity("unknown"))
	assert.False(t, ValidSeverity(""))
}

func TestSeverityOrder(t *testing.T) {
	assert.Less(t, severityOrder(SeverityCritical), severityOrder(SeverityHigh))
	assert.Less(t, severityOrder(SeverityHigh), severityOrder(SeverityMedium))
	assert.Less(t, severityOrder(SeverityMedium), severityOrder(SeverityLow))
	assert.Less(t, severityOrder(SeverityLow), severityOrder(SeverityInfo))
	assert.Equal(t, 5, severityOrder("unknown"))
}

func TestValidCategory(t *testing.T) {
	for _, c := range AllCategories() {
		assert.True(t, ValidCategory(c), "category %q should be valid", c)
	}
	assert.False(t, ValidCategory("invalid"))
	assert.False(t, ValidCategory(""))
}

func TestAllCategories(t *testing.T) {
	cats := AllCategories()
	assert.Len(t, cats, 12)
	// Verify sorted.
	for i := 1; i < len(cats); i++ {
		assert.Less(t, string(cats[i-1]), string(cats[i]))
	}
}

// ──────────────────────────────────────────────
// Auditor
// ──────────────────────────────────────────────

func TestNewAuditor(t *testing.T) {
	a := NewAuditor()
	require.NotNil(t, a)
	assert.Equal(t, 0, a.CheckCount())
}

func TestRegisterCheck(t *testing.T) {
	a := NewAuditor()
	err := a.RegisterCheck(Check{
		ID:       "TEST-001",
		Name:     "Test check",
		Category: CategoryAuth,
		Fn:       func() []Finding { return nil },
	})
	require.NoError(t, err)
	assert.Equal(t, 1, a.CheckCount())
}

func TestRegisterCheckErrors(t *testing.T) {
	a := NewAuditor()

	// Missing ID.
	err := a.RegisterCheck(Check{Name: "x", Category: CategoryAuth, Fn: func() []Finding { return nil }})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "ID is required")

	// Missing name.
	err = a.RegisterCheck(Check{ID: "x", Category: CategoryAuth, Fn: func() []Finding { return nil }})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "name is required")

	// Missing function.
	err = a.RegisterCheck(Check{ID: "x", Name: "x", Category: CategoryAuth})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "function is required")

	// Invalid category.
	err = a.RegisterCheck(Check{ID: "x", Name: "x", Category: "bad", Fn: func() []Finding { return nil }})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid category")

	// Duplicate ID.
	a.RegisterCheck(Check{ID: "dup", Name: "a", Category: CategoryAuth, Fn: func() []Finding { return nil }})
	err = a.RegisterCheck(Check{ID: "dup", Name: "b", Category: CategoryAuth, Fn: func() []Finding { return nil }})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "duplicate")
}

func TestRun(t *testing.T) {
	a := NewAuditor()
	a.RegisterCheck(Check{
		ID: "T1", Name: "Pass", Category: CategoryAuth,
		Fn: func() []Finding {
			return []Finding{{ID: "T1", Category: CategoryAuth, Severity: SeverityInfo, Title: "OK", Passed: true}}
		},
	})
	a.RegisterCheck(Check{
		ID: "T2", Name: "Fail", Category: CategoryCrypto,
		Fn: func() []Finding {
			return []Finding{{ID: "T2", Category: CategoryCrypto, Severity: SeverityHigh, Title: "Bad", Passed: false}}
		},
	})

	report := a.Run()
	require.NotNil(t, report)
	assert.Equal(t, 2, report.ChecksRun)
	assert.Len(t, report.Findings, 2)
	assert.Equal(t, 1, report.Summary.Passed)
	assert.Equal(t, 1, report.Summary.Failed)
	assert.Greater(t, report.Duration, time.Duration(0))
}

func TestRunFilterCategories(t *testing.T) {
	a := NewAuditor()
	a.RegisterCheck(Check{
		ID: "A1", Name: "Auth", Category: CategoryAuth,
		Fn: func() []Finding {
			return []Finding{{ID: "A1", Passed: true, Category: CategoryAuth, Severity: SeverityInfo}}
		},
	})
	a.RegisterCheck(Check{
		ID: "C1", Name: "Crypto", Category: CategoryCrypto,
		Fn: func() []Finding {
			return []Finding{{ID: "C1", Passed: true, Category: CategoryCrypto, Severity: SeverityInfo}}
		},
	})

	a.FilterCategories(CategoryAuth)
	report := a.Run()
	assert.Equal(t, 1, report.ChecksRun)
	assert.Len(t, report.Findings, 1)
	assert.Equal(t, CategoryAuth, report.Findings[0].Category)
}

func TestRunSortsBySeverity(t *testing.T) {
	a := NewAuditor()
	a.RegisterCheck(Check{
		ID: "S1", Name: "Multi", Category: CategoryAuth,
		Fn: func() []Finding {
			return []Finding{
				{ID: "low", Severity: SeverityLow, Category: CategoryAuth},
				{ID: "crit", Severity: SeverityCritical, Category: CategoryAuth},
				{ID: "med", Severity: SeverityMedium, Category: CategoryAuth},
			}
		},
	})

	report := a.Run()
	assert.Equal(t, SeverityCritical, report.Findings[0].Severity)
	assert.Equal(t, SeverityMedium, report.Findings[1].Severity)
	assert.Equal(t, SeverityLow, report.Findings[2].Severity)
}

// ──────────────────────────────────────────────
// Report
// ──────────────────────────────────────────────

func TestReportFailedFindings(t *testing.T) {
	r := &Report{
		Findings: []Finding{
			{ID: "1", Passed: true},
			{ID: "2", Passed: false},
			{ID: "3", Passed: false},
		},
	}
	failed := r.FailedFindings()
	assert.Len(t, failed, 2)
}

func TestReportFindingsByCategory(t *testing.T) {
	r := &Report{
		Findings: []Finding{
			{ID: "1", Category: CategoryAuth},
			{ID: "2", Category: CategoryCrypto},
			{ID: "3", Category: CategoryAuth},
		},
	}
	auth := r.FindingsByCategory(CategoryAuth)
	assert.Len(t, auth, 2)
}

func TestReportFindingsBySeverity(t *testing.T) {
	r := &Report{
		Findings: []Finding{
			{ID: "1", Severity: SeverityHigh},
			{ID: "2", Severity: SeverityLow},
			{ID: "3", Severity: SeverityHigh},
		},
	}
	high := r.FindingsBySeverity(SeverityHigh)
	assert.Len(t, high, 2)
}

func TestReportHasCritical(t *testing.T) {
	r := &Report{Findings: []Finding{{Severity: SeverityHigh}}}
	assert.False(t, r.HasCritical())

	r.Findings = append(r.Findings, Finding{Severity: SeverityCritical, Passed: true})
	assert.False(t, r.HasCritical()) // passed critical doesn't count

	r.Findings = append(r.Findings, Finding{Severity: SeverityCritical, Passed: false})
	assert.True(t, r.HasCritical())
}

func TestReportJSON(t *testing.T) {
	r := &Report{
		Timestamp: time.Date(2026, 3, 8, 0, 0, 0, 0, time.UTC),
		ChecksRun: 1,
		Findings:  []Finding{{ID: "test", Passed: true, Severity: SeverityInfo, Category: CategoryAuth}},
	}
	data, err := r.JSON()
	require.NoError(t, err)

	var parsed Report
	err = json.Unmarshal(data, &parsed)
	require.NoError(t, err)
	assert.Equal(t, 1, parsed.ChecksRun)
	assert.Len(t, parsed.Findings, 1)
}

func TestReportTextReport(t *testing.T) {
	r := &Report{
		Timestamp: time.Date(2026, 3, 8, 0, 0, 0, 0, time.UTC),
		ChecksRun: 2,
		RiskScore: 15.0,
		PassRate:  50.0,
		Summary:   Summary{Total: 2, Passed: 1, Failed: 1, High: 1, Info: 1},
		Findings: []Finding{
			{ID: "F1", Severity: SeverityHigh, Title: "Bad thing", Description: "Very bad", Location: "pkg/foo", Remediation: "Fix it", Passed: false, Category: CategoryAuth},
			{ID: "F2", Severity: SeverityInfo, Title: "Good", Passed: true, Category: CategoryAuth},
		},
	}
	text := r.TextReport()
	assert.Contains(t, text, "SECURITY AUDIT REPORT")
	assert.Contains(t, text, "Risk Score: 15.0")
	assert.Contains(t, text, "Pass Rate:  50.0%")
	assert.Contains(t, text, "FAILED CHECKS")
	assert.Contains(t, text, "[HIGH] F1")
	assert.Contains(t, text, "Fix it")
}

// ──────────────────────────────────────────────
// Scoring Functions
// ──────────────────────────────────────────────

func TestComputeSummary(t *testing.T) {
	findings := []Finding{
		{Severity: SeverityCritical, Passed: false},
		{Severity: SeverityHigh, Passed: false},
		{Severity: SeverityMedium, Passed: true},
		{Severity: SeverityLow, Passed: true},
		{Severity: SeverityInfo, Passed: true},
	}
	s := computeSummary(findings)
	assert.Equal(t, 5, s.Total)
	assert.Equal(t, 3, s.Passed)
	assert.Equal(t, 2, s.Failed)
	assert.Equal(t, 1, s.Critical)
	assert.Equal(t, 1, s.High)
	assert.Equal(t, 1, s.Medium)
	assert.Equal(t, 1, s.Low)
	assert.Equal(t, 1, s.Info)
}

func TestComputeRiskScore(t *testing.T) {
	assert.Equal(t, 0.0, computeRiskScore(nil))
	assert.Equal(t, 0.0, computeRiskScore([]Finding{{Passed: true, Severity: SeverityCritical}}))
	assert.Equal(t, 25.0, computeRiskScore([]Finding{{Passed: false, Severity: SeverityCritical}}))
	assert.Equal(t, 15.0, computeRiskScore([]Finding{{Passed: false, Severity: SeverityHigh}}))
	assert.Equal(t, 8.0, computeRiskScore([]Finding{{Passed: false, Severity: SeverityMedium}}))
	assert.Equal(t, 3.0, computeRiskScore([]Finding{{Passed: false, Severity: SeverityLow}}))
	assert.Equal(t, 1.0, computeRiskScore([]Finding{{Passed: false, Severity: SeverityInfo}}))

	// Capped at 100.
	many := make([]Finding, 10)
	for i := range many {
		many[i] = Finding{Passed: false, Severity: SeverityCritical}
	}
	assert.Equal(t, 100.0, computeRiskScore(many))
}

func TestComputePassRate(t *testing.T) {
	assert.Equal(t, 100.0, computePassRate(nil))
	assert.Equal(t, 100.0, computePassRate([]Finding{{Passed: true}}))
	assert.Equal(t, 0.0, computePassRate([]Finding{{Passed: false}}))
	assert.Equal(t, 50.0, computePassRate([]Finding{{Passed: true}, {Passed: false}}))
}

func TestComputeCategorySummaries(t *testing.T) {
	findings := []Finding{
		{Category: CategoryAuth, Passed: true},
		{Category: CategoryAuth, Passed: false},
		{Category: CategoryCrypto, Passed: true},
	}
	cats := computeCategorySummaries(findings)
	assert.Equal(t, 2, cats[CategoryAuth].Total)
	assert.Equal(t, 1, cats[CategoryAuth].Passed)
	assert.Equal(t, 1, cats[CategoryAuth].Failed)
	assert.Equal(t, 1, cats[CategoryCrypto].Total)
}

// ──────────────────────────────────────────────
// Auth Checks
// ──────────────────────────────────────────────

func TestCheckJWTKeyStrength(t *testing.T) {
	// No key.
	findings := checkJWTKeyStrength(nil)
	require.Len(t, findings, 1)
	assert.False(t, findings[0].Passed)
	assert.Equal(t, SeverityCritical, findings[0].Severity)

	// Short key.
	findings = checkJWTKeyStrength([]byte("short"))
	assert.False(t, findings[0].Passed)
	assert.Equal(t, SeverityHigh, findings[0].Severity)

	// Good key.
	findings = checkJWTKeyStrength(make([]byte, 32))
	assert.True(t, findings[0].Passed)
}

func TestCheckBcryptCost(t *testing.T) {
	findings := checkBcryptCost(0)
	assert.True(t, findings[0].Passed)

	findings = checkBcryptCost(8)
	assert.False(t, findings[0].Passed)

	findings = checkBcryptCost(12)
	assert.True(t, findings[0].Passed)
}

func TestCheckTokenExpiry(t *testing.T) {
	// Defaults (zero).
	findings := checkTokenExpiry(0, 0)
	assert.Len(t, findings, 2)
	assert.True(t, findings[0].Passed)
	assert.True(t, findings[1].Passed)

	// Too long access token.
	findings = checkTokenExpiry(2*time.Hour, 7*24*time.Hour)
	assert.False(t, findings[0].Passed)
	assert.Equal(t, SeverityHigh, findings[0].Severity)
	assert.True(t, findings[1].Passed)

	// Borderline access token.
	findings = checkTokenExpiry(45*time.Minute, 7*24*time.Hour)
	assert.False(t, findings[0].Passed)
	assert.Equal(t, SeverityMedium, findings[0].Severity)

	// Good access, too long refresh.
	findings = checkTokenExpiry(15*time.Minute, 60*24*time.Hour)
	assert.True(t, findings[0].Passed)
	assert.False(t, findings[1].Passed)
	assert.Equal(t, SeverityHigh, findings[1].Severity)
}

func TestCheckAntiEnumeration_NoBaseURL(t *testing.T) {
	findings := checkAntiEnumeration("")
	require.Len(t, findings, 1)
	assert.True(t, findings[0].Passed)
}

func TestCheckAntiEnumeration_Unreachable(t *testing.T) {
	findings := checkAntiEnumeration("http://localhost:1")
	require.Len(t, findings, 1)
	assert.True(t, findings[0].Passed) // skipped
}

func TestCheckAntiEnumeration_IdenticalErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(401)
		json.NewEncoder(w).Encode(map[string]string{"code": "invalid_credentials"})
	}))
	defer srv.Close()

	findings := checkAntiEnumeration(srv.URL)
	require.Len(t, findings, 1)
	assert.True(t, findings[0].Passed)
}

func TestCheckAntiEnumeration_DifferentErrors(t *testing.T) {
	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.Header().Set("Content-Type", "application/json")
		if callCount == 1 {
			w.WriteHeader(404)
			json.NewEncoder(w).Encode(map[string]string{"code": "user_not_found"})
		} else {
			w.WriteHeader(401)
			json.NewEncoder(w).Encode(map[string]string{"code": "wrong_password"})
		}
	}))
	defer srv.Close()

	findings := checkAntiEnumeration(srv.URL)
	require.Len(t, findings, 1)
	assert.False(t, findings[0].Passed)
}

// ──────────────────────────────────────────────
// Crypto Checks
// ──────────────────────────────────────────────

func TestCheckEncryptionKey(t *testing.T) {
	findings := checkEncryptionKey("")
	assert.False(t, findings[0].Passed)
	assert.Equal(t, SeverityCritical, findings[0].Severity)

	findings = checkEncryptionKey("some-key")
	assert.True(t, findings[0].Passed)
}

func TestCheckEncryptionKeyStrength(t *testing.T) {
	findings := checkEncryptionKeyStrength("")
	assert.True(t, findings[0].Passed) // skipped

	findings = checkEncryptionKeyStrength("short")
	assert.False(t, findings[0].Passed)
	assert.Equal(t, SeverityHigh, findings[0].Severity)

	findings = checkEncryptionKeyStrength("medium-key-16chars")
	assert.False(t, findings[0].Passed)
	assert.Equal(t, SeverityMedium, findings[0].Severity)

	findings = checkEncryptionKeyStrength("this-is-a-very-long-key-with-32-chars!")
	assert.True(t, findings[0].Passed)
}

func TestCheckTLSConfig(t *testing.T) {
	findings := checkTLSConfig(nil)
	assert.True(t, findings[0].Passed)

	findings = checkTLSConfig(&tls.Config{MinVersion: tls.VersionTLS10})
	assert.False(t, findings[0].Passed)

	findings = checkTLSConfig(&tls.Config{MinVersion: tls.VersionTLS12})
	assert.True(t, findings[0].Passed)

	findings = checkTLSConfig(&tls.Config{MinVersion: tls.VersionTLS13})
	assert.True(t, findings[0].Passed)
}

// ──────────────────────────────────────────────
// API Checks
// ──────────────────────────────────────────────

func TestCheckCORS_NoBaseURL(t *testing.T) {
	findings := checkCORS("", nil)
	assert.True(t, findings[0].Passed)
}

func TestCheckCORS_Unreachable(t *testing.T) {
	findings := checkCORS("http://localhost:1", nil)
	assert.True(t, findings[0].Passed)
}

func TestCheckCORS_WildcardOrigin(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.WriteHeader(200)
	}))
	defer srv.Close()

	findings := checkCORS(srv.URL, nil)
	assert.False(t, findings[0].Passed)
	assert.Contains(t, findings[0].Description, "all origins")
}

func TestCheckCORS_ReflectedOrigin(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", r.Header.Get("Origin"))
		w.WriteHeader(200)
	}))
	defer srv.Close()

	findings := checkCORS(srv.URL, nil)
	assert.False(t, findings[0].Passed)
	assert.Contains(t, findings[0].Description, "reflects arbitrary")
}

func TestCheckCORS_NoReflection(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer srv.Close()

	findings := checkCORS(srv.URL, nil)
	assert.True(t, findings[0].Passed)
}

func TestCheckSecurityHeaders_NoBaseURL(t *testing.T) {
	findings := checkSecurityHeaders("")
	assert.Len(t, findings, 1)
	assert.True(t, findings[0].Passed)
}

func TestCheckSecurityHeaders_AllPresent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Security-Policy", "default-src 'self'")
		w.Header().Set("Strict-Transport-Security", "max-age=31536000")
		w.Header().Set("X-XSS-Protection", "0")
		w.WriteHeader(200)
	}))
	defer srv.Close()

	findings := checkSecurityHeaders(srv.URL)
	assert.Len(t, findings, 5)
	for _, f := range findings {
		assert.True(t, f.Passed, "header finding %s should pass", f.Title)
	}
}

func TestCheckSecurityHeaders_Missing(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer srv.Close()

	findings := checkSecurityHeaders(srv.URL)
	assert.Len(t, findings, 5)
	for _, f := range findings {
		assert.False(t, f.Passed, "header finding %s should fail", f.Title)
	}
}

func TestCheckErrorSanitization_NoBaseURL(t *testing.T) {
	findings := checkErrorSanitization("")
	assert.True(t, findings[0].Passed)
}

func TestCheckErrorSanitization_Clean(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404)
		w.Write([]byte(`{"code":"not_found","message":"endpoint not found"}`))
	}))
	defer srv.Close()

	findings := checkErrorSanitization(srv.URL)
	assert.True(t, findings[0].Passed)
}

func TestCheckErrorSanitization_LeakyStackTrace(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
		w.Write([]byte(`goroutine 1 [running]: panic at /home/user/app/main.go:42`))
	}))
	defer srv.Close()

	findings := checkErrorSanitization(srv.URL)
	assert.False(t, findings[0].Passed)
}

func TestCheckContentTypeEnforcement_NoBaseURL(t *testing.T) {
	findings := checkContentTypeEnforcement("")
	assert.True(t, findings[0].Passed)
}

func TestCheckContentTypeEnforcement_Rejects(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Content-Type") != "application/json" {
			w.WriteHeader(400)
			return
		}
		w.WriteHeader(200)
	}))
	defer srv.Close()

	findings := checkContentTypeEnforcement(srv.URL)
	assert.True(t, findings[0].Passed)
}

func TestCheckContentTypeEnforcement_Accepts(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200) // accepts anything
	}))
	defer srv.Close()

	findings := checkContentTypeEnforcement(srv.URL)
	assert.False(t, findings[0].Passed)
}

// ──────────────────────────────────────────────
// Config Checks
// ──────────────────────────────────────────────

func TestCheckDebugMode(t *testing.T) {
	findings := checkDebugMode("debug", true)
	assert.False(t, findings[0].Passed)

	findings = checkDebugMode("trace", true)
	assert.False(t, findings[0].Passed)

	findings = checkDebugMode("info", true)
	assert.True(t, findings[0].Passed)

	findings = checkDebugMode("debug", false) // not prod
	assert.True(t, findings[0].Passed)
}

func TestCheckSensitiveEnv(t *testing.T) {
	os.Setenv("TEST_SECAUDIT_VAR", "value")
	defer os.Unsetenv("TEST_SECAUDIT_VAR")

	findings := checkSensitiveEnv([]string{"TEST_SECAUDIT_VAR", "NONEXISTENT_VAR_XYZ"})
	require.Len(t, findings, 2)
	assert.True(t, findings[0].Passed)
	assert.False(t, findings[1].Passed)
}

func TestCheckDefaultCredentials(t *testing.T) {
	// Weak values.
	findings := checkDefaultCredentials("password", "secret", "changeme")
	for _, f := range findings {
		assert.False(t, f.Passed, "finding %s should fail for weak value", f.Title)
		assert.Equal(t, SeverityCritical, f.Severity)
	}

	// Strong values.
	findings = checkDefaultCredentials("a1b2c3d4e5f6g7h8", "x9y8z7w6v5u4t3s2", "sk_live_abc123")
	for _, f := range findings {
		assert.True(t, f.Passed, "finding %s should pass for strong value", f.Title)
	}

	// Empty values.
	findings = checkDefaultCredentials("", "", "")
	for _, f := range findings {
		assert.True(t, f.Passed, "finding %s should pass for empty (not configured)", f.Title)
	}
}

// ──────────────────────────────────────────────
// Data Protection Checks
// ──────────────────────────────────────────────

func TestCheckGDPRCompliance(t *testing.T) {
	findings := checkGDPRCompliance(true, true, true)
	assert.Len(t, findings, 3)
	for _, f := range findings {
		assert.True(t, f.Passed)
	}

	findings = checkGDPRCompliance(false, false, false)
	for _, f := range findings {
		assert.False(t, f.Passed)
	}
}

func TestCheckAuditLogging(t *testing.T) {
	findings := checkAuditLogging(true)
	assert.True(t, findings[0].Passed)

	findings = checkAuditLogging(false)
	assert.False(t, findings[0].Passed)
}

func TestCheckBackupEncryption(t *testing.T) {
	findings := checkBackupEncryption(true)
	assert.True(t, findings[0].Passed)

	findings = checkBackupEncryption(false)
	assert.False(t, findings[0].Passed)
}

// ──────────────────────────────────────────────
// Rate Limit Checks
// ──────────────────────────────────────────────

func TestCheckRateLimiting_Disabled(t *testing.T) {
	findings := checkRateLimiting(false, "")
	assert.False(t, findings[0].Passed)
}

func TestCheckRateLimiting_Enabled(t *testing.T) {
	findings := checkRateLimiting(true, "")
	assert.True(t, findings[0].Passed)
}

func TestCheckRateLimiting_WithHeaders(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-RateLimit-Limit", "60")
		w.WriteHeader(200)
	}))
	defer srv.Close()

	findings := checkRateLimiting(true, srv.URL)
	assert.True(t, findings[0].Passed)
	assert.Contains(t, findings[0].Description, "limit headers")
}

func TestCheckLoginRateLimit(t *testing.T) {
	findings := checkLoginRateLimit(0)
	assert.False(t, findings[0].Passed)

	findings = checkLoginRateLimit(30)
	assert.False(t, findings[0].Passed)

	findings = checkLoginRateLimit(10)
	assert.True(t, findings[0].Passed)
}

// ──────────────────────────────────────────────
// Session Checks
// ──────────────────────────────────────────────

func TestCheckSessionTTL(t *testing.T) {
	// No TTL.
	findings := checkSessionTTL(0, 0)
	assert.Len(t, findings, 2)
	assert.False(t, findings[0].Passed)
	assert.False(t, findings[1].Passed)

	// Good TTL, good max.
	findings = checkSessionTTL(24*time.Hour, 10000)
	assert.True(t, findings[0].Passed)
	assert.True(t, findings[1].Passed)

	// Long TTL.
	findings = checkSessionTTL(30*24*time.Hour, 10000)
	assert.False(t, findings[0].Passed)
}

func TestCheckSessionIsolation(t *testing.T) {
	findings := checkSessionIsolation(true)
	assert.True(t, findings[0].Passed)

	findings = checkSessionIsolation(false)
	assert.False(t, findings[0].Passed)
}

// ──────────────────────────────────────────────
// Input Validation Checks
// ──────────────────────────────────────────────

func TestCheckSQLInjection(t *testing.T) {
	findings := checkSQLInjection(true)
	assert.True(t, findings[0].Passed)

	findings = checkSQLInjection(false)
	assert.False(t, findings[0].Passed)
}

func TestCheckCommandInjection(t *testing.T) {
	findings := checkCommandInjection(false, "")
	assert.False(t, findings[0].Passed)
	assert.Equal(t, SeverityCritical, findings[0].Severity)

	findings = checkCommandInjection(true, "container")
	assert.True(t, findings[0].Passed)

	findings = checkCommandInjection(true, "process")
	assert.True(t, findings[0].Passed)

	findings = checkCommandInjection(true, "none")
	assert.False(t, findings[0].Passed)
}

func TestCheckInputSizeLimits(t *testing.T) {
	findings := checkInputSizeLimits(0)
	assert.False(t, findings[0].Passed)

	findings = checkInputSizeLimits(200 * 1024 * 1024)
	assert.False(t, findings[0].Passed)

	findings = checkInputSizeLimits(1024 * 1024)
	assert.True(t, findings[0].Passed)
}

// ──────────────────────────────────────────────
// Handler
// ──────────────────────────────────────────────

func TestHandler_NilAuditor(t *testing.T) {
	h := Handler(nil)
	req := httptest.NewRequest("GET", "/api/v1/admin/security-audit", nil)
	w := httptest.NewRecorder()
	h(w, req)
	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
}

func TestHandler_MethodNotAllowed(t *testing.T) {
	h := Handler(NewAuditor())
	req := httptest.NewRequest("DELETE", "/api/v1/admin/security-audit", nil)
	w := httptest.NewRecorder()
	h(w, req)
	assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
}

func TestHandler_JSONFormat(t *testing.T) {
	a := NewAuditor()
	a.RegisterCheck(Check{
		ID: "H1", Name: "Test", Category: CategoryAuth,
		Fn: func() []Finding {
			return []Finding{{ID: "H1", Passed: true, Severity: SeverityInfo, Category: CategoryAuth}}
		},
	})

	h := Handler(a)
	req := httptest.NewRequest("GET", "/api/v1/admin/security-audit", nil)
	w := httptest.NewRecorder()
	h(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Header().Get("Content-Type"), "application/json")

	var report Report
	err := json.Unmarshal(w.Body.Bytes(), &report)
	require.NoError(t, err)
	assert.Equal(t, 1, report.ChecksRun)
}

func TestHandler_TextFormat(t *testing.T) {
	a := NewAuditor()
	a.RegisterCheck(Check{
		ID: "H2", Name: "Test", Category: CategoryAuth,
		Fn: func() []Finding {
			return []Finding{{ID: "H2", Passed: true, Severity: SeverityInfo, Category: CategoryAuth}}
		},
	})

	h := Handler(a)
	req := httptest.NewRequest("GET", "/api/v1/admin/security-audit?format=text", nil)
	w := httptest.NewRecorder()
	h(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Header().Get("Content-Type"), "text/plain")
	assert.Contains(t, w.Body.String(), "SECURITY AUDIT REPORT")
}

func TestHandler_CategoryFilter(t *testing.T) {
	a := NewAuditor()
	a.RegisterCheck(Check{
		ID: "A1", Name: "Auth", Category: CategoryAuth,
		Fn: func() []Finding {
			return []Finding{{ID: "A1", Passed: true, Severity: SeverityInfo, Category: CategoryAuth}}
		},
	})
	a.RegisterCheck(Check{
		ID: "C1", Name: "Crypto", Category: CategoryCrypto,
		Fn: func() []Finding {
			return []Finding{{ID: "C1", Passed: true, Severity: SeverityInfo, Category: CategoryCrypto}}
		},
	})

	h := Handler(a)
	req := httptest.NewRequest("GET", "/api/v1/admin/security-audit?categories=authentication", nil)
	w := httptest.NewRecorder()
	h(w, req)

	var report Report
	json.Unmarshal(w.Body.Bytes(), &report)
	assert.Equal(t, 1, report.ChecksRun)
}

func TestRegisterRoutes(t *testing.T) {
	mux := http.NewServeMux()
	RegisterRoutes(mux, NewAuditor())

	req := httptest.NewRequest("GET", "/api/v1/admin/security-audit", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// ──────────────────────────────────────────────
// RegisterAllChecks
// ──────────────────────────────────────────────

func TestRegisterAllChecks(t *testing.T) {
	a := NewAuditor()
	cfg := DefaultAuditConfig{
		Auth: AuthCheckConfig{
			JWTSigningKey:   make([]byte, 32),
			BcryptCost:      12,
			AccessTokenTTL:  15 * time.Minute,
			RefreshTokenTTL: 7 * 24 * time.Hour,
		},
		Crypto: CryptoCheckConfig{
			EncryptionKey: "a-very-long-encryption-key-32chars!",
		},
		DataProtection: DataProtectionConfig{
			HasExportEndpoint:  true,
			HasErasureEndpoint: true,
			HasRetentionPolicy: true,
			AuditEnabled:       true,
			BackupsEncrypted:   true,
		},
		RateLimit: RateLimitConfig{
			Enabled:             true,
			LoginLimitPerMinute: 10,
		},
		Session: SessionCheckConfig{
			TTL:             24 * time.Hour,
			MaxSessions:     10000,
			TenantIsolation: true,
		},
		Input: InputCheckConfig{
			UsesParameterizedQueries: true,
			HasSandbox:               true,
			SandboxLevel:             "container",
			MaxRequestBodyBytes:      1024 * 1024,
		},
	}

	err := RegisterAllChecks(a, cfg)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, a.CheckCount(), 20)
}

func TestRegisterAllChecks_FullAuditRun(t *testing.T) {
	a := NewAuditor()
	cfg := DefaultAuditConfig{
		Auth: AuthCheckConfig{
			JWTSigningKey:   make([]byte, 64),
			BcryptCost:      12,
			AccessTokenTTL:  15 * time.Minute,
			RefreshTokenTTL: 7 * 24 * time.Hour,
		},
		Crypto: CryptoCheckConfig{
			EncryptionKey: "this-is-a-very-strong-key-with-enough-characters",
		},
		Config: ConfigCheckConfig{
			LogLevel:     "info",
			IsProduction: true,
		},
		DataProtection: DataProtectionConfig{
			HasExportEndpoint:  true,
			HasErasureEndpoint: true,
			HasRetentionPolicy: true,
			AuditEnabled:       true,
			BackupsEncrypted:   true,
		},
		RateLimit: RateLimitConfig{
			Enabled:             true,
			LoginLimitPerMinute: 10,
		},
		Session: SessionCheckConfig{
			TTL:             24 * time.Hour,
			MaxSessions:     10000,
			TenantIsolation: true,
		},
		Input: InputCheckConfig{
			UsesParameterizedQueries: true,
			HasSandbox:               true,
			SandboxLevel:             "container",
			MaxRequestBodyBytes:      1024 * 1024,
		},
	}

	err := RegisterAllChecks(a, cfg)
	require.NoError(t, err)

	report := a.Run()
	assert.Greater(t, report.ChecksRun, 0)
	assert.Greater(t, len(report.Findings), 0)
	assert.GreaterOrEqual(t, report.PassRate, 0.0)
	assert.LessOrEqual(t, report.RiskScore, 100.0)

	// With good config, most should pass.
	assert.Greater(t, report.Summary.Passed, report.Summary.Failed,
		"With good config, more checks should pass than fail")
}

// ──────────────────────────────────────────────
// AuthChecks factory
// ──────────────────────────────────────────────

func TestAuthChecksFactory(t *testing.T) {
	checks := AuthChecks(AuthCheckConfig{})
	assert.Len(t, checks, 4)
	for _, c := range checks {
		assert.NotEmpty(t, c.ID)
		assert.NotEmpty(t, c.Name)
		assert.Equal(t, CategoryAuth, c.Category)
		assert.NotNil(t, c.Fn)
	}
}

func TestCryptoChecksFactory(t *testing.T) {
	checks := CryptoChecks(CryptoCheckConfig{})
	assert.Len(t, checks, 3)
	for _, c := range checks {
		assert.Equal(t, CategoryCrypto, c.Category)
	}
}

func TestAPIChecksFactory(t *testing.T) {
	checks := APIChecks(APICheckConfig{})
	assert.Len(t, checks, 4)
}

func TestConfigChecksFactory(t *testing.T) {
	checks := ConfigChecks(ConfigCheckConfig{})
	assert.Len(t, checks, 3)
}

func TestDataProtectionChecksFactory(t *testing.T) {
	checks := DataProtectionChecks(DataProtectionConfig{})
	assert.Len(t, checks, 3)
}

func TestRateLimitChecksFactory(t *testing.T) {
	checks := RateLimitChecks(RateLimitConfig{})
	assert.Len(t, checks, 2)
}

func TestSessionChecksFactory(t *testing.T) {
	checks := SessionChecks(SessionCheckConfig{})
	assert.Len(t, checks, 2)
}

func TestInputValidationChecksFactory(t *testing.T) {
	checks := InputValidationChecks(InputCheckConfig{})
	assert.Len(t, checks, 3)
}

// ──────────────────────────────────────────────
// Edge Cases
// ──────────────────────────────────────────────

func TestRunWithNoChecks(t *testing.T) {
	a := NewAuditor()
	report := a.Run()
	assert.Equal(t, 0, report.ChecksRun)
	assert.Len(t, report.Findings, 0)
	assert.Equal(t, 0.0, report.RiskScore)
	assert.Equal(t, 100.0, report.PassRate)
}

func TestEmptyReport(t *testing.T) {
	r := &Report{}
	assert.Nil(t, r.FailedFindings())
	assert.Nil(t, r.FindingsByCategory(CategoryAuth))
	assert.Nil(t, r.FindingsBySeverity(SeverityCritical))
	assert.False(t, r.HasCritical())
}

func TestFindingReferences(t *testing.T) {
	f := Finding{
		References: []string{"CWE-89", "OWASP A03:2021"},
	}
	assert.Len(t, f.References, 2)
}

func TestFindingJSON(t *testing.T) {
	f := Finding{
		ID:          "TEST-001",
		Category:    CategoryAuth,
		Severity:    SeverityHigh,
		Title:       "Test finding",
		Description: "A test",
		Location:    "pkg/test",
		Evidence:    "some evidence",
		Remediation: "fix it",
		References:  []string{"CWE-123"},
		Passed:      false,
	}
	data, err := json.Marshal(f)
	require.NoError(t, err)

	var parsed Finding
	err = json.Unmarshal(data, &parsed)
	require.NoError(t, err)
	assert.Equal(t, f.ID, parsed.ID)
	assert.Equal(t, f.Category, parsed.Category)
	assert.Equal(t, f.Severity, parsed.Severity)
	assert.Equal(t, f.Location, parsed.Location)
	assert.Equal(t, f.Evidence, parsed.Evidence)
}

func TestMultipleFindingsPerCheck(t *testing.T) {
	a := NewAuditor()
	a.RegisterCheck(Check{
		ID: "MULTI", Name: "Multi", Category: CategoryAuth,
		Fn: func() []Finding {
			return []Finding{
				{ID: "M1", Passed: true, Severity: SeverityInfo, Category: CategoryAuth},
				{ID: "M2", Passed: false, Severity: SeverityHigh, Category: CategoryAuth},
				{ID: "M3", Passed: false, Severity: SeverityCritical, Category: CategoryAuth},
			}
		},
	})

	report := a.Run()
	assert.Len(t, report.Findings, 3)
	// Sorted by severity.
	assert.Equal(t, SeverityCritical, report.Findings[0].Severity)
	assert.Equal(t, SeverityHigh, report.Findings[1].Severity)
}

func TestConcurrentAudit(t *testing.T) {
	a := NewAuditor()
	for i := 0; i < 10; i++ {
		id := fmt.Sprintf("CONC-%d", i)
		a.RegisterCheck(Check{
			ID: id, Name: id, Category: CategoryAuth,
			Fn: func() []Finding {
				return []Finding{{ID: id, Passed: true, Severity: SeverityInfo, Category: CategoryAuth}}
			},
		})
	}

	report := a.Run()
	assert.Equal(t, 10, report.ChecksRun)
	assert.Len(t, report.Findings, 10)
}

func TestHandler_POST(t *testing.T) {
	a := NewAuditor()
	a.RegisterCheck(Check{
		ID: "P1", Name: "Test", Category: CategoryAuth,
		Fn: func() []Finding {
			return []Finding{{ID: "P1", Passed: true, Severity: SeverityInfo, Category: CategoryAuth}}
		},
	})

	h := Handler(a)
	req := httptest.NewRequest("POST", "/api/v1/admin/security-audit", nil)
	w := httptest.NewRecorder()
	h(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

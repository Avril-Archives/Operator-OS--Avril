// Package secaudit provides an automated security audit framework for Operator OS.
// It performs comprehensive security checks covering OWASP Top 10, API security,
// configuration validation, authentication/authorization patterns, input validation,
// and cryptographic practices. Results are structured for both programmatic consumption
// and human-readable reporting.
package secaudit

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Severity levels for audit findings.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// ValidSeverity returns true if the severity is recognized.
func ValidSeverity(s Severity) bool {
	switch s {
	case SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow, SeverityInfo:
		return true
	}
	return false
}

// severityOrder returns a numeric ordering for severity (lower = more severe).
func severityOrder(s Severity) int {
	switch s {
	case SeverityCritical:
		return 0
	case SeverityHigh:
		return 1
	case SeverityMedium:
		return 2
	case SeverityLow:
		return 3
	case SeverityInfo:
		return 4
	default:
		return 5
	}
}

// Category groups related security checks.
type Category string

const (
	CategoryAuth       Category = "authentication"
	CategoryAuthz      Category = "authorization"
	CategoryInput      Category = "input_validation"
	CategoryCrypto     Category = "cryptography"
	CategorySession    Category = "session_management"
	CategoryAPI        Category = "api_security"
	CategoryConfig     Category = "configuration"
	CategoryData       Category = "data_protection"
	CategoryRateLimit  Category = "rate_limiting"
	CategoryHeaders    Category = "security_headers"
	CategoryInjection  Category = "injection"
	CategoryCompliance Category = "compliance"
)

// ValidCategory returns true if the category is recognized.
func ValidCategory(c Category) bool {
	switch c {
	case CategoryAuth, CategoryAuthz, CategoryInput, CategoryCrypto,
		CategorySession, CategoryAPI, CategoryConfig, CategoryData,
		CategoryRateLimit, CategoryHeaders, CategoryInjection, CategoryCompliance:
		return true
	}
	return false
}

// AllCategories returns all recognized categories in sorted order.
func AllCategories() []Category {
	cats := []Category{
		CategoryAuth, CategoryAuthz, CategoryInput, CategoryCrypto,
		CategorySession, CategoryAPI, CategoryConfig, CategoryData,
		CategoryRateLimit, CategoryHeaders, CategoryInjection, CategoryCompliance,
	}
	sort.Slice(cats, func(i, j int) bool { return cats[i] < cats[j] })
	return cats
}

// Finding represents a single security audit finding.
type Finding struct {
	ID          string   `json:"id"`
	Category    Category `json:"category"`
	Severity    Severity `json:"severity"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Location    string   `json:"location,omitempty"`    // file path, endpoint, etc.
	Evidence    string   `json:"evidence,omitempty"`    // specific evidence
	Remediation string   `json:"remediation,omitempty"` // how to fix
	References  []string `json:"references,omitempty"`  // CWE/OWASP references
	Passed      bool     `json:"passed"`                // true = check passed (no issue)
}

// CheckFunc is a function that performs a security check and returns findings.
type CheckFunc func() []Finding

// Check represents a registered security check.
type Check struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Category    Category `json:"category"`
	Description string   `json:"description"`
	Fn          CheckFunc
}

// Auditor orchestrates security checks and produces reports.
type Auditor struct {
	checks     []Check
	categories map[Category]bool // filter to specific categories if set
}

// NewAuditor creates a new security auditor.
func NewAuditor() *Auditor {
	return &Auditor{
		categories: make(map[Category]bool),
	}
}

// RegisterCheck adds a security check to the auditor.
func (a *Auditor) RegisterCheck(c Check) error {
	if c.ID == "" {
		return fmt.Errorf("secaudit: check ID is required")
	}
	if c.Name == "" {
		return fmt.Errorf("secaudit: check name is required")
	}
	if c.Fn == nil {
		return fmt.Errorf("secaudit: check function is required")
	}
	if !ValidCategory(c.Category) {
		return fmt.Errorf("secaudit: invalid category %q", c.Category)
	}
	for _, existing := range a.checks {
		if existing.ID == c.ID {
			return fmt.Errorf("secaudit: duplicate check ID %q", c.ID)
		}
	}
	a.checks = append(a.checks, c)
	return nil
}

// FilterCategories restricts the audit to specific categories.
// If not called (or called with empty slice), all categories are included.
func (a *Auditor) FilterCategories(cats ...Category) {
	a.categories = make(map[Category]bool)
	for _, c := range cats {
		a.categories[c] = true
	}
}

// CheckCount returns the number of registered checks.
func (a *Auditor) CheckCount() int {
	return len(a.checks)
}

// Run executes all registered checks (optionally filtered) and returns a report.
func (a *Auditor) Run() *Report {
	start := time.Now()
	var findings []Finding
	checksRun := 0

	for _, check := range a.checks {
		if len(a.categories) > 0 && !a.categories[check.Category] {
			continue
		}
		checksRun++
		results := check.Fn()
		findings = append(findings, results...)
	}

	// Sort findings by severity (most severe first), then by category.
	sort.Slice(findings, func(i, j int) bool {
		si, sj := severityOrder(findings[i].Severity), severityOrder(findings[j].Severity)
		if si != sj {
			return si < sj
		}
		return findings[i].Category < findings[j].Category
	})

	report := &Report{
		Timestamp:  time.Now().UTC(),
		Duration:   time.Since(start),
		ChecksRun:  checksRun,
		Findings:   findings,
		Summary:    computeSummary(findings),
		RiskScore:  computeRiskScore(findings),
		PassRate:   computePassRate(findings),
		Categories: computeCategorySummaries(findings),
	}

	return report
}

// Report is the output of a security audit.
type Report struct {
	Timestamp  time.Time                  `json:"timestamp"`
	Duration   time.Duration              `json:"duration"`
	ChecksRun  int                        `json:"checks_run"`
	Findings   []Finding                  `json:"findings"`
	Summary    Summary                    `json:"summary"`
	RiskScore  float64                    `json:"risk_score"`  // 0-100, lower = better
	PassRate   float64                    `json:"pass_rate"`   // 0-100%
	Categories map[Category]CategoryStats `json:"categories"`
}

// Summary counts findings by severity.
type Summary struct {
	Total    int `json:"total"`
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Info     int `json:"info"`
	Passed   int `json:"passed"`
	Failed   int `json:"failed"`
}

// CategoryStats summarizes findings for a single category.
type CategoryStats struct {
	Total  int `json:"total"`
	Passed int `json:"passed"`
	Failed int `json:"failed"`
}

// FailedFindings returns only findings that did not pass.
func (r *Report) FailedFindings() []Finding {
	var failed []Finding
	for _, f := range r.Findings {
		if !f.Passed {
			failed = append(failed, f)
		}
	}
	return failed
}

// FindingsByCategory returns findings filtered to a specific category.
func (r *Report) FindingsByCategory(cat Category) []Finding {
	var result []Finding
	for _, f := range r.Findings {
		if f.Category == cat {
			result = append(result, f)
		}
	}
	return result
}

// FindingsBySeverity returns findings at a specific severity level.
func (r *Report) FindingsBySeverity(sev Severity) []Finding {
	var result []Finding
	for _, f := range r.Findings {
		if f.Severity == sev {
			result = append(result, f)
		}
	}
	return result
}

// HasCritical returns true if there are any critical findings that failed.
func (r *Report) HasCritical() bool {
	for _, f := range r.Findings {
		if f.Severity == SeverityCritical && !f.Passed {
			return true
		}
	}
	return false
}

// JSON returns the report as indented JSON.
func (r *Report) JSON() ([]byte, error) {
	return json.MarshalIndent(r, "", "  ")
}

// TextReport returns a human-readable text summary of the report.
func (r *Report) TextReport() string {
	var b strings.Builder
	b.WriteString("═══════════════════════════════════════════════\n")
	b.WriteString("  OPERATOR OS SECURITY AUDIT REPORT\n")
	b.WriteString("═══════════════════════════════════════════════\n\n")
	fmt.Fprintf(&b, "  Timestamp:  %s\n", r.Timestamp.Format(time.RFC3339))
	fmt.Fprintf(&b, "  Duration:   %s\n", r.Duration.Round(time.Millisecond))
	fmt.Fprintf(&b, "  Checks Run: %d\n", r.ChecksRun)
	fmt.Fprintf(&b, "  Risk Score: %.1f/100 (lower is better)\n", r.RiskScore)
	fmt.Fprintf(&b, "  Pass Rate:  %.1f%%\n\n", r.PassRate)

	b.WriteString("  SUMMARY\n")
	b.WriteString("  ───────\n")
	fmt.Fprintf(&b, "  Total: %d  |  Passed: %d  |  Failed: %d\n", r.Summary.Total, r.Summary.Passed, r.Summary.Failed)
	fmt.Fprintf(&b, "  Critical: %d  |  High: %d  |  Medium: %d  |  Low: %d  |  Info: %d\n\n", r.Summary.Critical, r.Summary.High, r.Summary.Medium, r.Summary.Low, r.Summary.Info)

	failed := r.FailedFindings()
	if len(failed) > 0 {
		b.WriteString("  FAILED CHECKS\n")
		b.WriteString("  ─────────────\n")
		for _, f := range failed {
			fmt.Fprintf(&b, "  [%s] %s — %s\n", strings.ToUpper(string(f.Severity)), f.ID, f.Title)
			if f.Description != "" {
				fmt.Fprintf(&b, "    %s\n", f.Description)
			}
			if f.Location != "" {
				fmt.Fprintf(&b, "    Location: %s\n", f.Location)
			}
			if f.Remediation != "" {
				fmt.Fprintf(&b, "    Fix: %s\n", f.Remediation)
			}
			b.WriteString("\n")
		}
	}

	return b.String()
}

func computeSummary(findings []Finding) Summary {
	var s Summary
	s.Total = len(findings)
	for _, f := range findings {
		if f.Passed {
			s.Passed++
		} else {
			s.Failed++
		}
		switch f.Severity {
		case SeverityCritical:
			s.Critical++
		case SeverityHigh:
			s.High++
		case SeverityMedium:
			s.Medium++
		case SeverityLow:
			s.Low++
		case SeverityInfo:
			s.Info++
		}
	}
	return s
}

func computeRiskScore(findings []Finding) float64 {
	if len(findings) == 0 {
		return 0
	}
	score := 0.0
	for _, f := range findings {
		if f.Passed {
			continue
		}
		switch f.Severity {
		case SeverityCritical:
			score += 25.0
		case SeverityHigh:
			score += 15.0
		case SeverityMedium:
			score += 8.0
		case SeverityLow:
			score += 3.0
		case SeverityInfo:
			score += 1.0
		}
	}
	if score > 100 {
		score = 100
	}
	return score
}

func computePassRate(findings []Finding) float64 {
	if len(findings) == 0 {
		return 100
	}
	passed := 0
	for _, f := range findings {
		if f.Passed {
			passed++
		}
	}
	return float64(passed) / float64(len(findings)) * 100
}

func computeCategorySummaries(findings []Finding) map[Category]CategoryStats {
	cats := make(map[Category]CategoryStats)
	for _, f := range findings {
		cs := cats[f.Category]
		cs.Total++
		if f.Passed {
			cs.Passed++
		} else {
			cs.Failed++
		}
		cats[f.Category] = cs
	}
	return cats
}

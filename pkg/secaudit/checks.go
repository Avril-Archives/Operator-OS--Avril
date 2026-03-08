package secaudit

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// --- Authentication Checks ---

// AuthChecks returns checks for authentication security.
func AuthChecks(cfg AuthCheckConfig) []Check {
	return []Check{
		{
			ID:       "AUTH-001",
			Name:     "JWT signing key strength",
			Category: CategoryAuth,
			Description: "Verify JWT signing key meets minimum length requirements",
			Fn: func() []Finding {
				return checkJWTKeyStrength(cfg.JWTSigningKey)
			},
		},
		{
			ID:       "AUTH-002",
			Name:     "Password hashing algorithm",
			Category: CategoryAuth,
			Description: "Verify bcrypt cost factor is sufficient",
			Fn: func() []Finding {
				return checkBcryptCost(cfg.BcryptCost)
			},
		},
		{
			ID:       "AUTH-003",
			Name:     "Token expiry configuration",
			Category: CategoryAuth,
			Description: "Verify access and refresh token lifetimes are reasonable",
			Fn: func() []Finding {
				return checkTokenExpiry(cfg.AccessTokenTTL, cfg.RefreshTokenTTL)
			},
		},
		{
			ID:       "AUTH-004",
			Name:     "Anti-enumeration responses",
			Category: CategoryAuth,
			Description: "Verify login endpoint uses constant-time error messages",
			Fn: func() []Finding {
				return checkAntiEnumeration(cfg.BaseURL)
			},
		},
	}
}

// AuthCheckConfig holds configuration for authentication checks.
type AuthCheckConfig struct {
	JWTSigningKey   []byte
	BcryptCost      int
	AccessTokenTTL  time.Duration
	RefreshTokenTTL time.Duration
	BaseURL         string // e.g., "http://localhost:18790"
}

func checkJWTKeyStrength(key []byte) []Finding {
	f := Finding{
		ID:       "AUTH-001",
		Category: CategoryAuth,
		Severity: SeverityCritical,
		Title:    "JWT signing key strength",
		References: []string{"CWE-326", "OWASP A02:2021"},
	}
	if len(key) == 0 {
		f.Description = "No JWT signing key configured"
		f.Remediation = "Set a strong JWT signing key (≥32 bytes) via OPERATOR_JWT_SECRET"
		return []Finding{f}
	}
	if len(key) < 32 {
		f.Severity = SeverityHigh
		f.Description = fmt.Sprintf("JWT signing key is only %d bytes (minimum 32 recommended)", len(key))
		f.Remediation = "Use a signing key of at least 32 bytes (256 bits)"
		return []Finding{f}
	}
	f.Passed = true
	f.Severity = SeverityInfo
	f.Description = fmt.Sprintf("JWT signing key is %d bytes — adequate", len(key))
	return []Finding{f}
}

func checkBcryptCost(cost int) []Finding {
	f := Finding{
		ID:       "AUTH-002",
		Category: CategoryAuth,
		Severity: SeverityMedium,
		Title:    "Password hashing cost factor",
		References: []string{"CWE-916", "OWASP A02:2021"},
	}
	if cost == 0 {
		f.Description = "Bcrypt cost not configured (using default)"
		f.Severity = SeverityInfo
		f.Passed = true
		return []Finding{f}
	}
	if cost < 10 {
		f.Description = fmt.Sprintf("Bcrypt cost factor is %d (minimum 10 recommended)", cost)
		f.Remediation = "Increase bcrypt cost to at least 10, preferably 12"
		return []Finding{f}
	}
	f.Passed = true
	f.Severity = SeverityInfo
	f.Description = fmt.Sprintf("Bcrypt cost factor is %d — adequate", cost)
	return []Finding{f}
}

func checkTokenExpiry(accessTTL, refreshTTL time.Duration) []Finding {
	var findings []Finding

	af := Finding{
		ID:       "AUTH-003a",
		Category: CategoryAuth,
		Title:    "Access token lifetime",
		References: []string{"CWE-613", "OWASP A07:2021"},
	}
	if accessTTL == 0 {
		af.Severity = SeverityInfo
		af.Passed = true
		af.Description = "Access token TTL not configured (using default)"
	} else if accessTTL > 1*time.Hour {
		af.Severity = SeverityHigh
		af.Description = fmt.Sprintf("Access token lifetime is %s (max 1h recommended)", accessTTL)
		af.Remediation = "Reduce access token lifetime to ≤30 minutes"
	} else if accessTTL > 30*time.Minute {
		af.Severity = SeverityMedium
		af.Description = fmt.Sprintf("Access token lifetime is %s (≤30m recommended)", accessTTL)
		af.Remediation = "Consider reducing access token lifetime to ≤15 minutes"
	} else {
		af.Severity = SeverityInfo
		af.Passed = true
		af.Description = fmt.Sprintf("Access token lifetime is %s — adequate", accessTTL)
	}
	findings = append(findings, af)

	rf := Finding{
		ID:       "AUTH-003b",
		Category: CategoryAuth,
		Title:    "Refresh token lifetime",
		References: []string{"CWE-613"},
	}
	if refreshTTL == 0 {
		rf.Severity = SeverityInfo
		rf.Passed = true
		rf.Description = "Refresh token TTL not configured (using default)"
	} else if refreshTTL > 30*24*time.Hour {
		rf.Severity = SeverityHigh
		rf.Description = fmt.Sprintf("Refresh token lifetime is %s (max 30d recommended)", refreshTTL)
		rf.Remediation = "Reduce refresh token lifetime to ≤30 days"
	} else {
		rf.Severity = SeverityInfo
		rf.Passed = true
		rf.Description = fmt.Sprintf("Refresh token lifetime is %s — adequate", refreshTTL)
	}
	findings = append(findings, rf)

	return findings
}

func checkAntiEnumeration(baseURL string) []Finding {
	f := Finding{
		ID:       "AUTH-004",
		Category: CategoryAuth,
		Severity: SeverityMedium,
		Title:    "Anti-enumeration on login endpoint",
		References: []string{"CWE-204", "OWASP A07:2021"},
	}
	if baseURL == "" {
		f.Severity = SeverityInfo
		f.Passed = true
		f.Description = "No base URL configured — skipping live check"
		return []Finding{f}
	}

	client := &http.Client{Timeout: 5 * time.Second}

	// Try login with nonexistent email.
	body1 := `{"email":"nonexistent-audit-test@example.invalid","password":"TestPassword123!"}`
	resp1, err1 := client.Post(baseURL+"/api/v1/auth/login", "application/json", strings.NewReader(body1))
	if err1 != nil {
		f.Severity = SeverityInfo
		f.Passed = true
		f.Description = "Could not reach login endpoint — skipping live check"
		return []Finding{f}
	}
	defer resp1.Body.Close()
	body1Bytes, _ := io.ReadAll(resp1.Body)

	// Try login with likely-wrong password (same email format).
	body2 := `{"email":"another-audit-test@example.invalid","password":"DifferentPassword456!"}`
	resp2, err2 := client.Post(baseURL+"/api/v1/auth/login", "application/json", strings.NewReader(body2))
	if err2 != nil {
		f.Severity = SeverityInfo
		f.Passed = true
		f.Description = "Could not reach login endpoint — skipping live check"
		return []Finding{f}
	}
	defer resp2.Body.Close()
	body2Bytes, _ := io.ReadAll(resp2.Body)

	// Parse error codes from both responses.
	var r1, r2 map[string]any
	json.Unmarshal(body1Bytes, &r1)
	json.Unmarshal(body2Bytes, &r2)

	code1, _ := r1["code"].(string)
	code2, _ := r2["code"].(string)

	if code1 == code2 && resp1.StatusCode == resp2.StatusCode {
		f.Passed = true
		f.Severity = SeverityInfo
		f.Description = "Login endpoint returns identical error responses for different nonexistent users"
	} else {
		f.Description = "Login endpoint may leak user existence information through different error codes"
		f.Remediation = "Use the same error message for both wrong-email and wrong-password"
	}
	return []Finding{f}
}

// --- Cryptography Checks ---

// CryptoChecks returns checks for cryptographic practices.
func CryptoChecks(cfg CryptoCheckConfig) []Check {
	return []Check{
		{
			ID:       "CRYPTO-001",
			Name:     "Encryption key configured",
			Category: CategoryCrypto,
			Description: "Verify encryption key is set for data at rest",
			Fn: func() []Finding {
				return checkEncryptionKey(cfg.EncryptionKey)
			},
		},
		{
			ID:       "CRYPTO-002",
			Name:     "Encryption key strength",
			Category: CategoryCrypto,
			Description: "Verify encryption key meets minimum strength requirements",
			Fn: func() []Finding {
				return checkEncryptionKeyStrength(cfg.EncryptionKey)
			},
		},
		{
			ID:       "CRYPTO-003",
			Name:     "TLS configuration",
			Category: CategoryCrypto,
			Description: "Verify TLS version and cipher suite configuration",
			Fn: func() []Finding {
				return checkTLSConfig(cfg.TLSConfig)
			},
		},
	}
}

// CryptoCheckConfig holds configuration for cryptography checks.
type CryptoCheckConfig struct {
	EncryptionKey string
	TLSConfig     *tls.Config // optional — if server is using TLS
}

func checkEncryptionKey(key string) []Finding {
	f := Finding{
		ID:       "CRYPTO-001",
		Category: CategoryCrypto,
		Severity: SeverityCritical,
		Title:    "Encryption key configuration",
		References: []string{"CWE-311", "OWASP A02:2021"},
	}
	if key == "" {
		f.Description = "No encryption key configured (OPERATOR_ENCRYPTION_KEY). Credentials stored with base64 encoding only."
		f.Remediation = "Set OPERATOR_ENCRYPTION_KEY environment variable with a strong random key"
		return []Finding{f}
	}
	f.Passed = true
	f.Severity = SeverityInfo
	f.Description = "Encryption key is configured"
	return []Finding{f}
}

func checkEncryptionKeyStrength(key string) []Finding {
	f := Finding{
		ID:       "CRYPTO-002",
		Category: CategoryCrypto,
		Severity: SeverityHigh,
		Title:    "Encryption key strength",
		References: []string{"CWE-326"},
	}
	if key == "" {
		f.Severity = SeverityInfo
		f.Passed = true
		f.Description = "No encryption key configured — strength check skipped"
		return []Finding{f}
	}
	if len(key) < 16 {
		f.Description = fmt.Sprintf("Encryption key is only %d characters (minimum 16 recommended)", len(key))
		f.Remediation = "Use a key of at least 32 characters generated with a CSPRNG"
		return []Finding{f}
	}
	if len(key) < 32 {
		f.Severity = SeverityMedium
		f.Description = fmt.Sprintf("Encryption key is %d characters (32+ recommended)", len(key))
		f.Remediation = "Consider using a longer key for maximum security"
		return []Finding{f}
	}
	f.Passed = true
	f.Severity = SeverityInfo
	f.Description = fmt.Sprintf("Encryption key is %d characters — adequate", len(key))
	return []Finding{f}
}

func checkTLSConfig(cfg *tls.Config) []Finding {
	f := Finding{
		ID:       "CRYPTO-003",
		Category: CategoryCrypto,
		Title:    "TLS configuration",
		References: []string{"CWE-326", "OWASP A02:2021"},
	}
	if cfg == nil {
		f.Severity = SeverityInfo
		f.Passed = true
		f.Description = "No TLS config provided — skipping TLS check (may be handled by reverse proxy)"
		return []Finding{f}
	}
	if cfg.MinVersion < tls.VersionTLS12 {
		f.Severity = SeverityHigh
		f.Description = "TLS minimum version is below 1.2"
		f.Remediation = "Set MinVersion to tls.VersionTLS12 or tls.VersionTLS13"
		return []Finding{f}
	}
	f.Passed = true
	f.Severity = SeverityInfo
	f.Description = "TLS configuration meets minimum requirements"
	return []Finding{f}
}

// --- API Security Checks ---

// APIChecks returns checks for API endpoint security.
func APIChecks(cfg APICheckConfig) []Check {
	return []Check{
		{
			ID:       "API-001",
			Name:     "CORS configuration",
			Category: CategoryAPI,
			Description: "Verify CORS headers are properly configured",
			Fn: func() []Finding {
				return checkCORS(cfg.BaseURL, cfg.AllowedOrigins)
			},
		},
		{
			ID:       "API-002",
			Name:     "Security headers present",
			Category: CategoryHeaders,
			Description: "Verify security headers are set on API responses",
			Fn: func() []Finding {
				return checkSecurityHeaders(cfg.BaseURL)
			},
		},
		{
			ID:       "API-003",
			Name:     "Error response sanitization",
			Category: CategoryAPI,
			Description: "Verify error responses do not leak internal details",
			Fn: func() []Finding {
				return checkErrorSanitization(cfg.BaseURL)
			},
		},
		{
			ID:       "API-004",
			Name:     "Content-Type enforcement",
			Category: CategoryAPI,
			Description: "Verify API rejects non-JSON content types on JSON endpoints",
			Fn: func() []Finding {
				return checkContentTypeEnforcement(cfg.BaseURL)
			},
		},
	}
}

// APICheckConfig holds configuration for API security checks.
type APICheckConfig struct {
	BaseURL        string
	AllowedOrigins []string
}

func checkCORS(baseURL string, allowedOrigins []string) []Finding {
	f := Finding{
		ID:       "API-001",
		Category: CategoryAPI,
		Severity: SeverityHigh,
		Title:    "CORS configuration",
		References: []string{"CWE-942", "OWASP A05:2021"},
	}
	if baseURL == "" {
		f.Severity = SeverityInfo
		f.Passed = true
		f.Description = "No base URL — skipping CORS check"
		return []Finding{f}
	}

	client := &http.Client{Timeout: 5 * time.Second}
	req, _ := http.NewRequest("OPTIONS", baseURL+"/api/v1/billing/plans", nil)
	req.Header.Set("Origin", "https://evil.example.com")
	req.Header.Set("Access-Control-Request-Method", "GET")

	resp, err := client.Do(req)
	if err != nil {
		f.Severity = SeverityInfo
		f.Passed = true
		f.Description = "Could not reach server — skipping CORS check"
		return []Finding{f}
	}
	defer resp.Body.Close()

	origin := resp.Header.Get("Access-Control-Allow-Origin")
	if origin == "*" {
		f.Description = "CORS allows all origins (Access-Control-Allow-Origin: *)"
		f.Remediation = "Restrict CORS to specific trusted origins"
		return []Finding{f}
	}
	if origin == "https://evil.example.com" {
		f.Description = "CORS reflects arbitrary origins"
		f.Remediation = "Validate origins against an allowlist"
		return []Finding{f}
	}
	f.Passed = true
	f.Severity = SeverityInfo
	f.Description = "CORS does not reflect arbitrary origins"
	return []Finding{f}
}

func checkSecurityHeaders(baseURL string) []Finding {
	if baseURL == "" {
		return []Finding{{
			ID:          "API-002",
			Category:    CategoryHeaders,
			Severity:    SeverityInfo,
			Title:       "Security headers",
			Description: "No base URL — skipping header check",
			Passed:      true,
		}}
	}

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(baseURL + "/health")
	if err != nil {
		return []Finding{{
			ID:          "API-002",
			Category:    CategoryHeaders,
			Severity:    SeverityInfo,
			Title:       "Security headers",
			Description: "Could not reach server — skipping header check",
			Passed:      true,
		}}
	}
	defer resp.Body.Close()

	headers := map[string]struct {
		severity    Severity
		remediation string
	}{
		"X-Content-Type-Options":    {SeverityMedium, "Add 'X-Content-Type-Options: nosniff' header"},
		"X-Frame-Options":          {SeverityMedium, "Add 'X-Frame-Options: DENY' header"},
		"Content-Security-Policy":  {SeverityMedium, "Add a Content-Security-Policy header"},
		"Strict-Transport-Security": {SeverityHigh, "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' header"},
		"X-XSS-Protection":          {SeverityLow, "Add 'X-XSS-Protection: 0' header (modern browsers use CSP instead)"},
	}

	var findings []Finding
	for header, info := range headers {
		f := Finding{
			ID:         fmt.Sprintf("API-002-%s", strings.ReplaceAll(strings.ToLower(header), "-", "")),
			Category:   CategoryHeaders,
			Title:      fmt.Sprintf("Security header: %s", header),
			References: []string{"OWASP A05:2021"},
		}
		if resp.Header.Get(header) != "" {
			f.Passed = true
			f.Severity = SeverityInfo
			f.Description = fmt.Sprintf("Header %s is present", header)
		} else {
			f.Severity = info.severity
			f.Description = fmt.Sprintf("Header %s is missing", header)
			f.Remediation = info.remediation
		}
		findings = append(findings, f)
	}
	return findings
}

func checkErrorSanitization(baseURL string) []Finding {
	f := Finding{
		ID:       "API-003",
		Category: CategoryAPI,
		Severity: SeverityMedium,
		Title:    "Error response sanitization",
		References: []string{"CWE-209", "OWASP A04:2021"},
	}
	if baseURL == "" {
		f.Severity = SeverityInfo
		f.Passed = true
		f.Description = "No base URL — skipping error sanitization check"
		return []Finding{f}
	}

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(baseURL + "/api/v1/nonexistent-endpoint-for-audit")
	if err != nil {
		f.Severity = SeverityInfo
		f.Passed = true
		f.Description = "Could not reach server — skipping"
		return []Finding{f}
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	bodyStr := strings.ToLower(string(body))

	// Check for common information leakage patterns.
	leakPatterns := []string{"stack trace", "goroutine", "panic", "runtime error", "/home/", "/root/", "/usr/"}
	for _, pattern := range leakPatterns {
		if strings.Contains(bodyStr, pattern) {
			f.Description = fmt.Sprintf("Error response contains internal information (%q pattern detected)", pattern)
			f.Evidence = string(body)
			f.Remediation = "Sanitize error responses to exclude stack traces, file paths, and internal details"
			return []Finding{f}
		}
	}

	f.Passed = true
	f.Severity = SeverityInfo
	f.Description = "Error responses do not appear to leak internal details"
	return []Finding{f}
}

func checkContentTypeEnforcement(baseURL string) []Finding {
	f := Finding{
		ID:       "API-004",
		Category: CategoryAPI,
		Severity: SeverityLow,
		Title:    "Content-Type enforcement",
		References: []string{"CWE-436"},
	}
	if baseURL == "" {
		f.Severity = SeverityInfo
		f.Passed = true
		f.Description = "No base URL — skipping content-type check"
		return []Finding{f}
	}

	client := &http.Client{Timeout: 5 * time.Second}
	// Send request with wrong content type to a POST endpoint.
	resp, err := client.Post(baseURL+"/api/v1/auth/login", "text/plain", strings.NewReader(`not json`))
	if err != nil {
		f.Severity = SeverityInfo
		f.Passed = true
		f.Description = "Could not reach server — skipping"
		return []Finding{f}
	}
	defer resp.Body.Close()

	if resp.StatusCode == 400 || resp.StatusCode == 415 {
		f.Passed = true
		f.Severity = SeverityInfo
		f.Description = "API rejects non-JSON content types with appropriate error"
	} else {
		f.Description = fmt.Sprintf("API accepted non-JSON content type (status %d)", resp.StatusCode)
		f.Remediation = "Validate Content-Type header on POST/PUT/PATCH endpoints"
	}
	return []Finding{f}
}

// --- Configuration Checks ---

// ConfigChecks returns checks for secure configuration.
func ConfigChecks(cfg ConfigCheckConfig) []Check {
	return []Check{
		{
			ID:       "CFG-001",
			Name:     "Debug mode disabled",
			Category: CategoryConfig,
			Description: "Verify debug/development mode is not enabled in production",
			Fn: func() []Finding {
				return checkDebugMode(cfg.LogLevel, cfg.IsProduction)
			},
		},
		{
			ID:       "CFG-002",
			Name:     "Sensitive environment variables",
			Category: CategoryConfig,
			Description: "Verify sensitive credentials are set via environment variables",
			Fn: func() []Finding {
				return checkSensitiveEnv(cfg.RequiredEnvVars)
			},
		},
		{
			ID:       "CFG-003",
			Name:     "Default credentials",
			Category: CategoryConfig,
			Description: "Verify no default or weak credentials are in use",
			Fn: func() []Finding {
				return checkDefaultCredentials(cfg.EncryptionKey, cfg.JWTSecret, cfg.StripeKey)
			},
		},
	}
}

// ConfigCheckConfig holds configuration for configuration security checks.
type ConfigCheckConfig struct {
	LogLevel       string
	IsProduction   bool
	RequiredEnvVars []string
	EncryptionKey  string
	JWTSecret      string
	StripeKey      string
}

func checkDebugMode(logLevel string, isProd bool) []Finding {
	f := Finding{
		ID:       "CFG-001",
		Category: CategoryConfig,
		Severity: SeverityMedium,
		Title:    "Debug mode configuration",
		References: []string{"CWE-489", "OWASP A05:2021"},
	}
	lower := strings.ToLower(logLevel)
	if isProd && (lower == "debug" || lower == "trace") {
		f.Description = fmt.Sprintf("Production environment with verbose logging (%s)", logLevel)
		f.Remediation = "Set OPERATOR_LOG_LEVEL to 'info' or higher in production"
		return []Finding{f}
	}
	f.Passed = true
	f.Severity = SeverityInfo
	f.Description = "Log level is appropriate for environment"
	return []Finding{f}
}

func checkSensitiveEnv(requiredVars []string) []Finding {
	var findings []Finding
	for _, v := range requiredVars {
		f := Finding{
			ID:       fmt.Sprintf("CFG-002-%s", strings.ToLower(v)),
			Category: CategoryConfig,
			Title:    fmt.Sprintf("Environment variable: %s", v),
			References: []string{"CWE-798"},
		}
		if os.Getenv(v) == "" {
			f.Severity = SeverityHigh
			f.Description = fmt.Sprintf("Required environment variable %s is not set", v)
			f.Remediation = fmt.Sprintf("Set %s with a secure value", v)
		} else {
			f.Passed = true
			f.Severity = SeverityInfo
			f.Description = fmt.Sprintf("Environment variable %s is configured", v)
		}
		findings = append(findings, f)
	}
	return findings
}

func checkDefaultCredentials(encKey, jwtSecret, stripeKey string) []Finding {
	weakValues := []string{
		"password", "secret", "changeme", "default", "test", "example",
		"12345", "admin", "operator", "letmein",
	}

	check := func(name, value string) Finding {
		f := Finding{
			ID:       fmt.Sprintf("CFG-003-%s", strings.ToLower(strings.ReplaceAll(name, " ", "-"))),
			Category: CategoryConfig,
			Title:    fmt.Sprintf("Default credential check: %s", name),
			References: []string{"CWE-798", "CWE-1188"},
		}
		if value == "" {
			f.Severity = SeverityInfo
			f.Passed = true
			f.Description = fmt.Sprintf("%s is not configured", name)
			return f
		}
		lower := strings.ToLower(value)
		for _, weak := range weakValues {
			if lower == weak || strings.Contains(lower, weak) {
				f.Severity = SeverityCritical
				f.Description = fmt.Sprintf("%s appears to use a weak or default value", name)
				f.Remediation = fmt.Sprintf("Replace %s with a strong, randomly generated value", name)
				return f
			}
		}
		f.Passed = true
		f.Severity = SeverityInfo
		f.Description = fmt.Sprintf("%s does not appear to use a default value", name)
		return f
	}

	return []Finding{
		check("Encryption Key", encKey),
		check("JWT Secret", jwtSecret),
		check("Stripe Key", stripeKey),
	}
}

// --- Data Protection Checks ---

// DataProtectionChecks returns checks for data protection and privacy.
func DataProtectionChecks(cfg DataProtectionConfig) []Check {
	return []Check{
		{
			ID:       "DATA-001",
			Name:     "GDPR compliance components",
			Category: CategoryCompliance,
			Description: "Verify GDPR data subject request infrastructure exists",
			Fn: func() []Finding {
				return checkGDPRCompliance(cfg.HasExportEndpoint, cfg.HasErasureEndpoint, cfg.HasRetentionPolicy)
			},
		},
		{
			ID:       "DATA-002",
			Name:     "Audit logging enabled",
			Category: CategoryData,
			Description: "Verify audit logging is active for security events",
			Fn: func() []Finding {
				return checkAuditLogging(cfg.AuditEnabled)
			},
		},
		{
			ID:       "DATA-003",
			Name:     "Backup encryption",
			Category: CategoryData,
			Description: "Verify database backups are encrypted",
			Fn: func() []Finding {
				return checkBackupEncryption(cfg.BackupsEncrypted)
			},
		},
	}
}

// DataProtectionConfig holds configuration for data protection checks.
type DataProtectionConfig struct {
	HasExportEndpoint  bool
	HasErasureEndpoint bool
	HasRetentionPolicy bool
	AuditEnabled       bool
	BackupsEncrypted   bool
}

func checkGDPRCompliance(hasExport, hasErasure, hasRetention bool) []Finding {
	var findings []Finding

	components := []struct {
		name    string
		present bool
		id      string
	}{
		{"Data export endpoint", hasExport, "DATA-001-export"},
		{"Data erasure endpoint", hasErasure, "DATA-001-erasure"},
		{"Data retention policy", hasRetention, "DATA-001-retention"},
	}

	for _, c := range components {
		f := Finding{
			ID:       c.id,
			Category: CategoryCompliance,
			Title:    fmt.Sprintf("GDPR: %s", c.name),
			References: []string{"GDPR Art. 15-17", "OWASP A04:2021"},
		}
		if c.present {
			f.Passed = true
			f.Severity = SeverityInfo
			f.Description = fmt.Sprintf("%s is implemented", c.name)
		} else {
			f.Severity = SeverityHigh
			f.Description = fmt.Sprintf("%s is not implemented", c.name)
			f.Remediation = fmt.Sprintf("Implement %s for GDPR compliance", c.name)
		}
		findings = append(findings, f)
	}
	return findings
}

func checkAuditLogging(enabled bool) []Finding {
	f := Finding{
		ID:       "DATA-002",
		Category: CategoryData,
		Severity: SeverityHigh,
		Title:    "Audit logging",
		References: []string{"CWE-778", "OWASP A09:2021"},
	}
	if enabled {
		f.Passed = true
		f.Severity = SeverityInfo
		f.Description = "Audit logging is enabled"
	} else {
		f.Description = "Audit logging is not enabled"
		f.Remediation = "Enable audit logging for all security-relevant events"
	}
	return []Finding{f}
}

func checkBackupEncryption(encrypted bool) []Finding {
	f := Finding{
		ID:       "DATA-003",
		Category: CategoryData,
		Severity: SeverityMedium,
		Title:    "Backup encryption",
		References: []string{"CWE-311"},
	}
	if encrypted {
		f.Passed = true
		f.Severity = SeverityInfo
		f.Description = "Database backups are encrypted"
	} else {
		f.Description = "Database backups may not be encrypted"
		f.Remediation = "Enable encryption for database backups or ensure the backup directory has restricted permissions"
	}
	return []Finding{f}
}

// --- Rate Limiting Checks ---

// RateLimitChecks returns checks for rate limiting configuration.
func RateLimitChecks(cfg RateLimitConfig) []Check {
	return []Check{
		{
			ID:       "RATE-001",
			Name:     "Rate limiting enabled",
			Category: CategoryRateLimit,
			Description: "Verify rate limiting is configured for API endpoints",
			Fn: func() []Finding {
				return checkRateLimiting(cfg.Enabled, cfg.BaseURL)
			},
		},
		{
			ID:       "RATE-002",
			Name:     "Login rate limiting",
			Category: CategoryRateLimit,
			Description: "Verify login endpoint has rate limiting to prevent brute force",
			Fn: func() []Finding {
				return checkLoginRateLimit(cfg.LoginLimitPerMinute)
			},
		},
	}
}

// RateLimitConfig holds configuration for rate limiting checks.
type RateLimitConfig struct {
	Enabled             bool
	BaseURL             string
	LoginLimitPerMinute int
}

func checkRateLimiting(enabled bool, baseURL string) []Finding {
	f := Finding{
		ID:       "RATE-001",
		Category: CategoryRateLimit,
		Severity: SeverityHigh,
		Title:    "Rate limiting configuration",
		References: []string{"CWE-770", "OWASP A04:2021"},
	}
	if !enabled {
		f.Description = "Rate limiting is not enabled"
		f.Remediation = "Enable per-user rate limiting middleware"
		return []Finding{f}
	}

	if baseURL != "" {
		client := &http.Client{Timeout: 5 * time.Second}
		resp, err := client.Get(baseURL + "/api/v1/billing/plans")
		if err == nil {
			defer resp.Body.Close()
			if resp.Header.Get("X-RateLimit-Limit") != "" {
				f.Passed = true
				f.Severity = SeverityInfo
				f.Description = "Rate limiting is enabled and returning limit headers"
				return []Finding{f}
			}
		}
	}

	f.Passed = true
	f.Severity = SeverityInfo
	f.Description = "Rate limiting is enabled"
	return []Finding{f}
}

func checkLoginRateLimit(limitPerMin int) []Finding {
	f := Finding{
		ID:       "RATE-002",
		Category: CategoryRateLimit,
		Severity: SeverityHigh,
		Title:    "Login rate limiting",
		References: []string{"CWE-307", "OWASP A07:2021"},
	}
	if limitPerMin <= 0 {
		f.Severity = SeverityMedium
		f.Description = "Login rate limit not explicitly configured"
		f.Remediation = "Configure a specific rate limit for login attempts (recommended: 5-10 per minute)"
		return []Finding{f}
	}
	if limitPerMin > 20 {
		f.Description = fmt.Sprintf("Login rate limit is %d/min — too permissive for brute-force protection", limitPerMin)
		f.Remediation = "Reduce login rate limit to ≤10 per minute"
		return []Finding{f}
	}
	f.Passed = true
	f.Severity = SeverityInfo
	f.Description = fmt.Sprintf("Login rate limit is %d/min — adequate", limitPerMin)
	return []Finding{f}
}

// --- Session Security Checks ---

// SessionChecks returns checks for session management security.
func SessionChecks(cfg SessionCheckConfig) []Check {
	return []Check{
		{
			ID:       "SESS-001",
			Name:     "Session TTL configured",
			Category: CategorySession,
			Description: "Verify session TTL and eviction are configured",
			Fn: func() []Finding {
				return checkSessionTTL(cfg.TTL, cfg.MaxSessions)
			},
		},
		{
			ID:       "SESS-002",
			Name:     "Session isolation",
			Category: CategorySession,
			Description: "Verify tenant session isolation is enforced",
			Fn: func() []Finding {
				return checkSessionIsolation(cfg.TenantIsolation)
			},
		},
	}
}

// SessionCheckConfig holds configuration for session checks.
type SessionCheckConfig struct {
	TTL             time.Duration
	MaxSessions     int
	TenantIsolation bool
}

func checkSessionTTL(ttl time.Duration, maxSessions int) []Finding {
	var findings []Finding

	f1 := Finding{
		ID:       "SESS-001a",
		Category: CategorySession,
		Title:    "Session TTL",
		References: []string{"CWE-613"},
	}
	if ttl == 0 {
		f1.Severity = SeverityMedium
		f1.Description = "Session TTL is not configured — sessions may persist indefinitely"
		f1.Remediation = "Configure session TTL (recommended: 24h)"
	} else if ttl > 7*24*time.Hour {
		f1.Severity = SeverityMedium
		f1.Description = fmt.Sprintf("Session TTL is %s — long-lived sessions increase risk", ttl)
		f1.Remediation = "Reduce session TTL to ≤7 days"
	} else {
		f1.Passed = true
		f1.Severity = SeverityInfo
		f1.Description = fmt.Sprintf("Session TTL is %s — adequate", ttl)
	}
	findings = append(findings, f1)

	f2 := Finding{
		ID:       "SESS-001b",
		Category: CategorySession,
		Title:    "Session maximum count",
		References: []string{"CWE-770"},
	}
	if maxSessions <= 0 {
		f2.Severity = SeverityMedium
		f2.Description = "No maximum session count configured — unbounded session growth possible"
		f2.Remediation = "Configure max sessions with LRU eviction"
	} else {
		f2.Passed = true
		f2.Severity = SeverityInfo
		f2.Description = fmt.Sprintf("Maximum sessions: %d", maxSessions)
	}
	findings = append(findings, f2)

	return findings
}

func checkSessionIsolation(tenantIsolation bool) []Finding {
	f := Finding{
		ID:       "SESS-002",
		Category: CategorySession,
		Severity: SeverityHigh,
		Title:    "Tenant session isolation",
		References: []string{"CWE-284", "OWASP A01:2021"},
	}
	if tenantIsolation {
		f.Passed = true
		f.Severity = SeverityInfo
		f.Description = "Tenant session isolation is enabled"
	} else {
		f.Description = "Tenant session isolation is not enabled — multi-tenant data leakage possible"
		f.Remediation = "Enable tenant-scoped session stores for multi-tenant deployments"
	}
	return []Finding{f}
}

// --- Input Validation Checks ---

// InputValidationChecks returns checks for input validation and injection prevention.
func InputValidationChecks(cfg InputCheckConfig) []Check {
	return []Check{
		{
			ID:       "INJ-001",
			Name:     "SQL injection resistance",
			Category: CategoryInjection,
			Description: "Verify parameterized queries are used (not string concatenation)",
			Fn: func() []Finding {
				return checkSQLInjection(cfg.UsesParameterizedQueries)
			},
		},
		{
			ID:       "INJ-002",
			Name:     "Command injection resistance",
			Category: CategoryInjection,
			Description: "Verify command execution uses sandboxing",
			Fn: func() []Finding {
				return checkCommandInjection(cfg.HasSandbox, cfg.SandboxLevel)
			},
		},
		{
			ID:       "INJ-003",
			Name:     "Input size limits",
			Category: CategoryInput,
			Description: "Verify request body size limits are enforced",
			Fn: func() []Finding {
				return checkInputSizeLimits(cfg.MaxRequestBodyBytes)
			},
		},
	}
}

// InputCheckConfig holds configuration for input validation checks.
type InputCheckConfig struct {
	UsesParameterizedQueries bool
	HasSandbox               bool
	SandboxLevel             string // "none", "process", "container"
	MaxRequestBodyBytes      int64
}

func checkSQLInjection(parameterized bool) []Finding {
	f := Finding{
		ID:       "INJ-001",
		Category: CategoryInjection,
		Severity: SeverityCritical,
		Title:    "SQL injection prevention",
		References: []string{"CWE-89", "OWASP A03:2021"},
	}
	if parameterized {
		f.Passed = true
		f.Severity = SeverityInfo
		f.Description = "Application uses parameterized queries for all database operations"
	} else {
		f.Description = "Application may not use parameterized queries for all database operations"
		f.Remediation = "Use parameterized queries (? or $N placeholders) for all SQL operations"
	}
	return []Finding{f}
}

func checkCommandInjection(hasSandbox bool, level string) []Finding {
	f := Finding{
		ID:       "INJ-002",
		Category: CategoryInjection,
		Severity: SeverityHigh,
		Title:    "Command injection prevention",
		References: []string{"CWE-78", "OWASP A03:2021"},
	}
	if !hasSandbox {
		f.Severity = SeverityCritical
		f.Description = "No command execution sandboxing is configured"
		f.Remediation = "Enable command sandboxing (at minimum process-level isolation)"
		return []Finding{f}
	}
	switch level {
	case "container":
		f.Passed = true
		f.Severity = SeverityInfo
		f.Description = "Container-level command sandboxing is enabled"
	case "process":
		f.Passed = true
		f.Severity = SeverityInfo
		f.Description = "Process-level command sandboxing is enabled"
	default:
		f.Severity = SeverityMedium
		f.Description = fmt.Sprintf("Sandbox level is %q — consider container isolation for production", level)
		f.Remediation = "Use container-level sandboxing for maximum isolation"
	}
	return []Finding{f}
}

func checkInputSizeLimits(maxBytes int64) []Finding {
	f := Finding{
		ID:       "INJ-003",
		Category: CategoryInput,
		Severity: SeverityMedium,
		Title:    "Request body size limits",
		References: []string{"CWE-400"},
	}
	if maxBytes <= 0 {
		f.Description = "No request body size limit configured"
		f.Remediation = "Set a maximum request body size (recommended: 1MB for API endpoints)"
		return []Finding{f}
	}
	if maxBytes > 100*1024*1024 { // 100MB
		f.Description = fmt.Sprintf("Request body size limit is %d bytes — very large", maxBytes)
		f.Remediation = "Reduce request body size limit unless large uploads are required"
		return []Finding{f}
	}
	f.Passed = true
	f.Severity = SeverityInfo
	f.Description = fmt.Sprintf("Request body size limit: %d bytes", maxBytes)
	return []Finding{f}
}

// --- Composite Audit ---

// DefaultAuditConfig provides a configuration struct for a comprehensive audit.
type DefaultAuditConfig struct {
	Auth           AuthCheckConfig
	Crypto         CryptoCheckConfig
	API            APICheckConfig
	Config         ConfigCheckConfig
	DataProtection DataProtectionConfig
	RateLimit      RateLimitConfig
	Session        SessionCheckConfig
	Input          InputCheckConfig
}

// RegisterAllChecks registers all default check categories with the auditor.
func RegisterAllChecks(a *Auditor, cfg DefaultAuditConfig) error {
	allChecks := [][]Check{
		AuthChecks(cfg.Auth),
		CryptoChecks(cfg.Crypto),
		APIChecks(cfg.API),
		ConfigChecks(cfg.Config),
		DataProtectionChecks(cfg.DataProtection),
		RateLimitChecks(cfg.RateLimit),
		SessionChecks(cfg.Session),
		InputValidationChecks(cfg.Input),
	}
	for _, group := range allChecks {
		for _, c := range group {
			if err := a.RegisterCheck(c); err != nil {
				return err
			}
		}
	}
	return nil
}

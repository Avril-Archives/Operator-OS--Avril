# Changelog

All notable changes to Operator OS will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Web dashboard (React 19 + TypeScript + Tailwind CSS v4)
- Agent management UI with creation wizard and inline editing
- Chat interface with streaming, markdown rendering, and code highlighting
- Billing and usage dashboard with daily charts and model breakdown
- Admin panel with user management, audit log, and security dashboard
- Integration management with OAuth flow support
- OKLCH design system with dark/light themes and high-contrast mode
- Floating navbar with glass morphism and mobile-first responsive layout
- FAB (Floating Action Button) for quick actions
- Shared component library: Skeleton, Tooltip, Dropdown, Badge, EmptyState
- Service worker for offline fallback
- Structured request logging middleware with correlation IDs
- Request validation middleware (body size limits, content-type enforcement)
- Comprehensive config validation on startup with multi-error reporting
- Shared `apiutil` error response helpers for consistent API error formatting
- CORS middleware with configurable allowed origins
- IP-based auth rate limiting (login, register, verification endpoints)
- Per-user rate limiting with configurable thresholds per billing tier
- JWT token blacklist for logout/revocation
- Password strength validation (uppercase, lowercase, digit, special character)
- Health check infrastructure with component-level checks and `/health/detailed` endpoint
- Channel health checks registered with central health system
- Graceful shutdown with SIGTERM/SIGINT handling
- Sandbox policy hardening with default deny list for dangerous commands
- GDPR compliance endpoints (data export, erasure, retention policy)
- Security audit endpoint with category filtering
- OAuth 2.0 provider management API
- OpenAPI spec serving endpoint
- Documentation: configuration reference, self-hosting guide, contributing guide, security policy

### Changed
- Migrated all REST endpoint error responses to shared `apiutil.WriteError` format
- Standardized JSON error response format across admin, agents, users, billing, GDPR, integrations, OAuth, and middleware packages

### Fixed
- ESLint configuration for React hooks plugin
- Conditional hook call in RateLimitIndicator component
- Flex-wrap violations across 6 frontend files (replaced with horizontal scroll)
- Touch target sizes for TopBar hamburger, theme toggle, and MobileSidebar close button
- Hardcoded OKLCH values replaced with design system tokens

## [Template]

<!--
Use this template when tagging a new release.
Copy the [Unreleased] section, rename it to the version, and add a date.

## [X.Y.Z] - YYYY-MM-DD

### Added
- New features

### Changed
- Changes to existing functionality

### Deprecated
- Features that will be removed in future versions

### Removed
- Features that were removed

### Fixed
- Bug fixes

### Security
- Vulnerability fixes
-->

# Operator OS — Chat UI Workstream

**Created:** 2026-03-08
**Status:** Planning
**Target:** Production-ready chat interface for Operator OS platform

---

## Overview

A modern, real-time chat UI that serves as the primary interface for Operator OS. Not just a messaging window — a full platform client that surfaces authentication, agent management, billing, integrations, and admin capabilities built in the backend.

**Stack:** React + TypeScript + Vite
**Styling:** Tailwind CSS + OKLCH color system
**Real-time:** WebSocket (upgrade from REST polling)
**Auth:** JWT (login/register/verify flows already built in backend)
**Deployment:** Static build → Caddy at `os-final.operator.onl`

---

## Architecture

```
┌─────────────────────────────────────────────────┐
│                   Chat UI (SPA)                 │
│                                                 │
│  ┌──────────┐ ┌──────────┐ ┌────────────────┐  │
│  │  Auth     │ │  Chat    │ │  Dashboard     │  │
│  │  Module   │ │  Module  │ │  Module        │  │
│  └──────────┘ └──────────┘ └────────────────┘  │
│  ┌──────────┐ ┌──────────┐ ┌────────────────┐  │
│  │  Agents  │ │  Billing │ │  Integrations  │  │
│  │  Module  │ │  Module  │ │  Module        │  │
│  └──────────┘ └──────────┘ └────────────────┘  │
│  ┌──────────┐ ┌──────────┐                      │
│  │  Admin   │ │  Settings│                      │
│  │  Module  │ │  Module  │                      │
│  └──────────┘ └──────────┘                      │
└───────────────────┬─────────────────────────────┘
                    │ HTTPS + WSS
┌───────────────────▼─────────────────────────────┐
│              Operator OS Gateway                │
│         (Go API — already built)                │
│                                                 │
│  60+ REST endpoints across 15 API groups        │
│  JWT auth · Stripe billing · OAuth integrations │
└─────────────────────────────────────────────────┘
```

---

## Phase Overview

| # | Phase | Description | Tasks | Target |
|---|---|---|---|---|
| 1 | Foundation | Project scaffold, auth, routing, API client | C1–C5 | Week 1–2 |
| 2 | Chat Core | Real-time messaging, markdown, streaming | C6–C10 | Week 3–4 |
| 3 | Agent & Session Management | Multi-agent, sessions, history | C11–C14 | Week 5–6 |
| 4 | Platform Features | Billing, integrations, usage dashboard | C15–C19 | Week 7–8 |
| 5 | Admin & Settings | Admin panel, user management, security audit | C20–C23 | Week 9–10 |
| 6 | Polish & Launch | Mobile responsive, a11y, performance, deploy | C24–C28 | Week 11–12 |

---

## Phase 1: Foundation

| ID | Task | Priority | Status | Description |
|---|---|---|---|---|
| C1 | Project scaffold | P0 | ⬜ TODO | Vite + React + TypeScript + Tailwind. OKLCH design tokens (light/dark). Directory structure: `src/{components,pages,hooks,services,stores,types}`. ESLint + Prettier. |
| C2 | API client layer | P0 | ⬜ TODO | Typed HTTP client wrapping all backend endpoints. Auto-attach JWT from store. Refresh token interceptor. Error normalization. Request/response types generated from OpenAPI spec (`/api/v1/docs/openapi.json`). |
| C3 | Auth flows | P0 | ⬜ TODO | Login, register, email verification, password reset pages. JWT storage (httpOnly cookie or secure localStorage). Auth context provider. Protected route wrapper. Redirect logic. Calls: `POST /auth/register`, `POST /auth/login`, `POST /auth/verify-email`, `POST /auth/resend-verification`, `POST /auth/refresh`. |
| C4 | App shell & routing | P0 | ⬜ TODO | Sidebar navigation (collapsible), top bar with user menu, main content area. React Router v7. Routes: `/login`, `/register`, `/verify`, `/chat`, `/agents`, `/billing`, `/integrations`, `/settings`, `/admin`. Responsive layout with mobile drawer nav. |
| C5 | Theme system | P1 | ⬜ TODO | Light/dark mode with system preference detection. OKLCH color palette. CSS custom properties. Persist preference. Smooth transitions. Design tokens: `--surface`, `--text`, `--accent`, `--border`, `--error`, `--success`. |

---

## Phase 2: Chat Core

| ID | Task | Priority | Status | Description |
|---|---|---|---|---|
| C6 | WebSocket transport | P0 | ⬜ TODO | Backend: add WebSocket upgrade endpoint (`/api/v1/ws`) to the gateway. JWT auth on connect. Heartbeat ping/pong. Auto-reconnect with exponential backoff. Frontend: WebSocket provider with connection state management. |
| C7 | Message thread UI | P0 | ⬜ TODO | Chat message list with auto-scroll, scroll-to-bottom button, virtualized rendering for long threads. Message bubbles: user (right-aligned), assistant (left-aligned), system (centered). Timestamps, read indicators. Loading skeleton. |
| C8 | Markdown & code rendering | P0 | ⬜ TODO | Full markdown support (headings, lists, tables, links, images). Syntax-highlighted code blocks with copy button and language label. LaTeX/math rendering. Mermaid diagram support (stretch). |
| C9 | Streaming responses | P0 | ⬜ TODO | Server-sent events or WebSocket streaming for token-by-token display. Typing indicator. Cancel generation button. Partial markdown rendering during stream. |
| C10 | Input composer | P1 | ⬜ TODO | Multi-line textarea with auto-resize. File/image upload with drag-and-drop and preview. Paste image support. Send on Enter, newline on Shift+Enter. Character count. Model selector dropdown (from agent config). |

---

## Phase 3: Agent & Session Management

| ID | Task | Priority | Status | Description |
|---|---|---|---|---|
| C11 | Agent CRUD | P0 | ⬜ TODO | List agents, create/edit/delete. Agent card showing name, model, system prompt preview, status, integration scopes. Set default agent. Calls: `GET/POST /api/v1/agents`, `GET/PUT/DELETE /api/v1/agents/{id}`, `POST /api/v1/agents/{id}/default`. |
| C12 | Multi-session UI | P0 | ⬜ TODO | Session sidebar: list active sessions, create new, rename, delete. Session = conversation thread tied to an agent. Switch between sessions without losing state. Session metadata (created, message count, last active). |
| C13 | Conversation history | P1 | ⬜ TODO | Search across sessions. Filter by agent, date range. Export conversation as markdown/JSON. Pin important conversations. Archive old sessions. |
| C14 | Agent integration scopes | P1 | ⬜ TODO | Per-agent integration permission editor. Visual scope selector showing available integrations, tools, and OAuth scopes. Calls: `AllowedIntegrations` field on agent create/update. |

---

## Phase 4: Platform Features

| ID | Task | Priority | Status | Description |
|---|---|---|---|---|
| C15 | Billing & plans | P0 | ⬜ TODO | Plan comparison page (Free/Starter/Pro/Enterprise). Current plan badge. Upgrade/downgrade with proration preview. Stripe Checkout redirect. Billing portal link. Calls: `GET /api/v1/billing/plans`, `POST /billing/checkout`, `POST /billing/portal`, `GET /billing/subscription`, `POST /billing/change-plan`, `POST /billing/preview-change`. |
| C16 | Usage dashboard | P0 | ⬜ TODO | Token usage charts (daily, by model). Current period summary. Usage vs plan limits with progress bars. Overage warnings. Calls: `GET /billing/usage`, `GET /billing/usage/daily`, `GET /billing/usage/models`, `GET /billing/usage/limits`, `GET /billing/overage`. |
| C17 | Integration marketplace | P1 | ⬜ TODO | Browse available integrations by category. Connect/disconnect OAuth integrations (Google, Shopify). API key integrations. Status indicators (active/failed/revoked). Token health display. Calls: `GET /integrations`, `GET /integrations/categories`, `POST /manage/integrations/connect`, `POST /manage/integrations/disconnect`, `GET /manage/integrations/status`. |
| C18 | OAuth connect flow | P1 | ⬜ TODO | In-app OAuth popup/redirect for Google, Shopify. Callback handling. Scope consent display. Reconnect for expired/revoked tokens. Calls: `POST /oauth/authorize`, `GET /oauth/callback`. |
| C19 | Rate limit display | P2 | ⬜ TODO | Show current rate limit status from `X-RateLimit-*` response headers. Visual indicator when approaching limits. Calls: `GET /api/v1/rate-limit/status`. |

---

## Phase 5: Admin & Settings

| ID | Task | Priority | Status | Description |
|---|---|---|---|---|
| C20 | Admin panel | P1 | ⬜ TODO | User list with search/filter. Suspend/activate/delete users. Role management (user/admin). Platform stats dashboard. Requires admin role. Calls: `GET/PUT/DELETE /admin/users/*`, `POST /admin/users/{id}/suspend`, `POST /admin/users/{id}/activate`, `POST /admin/users/{id}/role`, `GET /admin/stats`. |
| C21 | Audit log viewer | P1 | ⬜ TODO | Filterable event log (by user, action, time range). Action categories (auth, agent, billing, admin). Expandable detail rows. CSV export. Calls: `GET /admin/audit`, `GET /admin/audit/count`. |
| C22 | Security audit dashboard | P2 | ⬜ TODO | Run security audit from UI. Risk score visualization (gauge). Check results grouped by category with pass/fail/warning. Remediation guidance. CWE/OWASP references. Calls: `GET /admin/security-audit`. |
| C23 | User settings | P1 | ⬜ TODO | Profile (email, password change). Theme preference. Notification settings. GDPR: data export request, account deletion request. API key management. Calls: `POST /gdpr/export`, `POST /gdpr/erase`, `GET /gdpr/requests`. |

---

## Phase 6: Polish & Launch

| ID | Task | Priority | Status | Description |
|---|---|---|---|---|
| C24 | Mobile responsive | P0 | ⬜ TODO | Full mobile layout. Bottom tab navigation. Slide-over panels for settings/agents. Touch-friendly composer. Responsive breakpoints: 640/768/1024/1280. Test on iOS Safari + Android Chrome. |
| C25 | Accessibility | P1 | ⬜ TODO | WCAG 2.1 AA compliance. Keyboard navigation throughout. Screen reader landmarks and ARIA labels. Focus management on route changes. Reduced motion support. Color contrast validation against OKLCH palette. |
| C26 | Performance | P1 | ⬜ TODO | Code splitting per route. Lazy load heavy components (markdown renderer, charts). Service worker for offline shell. Bundle analysis < 200KB initial JS. Lighthouse score > 90. Virtual scrolling for long message lists. |
| C27 | Error handling & empty states | P1 | ⬜ TODO | Global error boundary with recovery. Toast notifications for API errors. Offline detection banner. Empty states for all list views (no agents, no sessions, no integrations). Loading skeletons. |
| C28 | Production deployment | P0 | ⬜ TODO | Vite build → `/var/www/production/os-final/`. Caddy config for `os-final.operator.onl`. API proxy to gateway port. Gzip/Brotli. Cache headers for assets. CSP headers. GitHub Actions CI (lint + type-check + build). |

---

## Backend Requirements (New Endpoints Needed)

The chat UI requires a few backend additions not yet in the platform:

| ID | Endpoint | Purpose |
|---|---|---|
| B-WS | `GET /api/v1/ws` | WebSocket upgrade for real-time chat. JWT auth on handshake. Message send/receive + streaming tokens. |
| B-SESSIONS | `GET/POST/DELETE /api/v1/sessions` | Session CRUD — list user's chat sessions, create new, delete. |
| B-MESSAGES | `GET /api/v1/sessions/{id}/messages` | Paginated message history for a session. |
| B-SEND | `POST /api/v1/sessions/{id}/messages` | Send a message (triggers agent processing). |
| B-STREAM | `GET /api/v1/sessions/{id}/stream` | SSE fallback for streaming responses if WebSocket isn't available. |
| B-PROFILE | `GET/PUT /api/v1/user/profile` | Get/update current user profile. |
| B-PASSWORD | `POST /api/v1/user/password` | Change password (requires current password). |

---

## Design Principles

1. **API-first** — Every UI feature maps to an existing backend endpoint. No frontend hacks.
2. **Progressive disclosure** — Chat is front and center. Platform features (billing, integrations, admin) are one click away but never in the way.
3. **Real-time by default** — WebSocket for chat, polling fallback for dashboards. No manual refresh.
4. **Mobile-native feel** — Not a desktop app squeezed onto a phone. Touch targets, gestures, native-like transitions.
5. **Type-safe end-to-end** — OpenAPI spec → generated TypeScript types → zero runtime type mismatches.

---

## Deployment

| Environment | Domain | Branch | Auto-deploy |
|---|---|---|---|
| Dev | `os-ui.operator.onl` | `dev` | On push |
| Production | `os-final.operator.onl` | `main` | On merge |

---

## Changelog

| Date | Change |
|---|---|
| 2026-03-08 | Initial plan created. 28 tasks across 6 phases + 7 backend requirements. |

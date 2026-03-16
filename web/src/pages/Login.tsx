// ============================================================================
// Operator OS — Login Page
// Email + password sign-in with error display and register link.
// ============================================================================

import { useState } from 'react'
import { useNavigate, useLocation, Link } from 'react-router-dom'
import { SignIn, Warning, X } from '@phosphor-icons/react'
import { useAuthStore } from '../stores/authStore'

export function LoginPage() {
  const navigate = useNavigate()
  const location = useLocation()
  const { login, isLoading, error, clearError } = useAuthStore()

  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')

  // Where to redirect after successful login
  const from = (location.state as { from?: string })?.from || '/chat'

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!email || !password) return

    try {
      await login({ email, password })
      navigate(from, { replace: true })
    } catch {
      // Error is captured in store
    }
  }

  return (
    <div className="h-full flex items-center justify-center bg-bg px-4">
      <div className="w-full max-w-sm animate-fade-slide">
        {/* ─── Brand mark ─── */}
        <div className="flex flex-col items-center mb-8">
          <div className="w-12 h-12 rounded-2xl bg-accent flex items-center justify-center mb-4 shadow-[0_4px_16px_var(--glass-shadow)]">
            <span className="text-white text-lg font-bold leading-none">OS</span>
          </div>
          <h1 className="text-2xl font-bold text-text tracking-tight">
            Welcome back
          </h1>
          <p className="text-sm text-text-secondary mt-1">
            Sign in to Operator OS
          </p>
        </div>

        {/* ─── Card ─── */}
        <div className="bg-surface border border-border rounded-[var(--radius)] p-6 shadow-[0_4px_24px_var(--glass-shadow)]">
          {/* Error banner */}
          {error && (
            <div className="mb-4 px-3 py-2.5 bg-error-subtle border border-error/20 rounded-[var(--radius-sm)] text-sm text-error flex items-start gap-2" role="alert">
              <Warning size={16} weight="bold" className="shrink-0 mt-0.5" />
              <span className="flex-1">{error}</span>
              <button
                onClick={clearError}
                className="shrink-0 text-error/60 hover:text-error transition-colors cursor-pointer"
                aria-label="Dismiss error"
              >
                <X size={14} weight="bold" />
              </button>
            </div>
          )}

          <form onSubmit={handleSubmit} className="flex flex-col gap-3">
            <div className="flex flex-col gap-1.5">
              <label htmlFor="login-email" className="text-[13px] font-medium text-text-secondary">Email</label>
              <input
                id="login-email"
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                autoComplete="email"
                autoFocus
                required
                disabled={isLoading}
              />
            </div>
            <div className="flex flex-col gap-1.5">
              <label htmlFor="login-password" className="text-[13px] font-medium text-text-secondary">Password</label>
              <input
                id="login-password"
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                autoComplete="current-password"
                required
                disabled={isLoading}
              />
            </div>
            <button
              type="submit"
              disabled={isLoading || !email || !password}
              className="w-full py-3 bg-accent text-white text-sm font-semibold rounded-[var(--radius-sm)] hover:opacity-90 active:scale-[0.98] transition-all mt-1 disabled:opacity-40 disabled:cursor-not-allowed flex items-center justify-center gap-2 cursor-pointer"
            >
              {isLoading ? (
                <>
                  <span className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                  Signing in…
                </>
              ) : (
                <>
                  <SignIn size={16} weight="bold" />
                  Sign In
                </>
              )}
            </button>
          </form>
        </div>

        {/* Footer */}
        <p className="text-center text-xs text-text-dim mt-6">
          Don't have an account?{' '}
          <Link to="/register" className="text-accent-text hover:underline font-medium">
            Create one
          </Link>
        </p>
      </div>
    </div>
  )
}

// ============================================================================
// Operator OS — Login Page
// Email + password sign-in with error display and register link.
// ============================================================================

import { useState } from 'react'
import { useNavigate, useLocation, Link } from 'react-router-dom'
import { SignIn, Warning, X, Envelope, Lock } from '@phosphor-icons/react'
import { useAuthStore } from '../stores/authStore'
import { Input } from '../components/shared/Input'
import { Button } from '../components/shared/Button'

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
      <div className="w-full max-w-[380px] animate-fade-slide">
        {/* ─── Brand mark ─── */}
        <div className="flex flex-col items-center mb-10">
          <div className="w-14 h-14 rounded-2xl bg-accent flex items-center justify-center mb-5 shadow-[0_4px_16px_var(--glass-shadow)]">
            <span className="text-white text-xl font-bold leading-none tracking-tight">OS</span>
          </div>
          <h1 className="text-[22px] font-bold text-text tracking-tight">
            Welcome back
          </h1>
          <p className="text-[13px] text-text-dim mt-1.5">
            Sign in to your account
          </p>
        </div>

        {/* ─── Card ─── */}
        <div className="bg-surface border border-border rounded-[var(--radius)] p-6 shadow-[0_8px_32px_var(--glass-shadow)]">
          {/* Error banner */}
          {error && (
            <div className="mb-5 px-3 py-2.5 bg-error-subtle border border-error/20 rounded-[var(--radius-sm)] text-[13px] text-error flex items-start gap-2" role="alert">
              <Warning size={15} weight="bold" className="shrink-0 mt-0.5" />
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

          <form onSubmit={handleSubmit} className="flex flex-col gap-4">
            <Input
              id="login-email"
              type="email"
              label="Email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              autoComplete="email"
              autoFocus
              required
              disabled={isLoading}
              placeholder="you@example.com"
              icon={<Envelope size={16} weight="duotone" />}
            />

            <Input
              id="login-password"
              type="password"
              label="Password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              autoComplete="current-password"
              required
              disabled={isLoading}
              placeholder="Enter your password"
              icon={<Lock size={16} weight="duotone" />}
            />

            <Button
              type="submit"
              disabled={isLoading || !email || !password}
              loading={isLoading}
              icon={!isLoading ? <SignIn size={16} weight="bold" /> : undefined}
              size="lg"
              className="w-full mt-1"
            >
              {isLoading ? 'Signing in…' : 'Sign In'}
            </Button>
          </form>
        </div>

        {/* Footer */}
        <p className="text-center text-[13px] text-text-dim mt-6">
          Don't have an account?{' '}
          <Link to="/register" className="text-accent-text hover:underline font-medium">
            Create one
          </Link>
        </p>
      </div>
    </div>
  )
}

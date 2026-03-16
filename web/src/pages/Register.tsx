// ============================================================================
// Operator OS — Register Page
// Email + password + display name registration with verification redirect.
// ============================================================================

import { useState, useMemo } from 'react'
import { useNavigate, Link } from 'react-router-dom'
import { UserPlus, Warning, X } from '@phosphor-icons/react'
import { useAuthStore } from '../stores/authStore'

// ---------------------------------------------------------------------------
// Password strength meter
// ---------------------------------------------------------------------------

type StrengthLevel = 0 | 1 | 2 | 3 | 4

function getPasswordStrength(pw: string): StrengthLevel {
  if (!pw) return 0
  let score = 0
  if (pw.length >= 8) score++
  if (pw.length >= 12) score++
  if (/[a-z]/.test(pw) && /[A-Z]/.test(pw)) score++
  if (/\d/.test(pw)) score++
  if (/[^a-zA-Z0-9]/.test(pw)) score++
  return Math.min(4, Math.max(1, score)) as StrengthLevel
}

const strengthConfig: Record<StrengthLevel, { label: string; color: string; barColor: string }> = {
  0: { label: '', color: '', barColor: 'bg-border' },
  1: { label: 'Weak', color: 'text-error', barColor: 'bg-error' },
  2: { label: 'Fair', color: 'text-warning', barColor: 'bg-warning' },
  3: { label: 'Good', color: 'text-accent-text', barColor: 'bg-accent' },
  4: { label: 'Strong', color: 'text-success', barColor: 'bg-success' },
}

function PasswordStrength({ password }: { password: string }) {
  const level = getPasswordStrength(password)
  if (!password) return null
  const config = strengthConfig[level]

  return (
    <div className="flex items-center gap-2 mt-1">
      <div className="flex gap-1 flex-1">
        {[1, 2, 3, 4].map((i) => (
          <div
            key={i}
            className={`h-1 flex-1 rounded-full transition-colors duration-200 ${
              i <= level ? config.barColor : 'bg-border'
            }`}
          />
        ))}
      </div>
      <span className={`text-[11px] font-medium ${config.color}`}>
        {config.label}
      </span>
    </div>
  )
}

// ---------------------------------------------------------------------------
// Register page
// ---------------------------------------------------------------------------

export function RegisterPage() {
  const navigate = useNavigate()
  const { register, isLoading, error, clearError } = useAuthStore()

  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [displayName, setDisplayName] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [localError, setLocalError] = useState<string | null>(null)

  const combinedError = localError || error

  // Step indicator: how many fields are filled
  const step = useMemo(() => {
    if (!email) return 1
    if (!password) return 2
    if (!confirmPassword) return 3
    return 4
  }, [email, password, confirmPassword])

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setLocalError(null)

    if (!email || !password) return

    if (password.length < 8) {
      setLocalError('Password must be at least 8 characters')
      return
    }

    if (password !== confirmPassword) {
      setLocalError('Passwords do not match')
      return
    }

    try {
      await register({
        email,
        password,
        display_name: displayName || undefined,
      })
      navigate('/verify', { state: { email }, replace: true })
    } catch {
      // Error is captured in store
    }
  }

  return (
    <div className="h-full flex items-center justify-center bg-bg px-4 overflow-y-auto">
      <div className="w-full max-w-sm py-8 animate-fade-slide">
        {/* ─── Brand mark ─── */}
        <div className="flex flex-col items-center mb-8">
          <div className="w-12 h-12 rounded-2xl bg-accent flex items-center justify-center mb-4 shadow-[0_4px_16px_var(--glass-shadow)]">
            <span className="text-white text-lg font-bold leading-none">OS</span>
          </div>
          <h1 className="text-2xl font-bold text-text tracking-tight">
            Create Account
          </h1>
          <p className="text-sm text-text-secondary mt-1">
            Get started with Operator OS
          </p>
        </div>

        {/* ─── Step indicator ─── */}
        <div className="flex gap-1 mb-6 px-1">
          {[1, 2, 3, 4].map((s) => (
            <div
              key={s}
              className={`h-0.5 flex-1 rounded-full transition-colors duration-200 ${
                s <= step ? 'bg-accent' : 'bg-border'
              }`}
            />
          ))}
        </div>

        {/* ─── Card ─── */}
        <div className="bg-surface border border-border rounded-[var(--radius)] p-6 shadow-[0_4px_24px_var(--glass-shadow)]">
          {/* Error banner */}
          {combinedError && (
            <div className="mb-4 px-3 py-2.5 bg-error-subtle border border-error/20 rounded-[var(--radius-sm)] text-sm text-error flex items-start gap-2" role="alert">
              <Warning size={16} weight="bold" className="shrink-0 mt-0.5" />
              <span className="flex-1">{combinedError}</span>
              <button
                onClick={() => {
                  setLocalError(null)
                  clearError()
                }}
                className="shrink-0 text-error/60 hover:text-error transition-colors cursor-pointer"
                aria-label="Dismiss error"
              >
                <X size={14} weight="bold" />
              </button>
            </div>
          )}

          <form onSubmit={handleSubmit} className="flex flex-col gap-3">
            <div className="flex flex-col gap-1.5">
              <label htmlFor="reg-name" className="text-[13px] font-medium text-text-secondary">
                Display name <span className="text-text-dim">(optional)</span>
              </label>
              <input
                id="reg-name"
                type="text"
                value={displayName}
                onChange={(e) => setDisplayName(e.target.value)}
                autoComplete="name"
                autoFocus
                disabled={isLoading}
              />
            </div>
            <div className="flex flex-col gap-1.5">
              <label htmlFor="reg-email" className="text-[13px] font-medium text-text-secondary">Email</label>
              <input
                id="reg-email"
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                autoComplete="email"
                required
                disabled={isLoading}
              />
            </div>
            <div className="flex flex-col gap-1.5">
              <label htmlFor="reg-password" className="text-[13px] font-medium text-text-secondary">Password</label>
              <input
                id="reg-password"
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                autoComplete="new-password"
                required
                disabled={isLoading}
                aria-describedby="pw-strength"
              />
              <div id="pw-strength">
                <PasswordStrength password={password} />
              </div>
            </div>
            <div className="flex flex-col gap-1.5">
              <label htmlFor="reg-confirm" className="text-[13px] font-medium text-text-secondary">Confirm password</label>
              <input
                id="reg-confirm"
                type="password"
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                autoComplete="new-password"
                required
                disabled={isLoading}
              />
              {confirmPassword && password !== confirmPassword && (
                <p className="text-xs text-error" role="alert">Passwords do not match</p>
              )}
            </div>
            <button
              type="submit"
              disabled={isLoading || !email || !password || !confirmPassword}
              className="w-full py-3 bg-accent text-white text-sm font-semibold rounded-[var(--radius-sm)] hover:opacity-90 active:scale-[0.98] transition-all mt-1 disabled:opacity-40 disabled:cursor-not-allowed flex items-center justify-center gap-2 cursor-pointer"
            >
              {isLoading ? (
                <>
                  <span className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                  Creating account…
                </>
              ) : (
                <>
                  <UserPlus size={16} weight="bold" />
                  Create Account
                </>
              )}
            </button>
          </form>
        </div>

        {/* Footer */}
        <p className="text-center text-xs text-text-dim mt-6">
          Already have an account?{' '}
          <Link to="/login" className="text-accent-text hover:underline font-medium">
            Sign in
          </Link>
        </p>
      </div>
    </div>
  )
}

// ============================================================================
// Operator OS — Register Page
// Email + password + display name registration with verification redirect.
// ============================================================================

import { useState } from 'react'
import { useNavigate, Link } from 'react-router-dom'
import { UserPlus, Warning, X, Envelope, Lock, User } from '@phosphor-icons/react'
import { useAuthStore } from '../stores/authStore'
import { Input } from '../components/shared/Input'
import { Button } from '../components/shared/Button'

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
      <div className="w-full max-w-[380px] py-8 animate-fade-slide">
        {/* ─── Brand mark ─── */}
        <div className="flex flex-col items-center mb-10">
          <div className="w-14 h-14 rounded-2xl bg-accent flex items-center justify-center mb-5 shadow-[0_4px_16px_var(--glass-shadow)]">
            <span className="text-white text-xl font-bold leading-none tracking-tight">OS</span>
          </div>
          <h1 className="text-[22px] font-bold text-text tracking-tight">
            Create Account
          </h1>
          <p className="text-[13px] text-text-dim mt-1.5">
            Get started with Operator OS
          </p>
        </div>

        {/* ─── Card ─── */}
        <div className="bg-surface border border-border rounded-[var(--radius)] p-6 shadow-[0_8px_32px_var(--glass-shadow)]">
          {/* Error banner */}
          {combinedError && (
            <div className="mb-5 px-3 py-2.5 bg-error-subtle border border-error/20 rounded-[var(--radius-sm)] text-[13px] text-error flex items-start gap-2" role="alert">
              <Warning size={15} weight="bold" className="shrink-0 mt-0.5" />
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

          <form onSubmit={handleSubmit} className="flex flex-col gap-4">
            <Input
              id="reg-name"
              type="text"
              label="Display name"
              helper="Optional — you can set this later"
              value={displayName}
              onChange={(e) => setDisplayName(e.target.value)}
              autoComplete="name"
              autoFocus
              disabled={isLoading}
              placeholder="How should we call you?"
              icon={<User size={16} weight="duotone" />}
            />

            <Input
              id="reg-email"
              type="email"
              label="Email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              autoComplete="email"
              required
              disabled={isLoading}
              placeholder="you@example.com"
              icon={<Envelope size={16} weight="duotone" />}
            />

            <div>
              <Input
                id="reg-password"
                type="password"
                label="Password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                autoComplete="new-password"
                required
                disabled={isLoading}
                placeholder="Min. 8 characters"
                icon={<Lock size={16} weight="duotone" />}
              />
              <div id="pw-strength">
                <PasswordStrength password={password} />
              </div>
            </div>

            <Input
              id="reg-confirm"
              type="password"
              label="Confirm password"
              value={confirmPassword}
              onChange={(e) => setConfirmPassword(e.target.value)}
              autoComplete="new-password"
              required
              disabled={isLoading}
              placeholder="Re-enter your password"
              icon={<Lock size={16} weight="duotone" />}
              error={confirmPassword && password !== confirmPassword ? 'Passwords do not match' : undefined}
            />

            <Button
              type="submit"
              disabled={isLoading || !email || !password || !confirmPassword}
              loading={isLoading}
              icon={!isLoading ? <UserPlus size={16} weight="bold" /> : undefined}
              size="lg"
              className="w-full mt-1"
            >
              {isLoading ? 'Creating account…' : 'Create Account'}
            </Button>
          </form>
        </div>

        {/* Footer */}
        <p className="text-center text-[13px] text-text-dim mt-6">
          Already have an account?{' '}
          <Link to="/login" className="text-accent-text hover:underline font-medium">
            Sign in
          </Link>
        </p>
      </div>
    </div>
  )
}

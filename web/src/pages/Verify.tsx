// ============================================================================
// Operator OS — Email Verification Page
// Handles two flows:
//   1. Post-registration: shows "check your email" with resend button
//   2. Token verification: auto-verifies when ?token=xxx is in URL
// ============================================================================

import { useEffect, useState } from 'react'
import { Link, useLocation, useSearchParams } from 'react-router-dom'
import {
  Envelope,
  EnvelopeSimple,
  CheckCircle,
  XCircle,
  SpinnerGap,
  ArrowLeft,
  PaperPlaneTilt,
  Warning,
} from '@phosphor-icons/react'
import { useAuthStore } from '../stores/authStore'
import { Button } from '../components/shared/Button'
import { Input } from '../components/shared/Input'

type VerifyState = 'pending' | 'verifying' | 'success' | 'error'

export function VerifyPage() {
  const [searchParams] = useSearchParams()
  const location = useLocation()
  const { verifyEmail, resendVerification, isLoading, error, clearError } =
    useAuthStore()

  const token = searchParams.get('token')
  const emailFromState = (location.state as { email?: string })?.email
  const [verifyState, setVerifyState] = useState<VerifyState>(
    token ? 'verifying' : 'pending',
  )
  const [resendSuccess, setResendSuccess] = useState(false)
  const [resendEmail, setResendEmail] = useState(emailFromState || '')

  // Auto-verify if token is present in URL
  useEffect(() => {
    if (!token) return
    let cancelled = false

    const verify = async () => {
      try {
        await verifyEmail(token)
        if (!cancelled) setVerifyState('success')
      } catch {
        if (!cancelled) setVerifyState('error')
      }
    }

    verify()
    return () => {
      cancelled = true
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [token])

  const handleResend = async () => {
    if (!resendEmail) return
    setResendSuccess(false)
    try {
      await resendVerification(resendEmail)
      setResendSuccess(true)
    } catch {
      // Error captured in store
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
        </div>

        {/* ─── Card ─── */}
        <div className="bg-surface border border-border rounded-[var(--radius)] p-6 shadow-[0_8px_32px_var(--glass-shadow)]">
          {/* ─── Token verification flow ─── */}
          {token ? (
            <div className="text-center">
              {verifyState === 'verifying' && (
                <>
                  <div className="w-14 h-14 rounded-2xl bg-accent-subtle flex items-center justify-center mx-auto mb-4">
                    <SpinnerGap
                      size={28}
                      weight="bold"
                      className="text-accent-text animate-spin"
                    />
                  </div>
                  <h1 className="text-xl font-bold text-text">
                    Verifying your email
                  </h1>
                  <p className="text-[13px] text-text-dim mt-2">
                    This will only take a moment.
                  </p>
                </>
              )}

              {verifyState === 'success' && (
                <>
                  <div className="w-14 h-14 rounded-2xl bg-success-subtle flex items-center justify-center mx-auto mb-4">
                    <CheckCircle
                      size={28}
                      weight="fill"
                      className="text-success"
                    />
                  </div>
                  <h1 className="text-xl font-bold text-text">
                    Email Verified
                  </h1>
                  <p className="text-[13px] text-text-dim mt-2">
                    Your account is now active. You can sign in.
                  </p>
                  <Link to="/login" className="block mt-6">
                    <Button className="w-full" size="lg">
                      Sign In
                    </Button>
                  </Link>
                </>
              )}

              {verifyState === 'error' && (
                <>
                  <div className="w-14 h-14 rounded-2xl bg-error-subtle flex items-center justify-center mx-auto mb-4">
                    <XCircle
                      size={28}
                      weight="fill"
                      className="text-error"
                    />
                  </div>
                  <h1 className="text-xl font-bold text-text">
                    Verification Failed
                  </h1>
                  <p className="text-[13px] text-text-dim mt-2">
                    {error || 'This link may be invalid or expired.'}
                  </p>

                  {/* Resend form */}
                  <div className="mt-6 space-y-3 text-left">
                    <Input
                      type="email"
                      placeholder="Enter your email to resend"
                      value={resendEmail}
                      onChange={(e) => setResendEmail(e.target.value)}
                      icon={<Envelope size={16} weight="duotone" />}
                    />
                    <Button
                      variant="secondary"
                      className="w-full"
                      size="md"
                      onClick={handleResend}
                      disabled={isLoading || !resendEmail}
                      loading={isLoading}
                      icon={<PaperPlaneTilt size={16} />}
                    >
                      Resend Verification Email
                    </Button>
                  </div>
                </>
              )}
            </div>
          ) : (
            /* ─── Post-registration: check your email ─── */
            <div className="text-center">
              <div className="w-14 h-14 rounded-2xl bg-accent-subtle flex items-center justify-center mx-auto mb-4">
                <EnvelopeSimple
                  size={28}
                  weight="duotone"
                  className="text-accent-text"
                />
              </div>

              <h1 className="text-xl font-bold text-text">
                Check Your Email
              </h1>
              <p className="text-[13px] text-text-dim mt-2">
                We sent a verification link to{' '}
                {emailFromState ? (
                  <span className="text-text font-medium">{emailFromState}</span>
                ) : (
                  'your email'
                )}
                . Click the link to activate your account.
              </p>

              {/* Resend */}
              <div className="mt-6">
                {resendSuccess ? (
                  <div className="flex items-center justify-center gap-2 text-[13px] text-success py-3">
                    <CheckCircle size={16} weight="fill" />
                    Verification email resent. Check your inbox.
                  </div>
                ) : (
                  <div className="space-y-3 text-left">
                    {!emailFromState && (
                      <Input
                        type="email"
                        placeholder="Enter your email"
                        value={resendEmail}
                        onChange={(e) => setResendEmail(e.target.value)}
                        icon={<Envelope size={16} weight="duotone" />}
                      />
                    )}
                    <Button
                      variant="secondary"
                      className="w-full"
                      size="md"
                      onClick={handleResend}
                      disabled={isLoading || !resendEmail}
                      loading={isLoading}
                      icon={<PaperPlaneTilt size={16} />}
                    >
                      {emailFromState ? "Didn't get the email? Resend" : 'Resend verification'}
                    </Button>
                  </div>
                )}

                {error && (
                  <div className="flex items-center justify-between gap-2 mt-3 px-3 py-2
                    rounded-lg bg-error-subtle text-error text-xs">
                    <div className="flex items-center gap-1.5">
                      <Warning size={14} weight="fill" />
                      {error}
                    </div>
                    <button
                      onClick={clearError}
                      className="p-0.5 rounded hover:bg-error/10 transition-colors cursor-pointer"
                      aria-label="Dismiss error"
                    >
                      <XCircle size={14} />
                    </button>
                  </div>
                )}
              </div>
            </div>
          )}
        </div>

        {/* ─── Back to sign in ─── */}
        <div className="mt-6 text-center">
          <Link
            to="/login"
            className="inline-flex items-center gap-1.5 text-[13px] text-accent-text
              hover:underline transition-colors"
          >
            <ArrowLeft size={14} />
            Back to sign in
          </Link>
        </div>
      </div>
    </div>
  )
}

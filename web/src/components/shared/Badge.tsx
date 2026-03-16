// ============================================================================
// Operator OS — Badge
// Small status / label indicator using OKLCH token system.
// ============================================================================

import type { ReactNode } from 'react'

type BadgeVariant = 'default' | 'accent' | 'success' | 'warning' | 'error' | 'info'

interface BadgeProps {
  variant?: BadgeVariant
  children: ReactNode
  className?: string
  dot?: boolean
}

const variantClasses: Record<BadgeVariant, string> = {
  default: 'bg-surface-2 text-text-secondary border-border-subtle',
  accent: 'bg-accent-subtle text-accent-text border-transparent',
  success: 'bg-success-subtle text-success border-transparent',
  warning: 'bg-warning-subtle text-warning border-transparent',
  error: 'bg-error-subtle text-error border-transparent',
  info: 'bg-[oklch(0.95_0.02_250)] text-[oklch(0.5_0.15_250)] border-transparent dark:bg-[oklch(0.25_0.04_250)] dark:text-[oklch(0.72_0.14_250)]',
}

const dotColors: Record<BadgeVariant, string> = {
  default: 'bg-text-dim',
  accent: 'bg-accent',
  success: 'bg-success',
  warning: 'bg-warning',
  error: 'bg-error',
  info: 'bg-[oklch(0.55_0.18_250)]',
}

export function Badge({ variant = 'default', children, className = '', dot }: BadgeProps) {
  return (
    <span
      className={`
        inline-flex items-center gap-1.5
        px-2 py-0.5 rounded-full
        text-[11px] font-semibold leading-none tracking-wide
        border
        ${variantClasses[variant]}
        ${className}
      `}
    >
      {dot && (
        <span className={`w-1.5 h-1.5 rounded-full ${dotColors[variant]}`} />
      )}
      {children}
    </span>
  )
}

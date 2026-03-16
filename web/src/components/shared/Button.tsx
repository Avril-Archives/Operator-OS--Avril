// ============================================================================
// Operator OS — Button
// Themed button with variant support. Uses OKLCH token system.
// ============================================================================

import { forwardRef, type ButtonHTMLAttributes, type ReactNode } from 'react'

type Variant = 'primary' | 'secondary' | 'ghost' | 'danger'
type Size = 'sm' | 'md' | 'lg'

interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: Variant
  size?: Size
  icon?: ReactNode
  /** Render as icon-only button (square, no text padding) */
  iconOnly?: boolean
  loading?: boolean
}

const variantClasses: Record<Variant, string> = {
  primary:
    'bg-accent text-white hover:opacity-90 active:scale-[0.97] shadow-[0_2px_8px_var(--glass-shadow)]',
  secondary:
    'bg-surface-2 text-text border border-border hover:bg-surface-3 active:scale-[0.97]',
  ghost:
    'bg-transparent text-text-secondary hover:text-text hover:bg-surface-2/50',
  danger:
    'bg-error text-white hover:opacity-90 active:scale-[0.97]',
}

const sizeClasses: Record<Size, string> = {
  sm: 'h-8 px-3 text-xs gap-1.5 rounded-lg',
  md: 'h-10 px-4 text-sm gap-2 rounded-[var(--radius-md)]',
  lg: 'h-12 px-6 text-[15px] gap-2.5 rounded-[var(--radius)]',
}

const iconOnlySizeClasses: Record<Size, string> = {
  sm: 'h-8 w-8 text-xs rounded-lg',
  md: 'h-10 w-10 text-sm rounded-[var(--radius-md)]',
  lg: 'h-12 w-12 text-[15px] rounded-[var(--radius)]',
}

export const Button = forwardRef<HTMLButtonElement, ButtonProps>(
  ({ variant = 'primary', size = 'md', icon, iconOnly, loading, children, className = '', disabled, ...props }, ref) => {
    return (
      <button
        ref={ref}
        disabled={disabled || loading}
        className={`
          inline-flex items-center justify-center font-medium
          transition-all duration-150 select-none
          focus-ring cursor-pointer
          disabled:opacity-40 disabled:cursor-not-allowed disabled:pointer-events-none
          ${variantClasses[variant]}
          ${iconOnly ? iconOnlySizeClasses[size] : sizeClasses[size]}
          ${className}
        `}
        {...props}
      >
        {loading ? (
          <span className="w-4 h-4 border-2 border-current border-t-transparent rounded-full animate-spin" />
        ) : icon ? (
          <span className="shrink-0">{icon}</span>
        ) : null}
        {!iconOnly && children}
      </button>
    )
  },
)

Button.displayName = 'Button'

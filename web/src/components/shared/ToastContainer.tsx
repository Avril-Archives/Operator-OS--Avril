// ============================================================================
// Operator OS — Toast Container
// Renders floating toast notifications. Positioned bottom-right (desktop) or
// top-center (mobile). Animated entry/exit with OKLCH-themed variants.
// ============================================================================

import { memo, useEffect, useState } from 'react'
import {
  CheckCircle,
  WarningCircle,
  Warning,
  Info,
  X,
} from '@phosphor-icons/react'
import { useToastStore, type Toast, type ToastVariant } from '../../stores/toastStore'

// ---------------------------------------------------------------------------
// Variant config — uses CSS custom properties for theme-aware colors
// ---------------------------------------------------------------------------

const VARIANT_CONFIG: Record<
  ToastVariant,
  { icon: typeof CheckCircle; iconClass: string; borderClass: string }
> = {
  success: {
    icon: CheckCircle,
    iconClass: 'text-success',
    borderClass: 'border-[var(--success)]/30',
  },
  error: {
    icon: WarningCircle,
    iconClass: 'text-error',
    borderClass: 'border-[var(--error)]/30',
  },
  warning: {
    icon: Warning,
    iconClass: 'text-warning',
    borderClass: 'border-[var(--warning)]/30',
  },
  info: {
    icon: Info,
    iconClass: 'text-[var(--accent-text)]',
    borderClass: 'border-[var(--accent)]/30',
  },
}

// ---------------------------------------------------------------------------
// Single toast item
// ---------------------------------------------------------------------------

const ToastItem = memo(function ToastItem({ toast: t }: { toast: Toast }) {
  const dismiss = useToastStore((s) => s.dismiss)
  const [exiting, setExiting] = useState(false)
  const [visible, setVisible] = useState(false)

  // Entrance animation
  useEffect(() => {
    const raf = requestAnimationFrame(() => setVisible(true))
    return () => cancelAnimationFrame(raf)
  }, [])

  // Exit animation before dismiss
  const handleDismiss = () => {
    setExiting(true)
    setTimeout(() => dismiss(t.id), 200)
  }

  // Auto-dismiss: start exit slightly before store removes it
  useEffect(() => {
    if (t.duration && t.duration > 0) {
      const timer = setTimeout(() => setExiting(true), t.duration - 200)
      return () => clearTimeout(timer)
    }
  }, [t.duration])

  const config = VARIANT_CONFIG[t.variant]
  const Icon = config.icon

  return (
    <div
      role="alert"
      aria-live="assertive"
      className={`
        relative flex items-start gap-3 px-4 py-3 rounded-xl border shadow-lg
        max-w-sm w-full backdrop-blur-md
        bg-[var(--surface)] ${config.borderClass}
        transition-all duration-200 ease-out
        ${visible && !exiting ? 'opacity-100 translate-y-0' : 'opacity-0 translate-y-2'}
      `}
    >
      <Icon
        size={20}
        weight="fill"
        className={`shrink-0 mt-0.5 ${config.iconClass}`}
        aria-hidden="true"
      />
      <div className="flex-1 min-w-0">
        <p className="text-sm font-medium text-[var(--text)]">{t.title}</p>
        {t.message && (
          <p className="text-xs text-[var(--text-dim)] mt-0.5 line-clamp-2">{t.message}</p>
        )}
        {t.action && (
          <button
            onClick={() => {
              t.action!.onClick()
              handleDismiss()
            }}
            className="text-xs font-medium text-[var(--accent-text)] hover:underline mt-1.5 cursor-pointer"
          >
            {t.action.label}
          </button>
        )}
      </div>
      {t.dismissible && (
        <button
          onClick={handleDismiss}
          className="shrink-0 p-0.5 rounded-md text-[var(--text-dim)] hover:text-[var(--text)]
            hover:bg-[var(--surface-2)] transition-colors cursor-pointer"
          aria-label="Dismiss notification"
        >
          <X size={14} />
        </button>
      )}
    </div>
  )
})

// ---------------------------------------------------------------------------
// Container
// ---------------------------------------------------------------------------

export function ToastContainer() {
  const toasts = useToastStore((s) => s.toasts)

  if (toasts.length === 0) return null

  return (
    <div
      aria-label="Notifications"
      className="fixed z-[100] bottom-20 md:bottom-6 right-4 md:right-6
        flex flex-col-reverse gap-2 items-end
        pointer-events-none"
    >
      {toasts.slice(-5).map((t) => (
        <div key={t.id} className="pointer-events-auto">
          <ToastItem toast={t} />
        </div>
      ))}
    </div>
  )
}

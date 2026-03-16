// ============================================================================
// Operator OS — Tooltip
// Accessible tooltip triggered by hover/focus. Uses OKLCH token system.
// ============================================================================

import { useState, useRef, useEffect, type ReactNode } from 'react'

type Placement = 'top' | 'bottom' | 'left' | 'right'

interface TooltipProps {
  content: string
  children: ReactNode
  placement?: Placement
  /** Delay before showing (ms) */
  delay?: number
  className?: string
}

const placementClasses: Record<Placement, string> = {
  top: 'bottom-full left-1/2 -translate-x-1/2 mb-2',
  bottom: 'top-full left-1/2 -translate-x-1/2 mt-2',
  left: 'right-full top-1/2 -translate-y-1/2 mr-2',
  right: 'left-full top-1/2 -translate-y-1/2 ml-2',
}

export function Tooltip({
  content,
  children,
  placement = 'top',
  delay = 200,
  className = '',
}: TooltipProps) {
  const [visible, setVisible] = useState(false)
  const timeoutRef = useRef<ReturnType<typeof setTimeout>>(null)
  const id = useRef(`tooltip-${Math.random().toString(36).slice(2, 9)}`).current

  const show = () => {
    timeoutRef.current = setTimeout(() => setVisible(true), delay)
  }

  const hide = () => {
    if (timeoutRef.current) clearTimeout(timeoutRef.current)
    setVisible(false)
  }

  useEffect(() => {
    return () => {
      if (timeoutRef.current) clearTimeout(timeoutRef.current)
    }
  }, [])

  return (
    <div
      className={`relative inline-flex ${className}`}
      onMouseEnter={show}
      onMouseLeave={hide}
      onFocus={show}
      onBlur={hide}
    >
      <div aria-describedby={visible ? id : undefined}>
        {children}
      </div>
      {visible && (
        <div
          id={id}
          role="tooltip"
          className={`
            absolute z-50 pointer-events-none
            ${placementClasses[placement]}
            px-2.5 py-1.5 rounded-[var(--radius-sm)]
            bg-[var(--surface-3)] text-[var(--text)]
            text-xs font-medium leading-tight
            border border-[var(--border)]
            shadow-lg
            animate-fade-in
            whitespace-nowrap
          `}
        >
          {content}
        </div>
      )}
    </div>
  )
}

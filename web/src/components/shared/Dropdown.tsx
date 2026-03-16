// ============================================================================
// Operator OS — Dropdown
// Accessible dropdown menu with keyboard navigation. Uses OKLCH token system.
// ============================================================================

import {
  useState,
  useRef,
  useEffect,
  useCallback,
  type ReactNode,
  type KeyboardEvent as ReactKeyboardEvent,
} from 'react'

export interface DropdownItem {
  id: string
  label: string
  icon?: ReactNode
  danger?: boolean
  disabled?: boolean
  onSelect: () => void
}

interface DropdownProps {
  trigger: ReactNode
  items: DropdownItem[]
  /** Alignment relative to trigger */
  align?: 'start' | 'end'
  className?: string
}

export function Dropdown({ trigger, items, align = 'end', className = '' }: DropdownProps) {
  const [open, setOpen] = useState(false)
  const [focusIndex, setFocusIndex] = useState(-1)
  const containerRef = useRef<HTMLDivElement>(null)
  const menuRef = useRef<HTMLDivElement>(null)

  // Close on outside click
  useEffect(() => {
    if (!open) return
    const handler = (e: MouseEvent) => {
      if (containerRef.current && !containerRef.current.contains(e.target as Node)) {
        setOpen(false)
      }
    }
    document.addEventListener('mousedown', handler)
    return () => document.removeEventListener('mousedown', handler)
  }, [open])

  // Close on Escape
  useEffect(() => {
    if (!open) return
    const handler = (e: globalThis.KeyboardEvent) => {
      if (e.key === 'Escape') {
        setOpen(false)
        setFocusIndex(-1)
      }
    }
    document.addEventListener('keydown', handler)
    return () => document.removeEventListener('keydown', handler)
  }, [open])

  // Focus active item
  useEffect(() => {
    if (!open || focusIndex < 0) return
    const el = menuRef.current?.querySelectorAll('[role="menuitem"]')[focusIndex] as HTMLElement | undefined
    el?.focus()
  }, [open, focusIndex])

  const enabledItems = items.filter((i) => !i.disabled)

  const handleKeyDown = useCallback(
    (e: ReactKeyboardEvent) => {
      if (!open) {
        if (e.key === 'ArrowDown' || e.key === 'Enter' || e.key === ' ') {
          e.preventDefault()
          setOpen(true)
          setFocusIndex(0)
        }
        return
      }

      switch (e.key) {
        case 'ArrowDown':
          e.preventDefault()
          setFocusIndex((prev) => {
            const next = prev + 1
            return next >= enabledItems.length ? 0 : next
          })
          break
        case 'ArrowUp':
          e.preventDefault()
          setFocusIndex((prev) => {
            const next = prev - 1
            return next < 0 ? enabledItems.length - 1 : next
          })
          break
        case 'Home':
          e.preventDefault()
          setFocusIndex(0)
          break
        case 'End':
          e.preventDefault()
          setFocusIndex(enabledItems.length - 1)
          break
        case 'Enter':
        case ' ':
          e.preventDefault()
          if (focusIndex >= 0 && focusIndex < enabledItems.length) {
            enabledItems[focusIndex].onSelect()
            setOpen(false)
            setFocusIndex(-1)
          }
          break
      }
    },
    [open, focusIndex, enabledItems],
  )

  const toggle = () => {
    setOpen((prev) => !prev)
    if (!open) setFocusIndex(-1)
  }

  return (
    <div ref={containerRef} className={`relative inline-flex ${className}`} onKeyDown={handleKeyDown}>
      {/* ─── Trigger ─── */}
      <div
        onClick={toggle}
        role="button"
        tabIndex={0}
        aria-haspopup="menu"
        aria-expanded={open}
      >
        {trigger}
      </div>

      {/* ─── Menu ─── */}
      {open && (
        <div
          ref={menuRef}
          role="menu"
          className={`
            absolute z-50 mt-1 top-full
            ${align === 'end' ? 'right-0' : 'left-0'}
            min-w-[160px] py-1
            bg-[var(--surface)] border border-[var(--border)]
            rounded-[var(--radius-md)] shadow-xl
            animate-scale-in origin-top
          `}
        >
          {items.map((item) => (
            <button
              key={item.id}
              role="menuitem"
              tabIndex={-1}
              disabled={item.disabled}
              onClick={() => {
                if (!item.disabled) {
                  item.onSelect()
                  setOpen(false)
                  setFocusIndex(-1)
                }
              }}
              className={`
                w-full flex items-center gap-2.5 px-3 py-2 text-left
                text-sm transition-colors duration-100
                focus:outline-none
                ${item.disabled
                  ? 'opacity-40 cursor-not-allowed'
                  : item.danger
                    ? 'text-[var(--error)] hover:bg-[var(--error-subtle)] focus:bg-[var(--error-subtle)]'
                    : 'text-[var(--text)] hover:bg-[var(--surface-2)] focus:bg-[var(--surface-2)]'
                }
              `}
            >
              {item.icon && <span className="shrink-0 text-current opacity-70">{item.icon}</span>}
              {item.label}
            </button>
          ))}
        </div>
      )}
    </div>
  )
}

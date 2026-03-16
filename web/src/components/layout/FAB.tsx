// ============================================================================
// Operator OS — Floating Action Button
// Quick-action FAB for mobile: new chat, new agent. Positioned above BottomTabs.
// ============================================================================

import { useState, useEffect, useRef } from 'react'
import { useNavigate, useLocation } from 'react-router-dom'
import { Plus, ChatCircle, Robot, X } from '@phosphor-icons/react'
import { useSessionStore } from '../../stores/sessionStore'

export function FAB() {
  const [open, setOpen] = useState(false)
  const containerRef = useRef<HTMLDivElement>(null)
  const navigate = useNavigate()
  const location = useLocation()
  const createSession = useSessionStore((s) => s.createSession)

  // Close when navigating
  useEffect(() => {
    setOpen(false)
  }, [location.pathname])

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

  const handleNewChat = async () => {
    setOpen(false)
    await createSession({ name: 'New Chat' })
    navigate('/chat')
  }

  const handleNewAgent = () => {
    setOpen(false)
    navigate('/agents')
  }

  return (
    <div
      ref={containerRef}
      className="md:hidden fixed z-90 right-4"
      style={{ bottom: 'calc(var(--bottom-tabs-h) + 12px)' }}
    >
      {/* ─── Speed-dial actions ─── */}
      {open && (
        <div className="absolute bottom-full right-0 mb-3 flex flex-col gap-2 items-end animate-fade-in">
          <button
            onClick={handleNewChat}
            className="flex items-center gap-2.5 px-4 py-2.5
              bg-[var(--surface)] border border-[var(--border)]
              rounded-[var(--radius-md)] shadow-lg
              text-sm font-medium text-[var(--text)]
              hover:bg-[var(--surface-2)] transition-colors
              active:scale-95 min-h-[44px]"
            aria-label="New chat"
          >
            <ChatCircle size={18} weight="bold" />
            New Chat
          </button>
          <button
            onClick={handleNewAgent}
            className="flex items-center gap-2.5 px-4 py-2.5
              bg-[var(--surface)] border border-[var(--border)]
              rounded-[var(--radius-md)] shadow-lg
              text-sm font-medium text-[var(--text)]
              hover:bg-[var(--surface-2)] transition-colors
              active:scale-95 min-h-[44px]"
            aria-label="New agent"
          >
            <Robot size={18} weight="bold" />
            New Agent
          </button>
        </div>
      )}

      {/* ─── Main FAB button ─── */}
      <button
        onClick={() => setOpen((prev) => !prev)}
        aria-label={open ? 'Close quick actions' : 'Quick actions'}
        aria-expanded={open}
        className={`
          w-12 h-12 rounded-full flex items-center justify-center
          shadow-lg transition-all duration-200
          active:scale-90
          ${open
            ? 'bg-[var(--surface-3)] text-[var(--text)] rotate-0'
            : 'bg-[var(--accent)] text-white'
          }
        `}
      >
        {open ? <X size={22} weight="bold" /> : <Plus size={22} weight="bold" />}
      </button>
    </div>
  )
}

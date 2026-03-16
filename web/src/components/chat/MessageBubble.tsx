// ============================================================================
// Operator OS — MessageBubble
// Renders a single chat message: user, agent, or system.
// Ports visual treatment from legacy index.html (OKLCH tokens, border radii,
// font sizing, spacing). Agent messages render markdown via MarkdownRenderer.
// ============================================================================

import { memo } from 'react'
import { Robot } from '@phosphor-icons/react'
import type { ChatMessage } from '../../stores/chatStore'
import { MarkdownRenderer } from './MarkdownRenderer'

interface MessageBubbleProps {
  message: ChatMessage
  /** Whether to show the timestamp (e.g. first in a group, or >2min gap) */
  showTimestamp?: boolean
  /** Whether to show the role avatar (first message in a group) */
  showAvatar?: boolean
}

function formatTime(iso: string): string {
  try {
    const d = new Date(iso)
    return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
  } catch {
    return ''
  }
}

function MessageBubbleInner({ message, showTimestamp = false, showAvatar = false }: MessageBubbleProps) {
  const { role, content, streaming, cancelled } = message

  // ── System message ──
  if (role === 'system') {
    return (
      <div className="flex justify-center py-2 animate-fade-slide" role="status">
        <div className="text-[11px] text-[var(--text-dim)] px-4 py-1.5 max-w-[90%] text-center
          bg-[var(--surface-2)]/50 rounded-full border border-[var(--border-subtle)]">
          {content}
        </div>
      </div>
    )
  }

  // ── User message ──
  if (role === 'user') {
    return (
      <div className="flex flex-col items-end gap-1 py-1 animate-fade-slide" role="listitem" aria-label={`You said: ${content.slice(0, 100)}`}>
        <div
          className="max-w-[680px] w-fit bg-[var(--user-bg)] border border-[var(--user-border)]
            rounded-[var(--radius)] rounded-br-[var(--radius-xs)]
            px-4 py-3 text-sm leading-[1.65] whitespace-pre-wrap break-words text-[var(--text)]"
        >
          {content}
        </div>
        {showTimestamp && (
          <span className="text-[10px] text-[var(--text-dim)] mr-1">
            {formatTime(message.createdAt)}
          </span>
        )}
      </div>
    )
  }

  // ── Agent message ──
  return (
    <div className="flex gap-2.5 py-1 animate-fade-slide" role="listitem" aria-label={`Agent said: ${content.slice(0, 100)}`}>
      {/* Agent avatar */}
      {showAvatar ? (
        <div className="shrink-0 w-7 h-7 rounded-lg bg-[var(--accent-subtle)] flex items-center justify-center mt-0.5">
          <Robot size={14} weight="duotone" className="text-[var(--accent-text)]" />
        </div>
      ) : (
        <div className="shrink-0 w-7" />
      )}

      <div className="flex flex-col items-start min-w-0 flex-1">
        <div
          className={`max-w-[680px] w-fit text-[var(--text)]
            ${streaming ? 'animate-pulse-glow rounded-lg px-2 py-1' : ''}`}
        >
          <MarkdownRenderer content={content} streaming={streaming} />
          {streaming && (
            <span className="inline-block w-[2px] h-[1em] bg-[var(--accent)] ml-0.5 align-middle animate-blink" />
          )}
        </div>
        {(showTimestamp || cancelled) && !streaming && (
          <span className="text-[10px] text-[var(--text-dim)] mt-1 ml-0.5">
            {showTimestamp && formatTime(message.createdAt)}
            {message.model && showTimestamp && (
              <span className="ml-1.5 text-[var(--text-dim)]">· {message.model}</span>
            )}
            {cancelled && (
              <span className="ml-1.5 text-[var(--warning)] italic">· stopped</span>
            )}
          </span>
        )}
      </div>
    </div>
  )
}

export const MessageBubble = memo(MessageBubbleInner)

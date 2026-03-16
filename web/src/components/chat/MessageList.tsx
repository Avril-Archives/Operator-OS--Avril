// ============================================================================
// Operator OS — MessageList
// Scrollable container for chat messages. Handles auto-scroll, scroll-to-bottom
// button, timestamp grouping, and the typing indicator.
// ============================================================================

import { useRef, useEffect, useCallback, useState, useMemo } from 'react'
import type { ChatMessage } from '../../stores/chatStore'
import { MessageBubble } from './MessageBubble'
import { TypingIndicator } from './TypingIndicator'
import { ScrollToBottom } from './ScrollToBottom'

interface MessageListProps {
  messages: ChatMessage[]
  isTyping: boolean
  /** Set true while loading history */
  loading?: boolean
  /** ID of the currently streaming message (for auto-scroll during streaming) */
  streamingMessageId?: string | null
}

// Show timestamp if messages are >2 minutes apart or from different roles
function shouldShowTimestamp(
  current: ChatMessage,
  previous: ChatMessage | undefined,
): boolean {
  if (!previous) return true
  if (previous.role !== current.role) return true

  const gap =
    new Date(current.createdAt).getTime() - new Date(previous.createdAt).getTime()
  return gap > 2 * 60 * 1000 // 2 minutes
}

// Show avatar for first message in a group (first overall or role changed)
function shouldShowAvatar(
  current: ChatMessage,
  previous: ChatMessage | undefined,
): boolean {
  if (!previous) return true
  return previous.role !== current.role
}

// Format date label for date separators
function formatDateLabel(iso: string): string {
  const date = new Date(iso)
  const today = new Date()
  const yesterday = new Date(today)
  yesterday.setDate(yesterday.getDate() - 1)

  if (date.toDateString() === today.toDateString()) return 'Today'
  if (date.toDateString() === yesterday.toDateString()) return 'Yesterday'
  return date.toLocaleDateString(undefined, { weekday: 'short', month: 'short', day: 'numeric' })
}

// Check if we should show a date separator between two messages
function shouldShowDateSeparator(
  current: ChatMessage,
  previous: ChatMessage | undefined,
): boolean {
  if (!previous) return true
  const curDate = new Date(current.createdAt).toDateString()
  const prevDate = new Date(previous.createdAt).toDateString()
  return curDate !== prevDate
}

export function MessageList({ messages, isTyping, loading = false, streamingMessageId }: MessageListProps) {
  const containerRef = useRef<HTMLDivElement>(null)
  const bottomRef = useRef<HTMLDivElement>(null)
  const [isAtBottom, setIsAtBottom] = useState(true)
  const [unreadCount, setUnreadCount] = useState(0)

  // ── Detect if user is at bottom ──
  const checkIsAtBottom = useCallback(() => {
    const el = containerRef.current
    if (!el) return true
    // "At bottom" = within 80px of the end
    return el.scrollHeight - el.scrollTop - el.clientHeight < 80
  }, [])

  // ── Scroll to bottom (smooth) ──
  const scrollToBottom = useCallback((behavior: ScrollBehavior = 'smooth') => {
    bottomRef.current?.scrollIntoView({ behavior, block: 'end' })
    setIsAtBottom(true)
    setUnreadCount(0)
  }, [])

  // ── Handle scroll events ──
  const handleScroll = useCallback(() => {
    const atBottom = checkIsAtBottom()
    setIsAtBottom(atBottom)
    if (atBottom) setUnreadCount(0)
  }, [checkIsAtBottom])

  // ── Auto-scroll on new messages if already at bottom ──
  useEffect(() => {
    if (isAtBottom) {
      // Instant scroll for first render, smooth for subsequent
      const behavior = messages.length <= 1 ? 'instant' : 'smooth'
      scrollToBottom(behavior as ScrollBehavior)
    } else {
      // User is scrolled up — increment unread
      const lastMsg = messages[messages.length - 1]
      if (lastMsg && lastMsg.role !== 'user') {
        setUnreadCount((c) => c + 1)
      }
    }
    // Only react to message count changes
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [messages.length])

  // ── Auto-scroll when typing starts ──
  useEffect(() => {
    if (isTyping && isAtBottom) {
      scrollToBottom()
    }
  }, [isTyping, isAtBottom, scrollToBottom])

  // ── Auto-scroll during streaming content growth ──
  // Track content length of streaming message to scroll as tokens arrive
  const streamingContent = streamingMessageId
    ? messages.find((m) => m.id === streamingMessageId)?.content
    : undefined

  useEffect(() => {
    if (streamingContent !== undefined && isAtBottom) {
      // Use instant scroll for streaming to avoid jitter from queued smooth scrolls
      bottomRef.current?.scrollIntoView({ behavior: 'instant', block: 'end' })
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [streamingContent?.length])

  // ── Initial scroll to bottom ──
  useEffect(() => {
    if (messages.length > 0) {
      scrollToBottom('instant' as ScrollBehavior)
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  // Screen reader announcement for new messages
  const lastMessage = messages[messages.length - 1]
  const lastNonStreamingMsg = useMemo(() => {
    if (!lastMessage || lastMessage.streaming) return null
    const prefix = lastMessage.role === 'user' ? 'You' : 'Agent'
    return `${prefix}: ${lastMessage.content.slice(0, 200)}`
  }, [lastMessage?.id, lastMessage?.streaming]) // eslint-disable-line react-hooks/exhaustive-deps

  return (
    <div className="relative flex-1 min-h-0">
      {/* ─── Scrollable message area ─── */}
      <div
        ref={containerRef}
        onScroll={handleScroll}
        className="h-full overflow-y-auto overscroll-contain
          [-webkit-overflow-scrolling:touch]
          [&::-webkit-scrollbar]:w-[3px]
          [&::-webkit-scrollbar-track]:bg-transparent
          [&::-webkit-scrollbar-thumb]:bg-[var(--scrollthumb)]
          [&::-webkit-scrollbar-thumb]:rounded-sm"
      >
        <div className="max-w-3xl mx-auto px-4 md:px-5 pt-6 pb-2 flex flex-col gap-5">
          {/* Loading skeleton placeholder */}
          {loading && (
            <div className="flex justify-center py-4">
              <div className="flex items-center gap-2 text-xs text-[var(--text-dim)]">
                <div className="w-4 h-4 border-2 border-[var(--border)] border-t-[var(--accent)] rounded-full animate-spin" />
                Loading history…
              </div>
            </div>
          )}

          {/* Messages */}
          <div role="list" aria-label="Chat messages">
            {messages.map((msg, i) => {
              const prev = messages[i - 1]
              const showDateSep = shouldShowDateSeparator(msg, prev)
              return (
                <div key={msg.id}>
                  {showDateSep && (
                    <div className="flex items-center gap-3 py-3 select-none" aria-label={`Messages from ${formatDateLabel(msg.createdAt)}`}>
                      <div className="flex-1 h-px bg-[var(--border-subtle)]" />
                      <span className="text-[10px] font-medium text-[var(--text-dim)] uppercase tracking-wider">
                        {formatDateLabel(msg.createdAt)}
                      </span>
                      <div className="flex-1 h-px bg-[var(--border-subtle)]" />
                    </div>
                  )}
                  <MessageBubble
                    message={msg}
                    showTimestamp={shouldShowTimestamp(msg, prev)}
                    showAvatar={shouldShowAvatar(msg, prev)}
                  />
                </div>
              )
            })}
          </div>

          {/* Typing indicator */}
          {isTyping && !messages.some((m) => m.streaming) && <TypingIndicator />}

          {/* Bottom anchor for auto-scroll */}
          <div ref={bottomRef} className="h-px shrink-0" />

          {/* Bottom spacer so messages don't hide behind composer */}
          <div className="h-2 shrink-0 pointer-events-none" />
        </div>
      </div>

      {/* ─── Scroll-to-bottom button ─── */}
      <ScrollToBottom
        visible={!isAtBottom}
        onClick={() => scrollToBottom()}
        unreadCount={unreadCount}
      />

      {/* ─── Screen reader live region for new messages ─── */}
      <div
        aria-live="polite"
        aria-atomic="true"
        className="sr-only"
      >
        {lastNonStreamingMsg}
      </div>
    </div>
  )
}

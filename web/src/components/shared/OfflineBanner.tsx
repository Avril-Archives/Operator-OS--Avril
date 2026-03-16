// ============================================================================
// Operator OS — Offline Banner
// Persistent top-of-page banner when the browser loses network connectivity.
// ============================================================================

import { WifiSlash } from '@phosphor-icons/react'
import { useOnline } from '../../hooks/useOnline'

export function OfflineBanner() {
  const online = useOnline()

  if (online) return null

  return (
    <div
      role="alert"
      className="flex items-center justify-center gap-2 px-4 py-2
        text-xs font-medium shrink-0
        bg-error-subtle text-error
        animate-fade-slide"
    >
      <WifiSlash size={14} weight="bold" aria-hidden="true" />
      <span>You're offline — some features may be unavailable</span>
    </div>
  )
}

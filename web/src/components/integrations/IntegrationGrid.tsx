// ============================================================================
// Operator OS — Integration Grid
// Category-filtered, searchable grid of integration cards.
// Uses shared Skeleton for loading state.
// ============================================================================

import { memo } from 'react'
import { Plugs } from '@phosphor-icons/react'
import { IntegrationCard } from './IntegrationCard'
import { EmptyState } from '../shared/EmptyState'
import { Skeleton } from '../shared/Skeleton'
import type { IntegrationSummary, IntegrationStatus, UserIntegration } from '../../types/api'

interface IntegrationGridProps {
  integrations: IntegrationSummary[]
  statuses: IntegrationStatus[]
  userIntegrations: UserIntegration[]
  onConnect: (integration: IntegrationSummary) => void
  onDisconnect: (integrationId: string) => void
  onReconnect: (integrationId: string) => void
  connectingId: string | null
  disconnectingId: string | null
  loading?: boolean
}

export const IntegrationGrid = memo(function IntegrationGrid({
  integrations,
  statuses,
  userIntegrations,
  onConnect,
  onDisconnect,
  onReconnect,
  connectingId,
  disconnectingId,
  loading,
}: IntegrationGridProps) {
  if (loading) {
    return (
      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
        {Array.from({ length: 6 }).map((_, i) => (
          <IntegrationSkeleton key={i} />
        ))}
      </div>
    )
  }

  if (integrations.length === 0) {
    return (
      <EmptyState
        icon={Plugs}
        title="No integrations found"
        description="Try adjusting your search or filter to find integrations."
      />
    )
  }

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
      {integrations.map((integration) => (
        <IntegrationCard
          key={integration.id}
          integration={integration}
          status={statuses.find((s) => s.integration_id === integration.id)}
          userIntegration={userIntegrations.find((ui) => ui.integration_id === integration.id)}
          onConnect={onConnect}
          onDisconnect={onDisconnect}
          onReconnect={onReconnect}
          connectingId={connectingId}
          disconnectingId={disconnectingId}
        />
      ))}
    </div>
  )
})

// ---------------------------------------------------------------------------
// Loading skeleton — uses shared Skeleton component
// ---------------------------------------------------------------------------

function IntegrationSkeleton() {
  return (
    <div
      className="flex flex-col gap-3 p-4 bg-[var(--surface)] border border-[var(--border-subtle)] rounded-[var(--radius)]"
      aria-hidden="true"
    >
      {/* Header row */}
      <div className="flex items-center gap-3">
        <Skeleton width="w-10" height="h-10" rounded="rounded-xl" />
        <div className="flex-1 flex flex-col gap-1.5">
          <Skeleton width="w-28" height="h-3.5" />
          <Skeleton width="w-16" height="h-2.5" />
        </div>
      </div>
      {/* Description */}
      <Skeleton width="w-full" height="h-3" />
      <Skeleton width="w-3/4" height="h-3" />
      {/* Tools hint */}
      <Skeleton width="w-20" height="h-3" />
      {/* Button */}
      <Skeleton width="w-full" height="h-8" rounded="rounded-lg" className="mt-auto" />
    </div>
  )
}

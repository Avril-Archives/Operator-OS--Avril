// ============================================================================
// Operator OS — Integration Card
// Displays an integration with status, tools, and connect/disconnect actions.
// Uses shared Dropdown for the action menu.
// ============================================================================

import { memo, useState } from 'react'
import {
  Plugs,
  PlugsConnected,
  DotsThreeVertical,
  ArrowsClockwise,
  Trash,
  Wrench,
  CaretDown,
  CaretUp,
  GoogleLogo,
  ShoppingBag,
  GithubLogo,
  SlackLogo,
  Globe,
  Lightning,
} from '@phosphor-icons/react'
import { Badge } from '../shared/Badge'
import { Button } from '../shared/Button'
import { Dropdown, type DropdownItem } from '../shared/Dropdown'
import { StatusBadge } from './StatusBadge'
import type { IntegrationSummary, IntegrationStatus, UserIntegration } from '../../types/api'

interface IntegrationCardProps {
  integration: IntegrationSummary
  status?: IntegrationStatus
  userIntegration?: UserIntegration
  onConnect: (integration: IntegrationSummary) => void
  onDisconnect: (integrationId: string) => void
  onReconnect: (integrationId: string) => void
  connectingId: string | null
  disconnectingId: string | null
}

/** Map integration name/id to an icon */
function IntegrationIcon({ name, size = 24 }: { name: string; size?: number }) {
  const lower = name.toLowerCase()
  if (lower.includes('google')) return <GoogleLogo size={size} weight="fill" />
  if (lower.includes('shopify')) return <ShoppingBag size={size} weight="fill" />
  if (lower.includes('github')) return <GithubLogo size={size} weight="fill" />
  if (lower.includes('slack')) return <SlackLogo size={size} weight="fill" />
  if (lower.includes('zapier') || lower.includes('webhook')) return <Lightning size={size} weight="fill" />
  if (lower.includes('api') || lower.includes('rest')) return <Globe size={size} weight="fill" />
  return <Plugs size={size} weight="fill" />
}

/** Auth type label */
function authTypeLabel(authType: string): string {
  switch (authType) {
    case 'oauth2': return 'OAuth 2.0'
    case 'api_key': return 'API Key'
    case 'none': return 'No Auth'
    default: return authType
  }
}

export const IntegrationCard = memo(function IntegrationCard({
  integration,
  status,
  userIntegration,
  onConnect,
  onDisconnect,
  onReconnect,
  connectingId,
  disconnectingId,
}: IntegrationCardProps) {
  const [toolsExpanded, setToolsExpanded] = useState(false)

  const isConnected = userIntegration?.status === 'active'
  const isFailed = userIntegration?.status === 'failed'
  const isRevoked = userIntegration?.status === 'revoked'
  const isPending = userIntegration?.status === 'pending'
  const isConnecting = connectingId === integration.id
  const isDisconnecting = disconnectingId === integration.id
  const tokenExpired = status?.token_status?.is_expired ?? false
  const needsRefresh = status?.token_status?.needs_refresh ?? false
  const hasIssue = isFailed || isRevoked || tokenExpired || needsRefresh

  const connectionStatus = userIntegration?.status ?? 'disconnected'

  // Build dropdown menu items for connected integrations
  const menuItems: DropdownItem[] = []
  if (isConnected && hasIssue) {
    menuItems.push({
      id: 'reconnect',
      label: 'Reconnect',
      icon: <ArrowsClockwise size={15} />,
      onSelect: () => onReconnect(integration.id),
    })
  }
  if (isConnected) {
    menuItems.push({
      id: 'disconnect',
      label: 'Disconnect',
      icon: <Trash size={15} />,
      danger: true,
      onSelect: () => onDisconnect(integration.id),
    })
  }

  return (
    <div
      className={`
        group relative flex flex-col gap-3 p-4
        bg-[var(--surface)] border border-[var(--border-subtle)]
        rounded-[var(--radius)] transition-all duration-200
        hover:border-[var(--border)] hover:shadow-[0_2px_12px_var(--glass-shadow)]
        ${isConnected && !hasIssue ? 'border-l-[3px] border-l-[var(--success)]' : ''}
        ${hasIssue ? 'border-l-[3px] border-l-[var(--warning)]' : ''}
        animate-fade-slide
      `}
    >
      {/* ─── Header ─── */}
      <div className="flex items-start justify-between gap-2">
        <div className="flex items-center gap-3 min-w-0">
          <div
            className={`
              w-10 h-10 rounded-xl flex items-center justify-center shrink-0
              ${isConnected
                ? 'bg-[var(--success-subtle)] text-[var(--success)]'
                : 'bg-[var(--surface-2)] text-[var(--text-dim)]'
              }
            `}
          >
            <IntegrationIcon name={integration.name} size={22} />
          </div>
          <div className="min-w-0">
            <div className="flex items-center gap-2">
              <h3 className="text-sm font-semibold text-[var(--text)] truncate">
                {integration.name}
              </h3>
              <StatusBadge
                status={connectionStatus as 'active' | 'pending' | 'failed' | 'revoked' | 'disabled' | 'disconnected'}
                tokenExpired={tokenExpired}
                needsRefresh={needsRefresh}
              />
            </div>
            <div className="flex items-center gap-2 mt-0.5">
              <span className="text-[11px] text-[var(--text-dim)]">
                {integration.category}
              </span>
              <span className="text-[var(--border)] text-[11px]">·</span>
              <span className="text-[11px] text-[var(--text-dim)]">
                {authTypeLabel(integration.auth_type)}
              </span>
            </div>
          </div>
        </div>

        {/* ─── Connected menu (shared Dropdown) ─── */}
        {isConnected && menuItems.length > 0 && (
          <Dropdown
            trigger={
              <button
                className="p-1.5 rounded-lg text-[var(--text-dim)]
                  hover:text-[var(--text)] hover:bg-[var(--surface-2)]
                  opacity-0 group-hover:opacity-100 focus:opacity-100
                  transition-all cursor-pointer"
                aria-label={`Actions for ${integration.name}`}
              >
                <DotsThreeVertical size={18} weight="bold" />
              </button>
            }
            items={menuItems}
            align="end"
          />
        )}
      </div>

      {/* ─── Description ─── */}
      <p className="text-xs text-[var(--text-secondary)] line-clamp-2 leading-relaxed">
        {integration.description}
      </p>

      {/* ─── Error message ─── */}
      {userIntegration?.error_message && (
        <div className="text-[11px] text-[var(--error)] bg-[var(--error-subtle)] px-3 py-1.5 rounded-lg">
          {userIntegration.error_message}
        </div>
      )}

      {/* ─── Token health (connected only) ─── */}
      {status && isConnected && (
        <div className="flex items-center gap-3 text-[11px] text-[var(--text-dim)]">
          {status.token_status.has_access_token && (
            <span>
              Token: <span className={tokenExpired ? 'text-[var(--error)]' : 'text-[var(--success)]'}>
                {status.token_status.token_status}
              </span>
            </span>
          )}
          {status.token_status.expires_at && !tokenExpired && (
            <span>
              Expires: {new Date(status.token_status.expires_at).toLocaleDateString()}
            </span>
          )}
          {status.refresh_status.retry_count > 0 && (
            <span className="text-[var(--warning)]">
              Retries: {status.refresh_status.retry_count}/{status.refresh_status.max_retries}
            </span>
          )}
        </div>
      )}

      {/* ─── Tools (expandable) ─── */}
      {integration.tools.length > 0 && (
        <div>
          <button
            onClick={() => setToolsExpanded(!toolsExpanded)}
            className="flex items-center gap-1.5 text-[11px] text-[var(--text-dim)]
              hover:text-[var(--text-secondary)] transition-colors cursor-pointer"
          >
            <Wrench size={12} />
            <span>{integration.tools.length} tool{integration.tools.length !== 1 ? 's' : ''}</span>
            {toolsExpanded ? <CaretUp size={10} /> : <CaretDown size={10} />}
          </button>

          {toolsExpanded && (
            <div className="mt-2 flex gap-1.5 overflow-x-auto scrollbar-none">
              {integration.tools.map((tool) => (
                <span
                  key={tool.name}
                  title={tool.description}
                  className="shrink-0 px-2 py-0.5 text-[10px] font-mono
                    bg-[var(--surface-2)] text-[var(--text-dim)]
                    rounded-md border border-[var(--border-subtle)]
                    hover:text-[var(--text-secondary)] transition-colors"
                >
                  {tool.name}
                </span>
              ))}
            </div>
          )}
        </div>
      )}

      {/* ─── Required plan ─── */}
      {integration.required_plan && integration.required_plan !== 'free' && (
        <div className="mt-auto pt-1">
          <Badge variant="accent">
            Requires {integration.required_plan}
          </Badge>
        </div>
      )}

      {/* ─── Action button ─── */}
      <div className="mt-auto pt-1">
        {!isConnected && !isPending ? (
          <Button
            variant={hasIssue ? 'secondary' : 'primary'}
            size="sm"
            className="w-full"
            icon={hasIssue ? <ArrowsClockwise size={14} /> : <PlugsConnected size={14} />}
            loading={isConnecting}
            onClick={() => hasIssue ? onReconnect(integration.id) : onConnect(integration)}
          >
            {isFailed || isRevoked ? 'Reconnect' : 'Connect'}
          </Button>
        ) : isPending ? (
          <Button variant="secondary" size="sm" className="w-full" disabled>
            Pending…
          </Button>
        ) : isDisconnecting ? (
          <Button variant="danger" size="sm" className="w-full" loading>
            Disconnecting…
          </Button>
        ) : null}
      </div>
    </div>
  )
})

// ============================================================================
// Operator OS — Agent Card
// Displays an agent's summary: name, model, status, prompt preview, default badge.
// Uses shared Dropdown for accessible action menu.
// ============================================================================

import { memo, useMemo } from 'react'
import {
  Robot,
  DotsThreeVertical,
  PencilSimple,
  TrashSimple,
  Crown,
  Circle,
} from '@phosphor-icons/react'
import { Badge } from '../shared/Badge'
import { Dropdown, type DropdownItem } from '../shared/Dropdown'
import type { Agent } from '../../types/api'

interface AgentCardProps {
  agent: Agent
  onEdit: (agent: Agent) => void
  onDelete: (agent: Agent) => void
  onSetDefault: (agent: Agent) => void
}

export const AgentCard = memo(function AgentCard({
  agent,
  onEdit,
  onDelete,
  onSetDefault,
}: AgentCardProps) {
  const isArchived = agent.status === 'archived'

  const menuItems: DropdownItem[] = useMemo(() => {
    const items: DropdownItem[] = [
      {
        id: 'edit',
        label: 'Edit',
        icon: <PencilSimple size={15} />,
        onSelect: () => onEdit(agent),
      },
    ]
    if (!agent.is_default) {
      items.push({
        id: 'set-default',
        label: 'Set as default',
        icon: <Crown size={15} />,
        onSelect: () => onSetDefault(agent),
      })
    }
    items.push({
      id: 'delete',
      label: 'Delete',
      icon: <TrashSimple size={15} />,
      danger: true,
      onSelect: () => onDelete(agent),
    })
    return items
  }, [agent, onEdit, onDelete, onSetDefault])

  return (
    <div
      className={`
        group relative flex flex-col gap-3 p-4
        bg-[var(--surface)] border border-[var(--border-subtle)]
        rounded-[var(--radius)] transition-all duration-200
        hover:border-[var(--border)] hover:shadow-[0_2px_12px_var(--glass-shadow)]
        ${isArchived ? 'opacity-60' : ''}
        animate-fade-slide
      `}
    >
      {/* ─── Header ─── */}
      <div className="flex items-start justify-between gap-2">
        <div className="flex items-center gap-3 min-w-0">
          <div className="relative shrink-0">
            <div
              className={`
                w-10 h-10 rounded-xl flex items-center justify-center
                ${agent.is_default
                  ? 'bg-[var(--accent-subtle)] text-[var(--accent-text)]'
                  : 'bg-[var(--surface-2)] text-[var(--text-dim)]'
                }
              `}
            >
              <Robot size={22} weight={agent.is_default ? 'fill' : 'regular'} />
            </div>
            {/* Status dot */}
            <Circle
              size={10}
              weight="fill"
              className={`absolute -bottom-0.5 -right-0.5
                ${agent.status === 'active' ? 'text-success' : 'text-[var(--text-dim)]'}
              `}
              aria-label={agent.status === 'active' ? 'Active' : 'Inactive'}
            />
          </div>
          <div className="min-w-0">
            <div className="flex items-center gap-2">
              <h3 className="text-sm font-semibold text-[var(--text)] truncate">
                {agent.name}
              </h3>
              {agent.is_default && (
                <Badge variant="accent" dot>Default</Badge>
              )}
              {isArchived && (
                <Badge variant="warning">Archived</Badge>
              )}
            </div>
            <p className="text-[11px] text-[var(--text-dim)] font-mono mt-0.5 truncate">
              {agent.model}
            </p>
          </div>
        </div>

        {/* ─── Action menu via shared Dropdown ─── */}
        <Dropdown
          items={menuItems}
          align="end"
          trigger={
            <button
              className="p-1.5 rounded-lg text-[var(--text-dim)]
                hover:text-[var(--text)] hover:bg-[var(--surface-2)]
                opacity-0 group-hover:opacity-100 focus:opacity-100
                transition-all cursor-pointer"
              aria-label={`Actions for ${agent.name}`}
            >
              <DotsThreeVertical size={18} weight="bold" />
            </button>
          }
        />
      </div>

      {/* ─── Description ─── */}
      {agent.description && (
        <p className="text-xs text-[var(--text-secondary)] line-clamp-2 leading-relaxed">
          {agent.description}
        </p>
      )}

      {/* ─── System prompt preview ─── */}
      {agent.system_prompt && (
        <div className="rounded-lg bg-[var(--surface-2)] px-3 py-2">
          <p className="text-[11px] text-[var(--text-dim)] font-mono line-clamp-2 leading-relaxed">
            {agent.system_prompt}
          </p>
        </div>
      )}

      {/* ─── Footer meta ─── */}
      <div className="flex items-center justify-between text-[11px] text-[var(--text-dim)] mt-auto pt-1">
        <div className="flex items-center gap-3">
          {agent.tools.length > 0 && (
            <span>{agent.tools.length} tool{agent.tools.length !== 1 ? 's' : ''}</span>
          )}
          {agent.skills.length > 0 && (
            <span>{agent.skills.length} skill{agent.skills.length !== 1 ? 's' : ''}</span>
          )}
          {agent.allowed_integrations.length > 0 && (
            <span title={agent.allowed_integrations.map(s => s.integration_id).join(', ')}>
              {agent.allowed_integrations.length} integration{agent.allowed_integrations.length !== 1 ? 's' : ''}
            </span>
          )}
        </div>
        {agent.temperature !== undefined && (
          <span className="font-mono">temp {agent.temperature}</span>
        )}
      </div>
    </div>
  )
})

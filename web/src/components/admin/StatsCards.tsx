// ============================================================================
// Operator OS — Admin Stats Cards
// Platform-level stat cards: total users, active, pending, suspended.
// ============================================================================

import { memo, useMemo } from 'react'
import { Users, UserCheck, Clock, UserMinus, TrendUp, TrendDown, Minus } from '@phosphor-icons/react'
import type { PlatformStats } from '../../types/api'

interface StatsCardsProps {
  stats: PlatformStats | null
  previousStats?: PlatformStats | null
  loading: boolean
}

interface StatItem {
  label: string
  value: number
  previousValue?: number
  icon: React.ReactNode
  color: string
  bgColor: string
}

function TrendIndicator({ current, previous }: { current: number; previous?: number }) {
  if (previous === undefined || previous === current) {
    return (
      <span className="inline-flex items-center gap-0.5 text-[10px] text-[var(--text-dim)]">
        <Minus size={10} />
        <span>No change</span>
      </span>
    )
  }

  const diff = current - previous
  const isUp = diff > 0
  const pct = previous > 0 ? Math.abs(Math.round((diff / previous) * 100)) : 0

  return (
    <span className={`inline-flex items-center gap-0.5 text-[10px] ${isUp ? 'text-[var(--success)]' : 'text-[var(--error)]'}`}>
      {isUp ? <TrendUp size={10} weight="bold" /> : <TrendDown size={10} weight="bold" />}
      <span>{pct > 0 ? `${pct}%` : `${Math.abs(diff)}`}</span>
    </span>
  )
}

export const StatsCards = memo(function StatsCards({ stats, previousStats, loading }: StatsCardsProps) {
  const items: StatItem[] = useMemo(() => [
    {
      label: 'Total Users',
      value: stats?.total_users ?? 0,
      previousValue: previousStats?.total_users,
      icon: <Users size={20} weight="fill" />,
      color: 'var(--accent-text)',
      bgColor: 'var(--accent-subtle)',
    },
    {
      label: 'Active',
      value: stats?.active_users ?? 0,
      previousValue: previousStats?.active_users,
      icon: <UserCheck size={20} weight="fill" />,
      color: 'var(--success)',
      bgColor: 'oklch(0.85 0.08 145)',
    },
    {
      label: 'Pending',
      value: stats?.pending_users ?? 0,
      previousValue: previousStats?.pending_users,
      icon: <Clock size={20} weight="fill" />,
      color: 'var(--warning)',
      bgColor: 'oklch(0.90 0.08 85)',
    },
    {
      label: 'Suspended',
      value: stats?.suspended_users ?? 0,
      previousValue: previousStats?.suspended_users,
      icon: <UserMinus size={20} weight="fill" />,
      color: 'var(--error)',
      bgColor: 'var(--error-subtle)',
    },
  ], [stats, previousStats])

  if (loading) {
    return (
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        {Array.from({ length: 4 }).map((_, i) => (
          <div
            key={i}
            className="h-[88px] rounded-[var(--radius-md)] bg-[var(--surface-2)] animate-pulse"
          />
        ))}
      </div>
    )
  }

  return (
    <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
      {items.map((item) => (
        <div
          key={item.label}
          className="px-4 py-4 rounded-[var(--radius-md)]
            bg-[var(--surface-2)] border border-[var(--border-subtle)]
            flex items-center gap-3"
        >
          <div
            className="w-10 h-10 rounded-xl flex items-center justify-center shrink-0"
            style={{ backgroundColor: item.bgColor, color: item.color }}
          >
            {item.icon}
          </div>
          <div className="min-w-0">
            <div className="flex items-center gap-2">
              <span className="text-xl font-bold text-[var(--text)] tabular-nums">
                {item.value.toLocaleString()}
              </span>
              {item.previousValue !== undefined && (
                <TrendIndicator current={item.value} previous={item.previousValue} />
              )}
            </div>
            <div className="text-xs text-[var(--text-dim)] truncate">{item.label}</div>
          </div>
        </div>
      ))}
    </div>
  )
})

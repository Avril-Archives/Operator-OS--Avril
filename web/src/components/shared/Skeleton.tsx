// ============================================================================
// Operator OS — Skeleton
// Animated placeholder for loading states. Uses OKLCH token system.
// ============================================================================

interface SkeletonProps {
  /** Width class — e.g. "w-full", "w-24", "w-[120px]" */
  width?: string
  /** Height class — e.g. "h-4", "h-10" */
  height?: string
  /** Border radius — defaults to rounded-lg */
  rounded?: string
  /** Extra classes */
  className?: string
}

export function Skeleton({
  width = 'w-full',
  height = 'h-4',
  rounded = 'rounded-lg',
  className = '',
}: SkeletonProps) {
  return (
    <div
      aria-hidden="true"
      className={`
        ${width} ${height} ${rounded}
        bg-[var(--surface-2)] animate-pulse
        ${className}
      `}
    />
  )
}

/** Pre-composed skeleton for text lines */
export function SkeletonText({
  lines = 3,
  className = '',
}: {
  lines?: number
  className?: string
}) {
  return (
    <div className={`flex flex-col gap-2 ${className}`}>
      {Array.from({ length: lines }, (_, i) => (
        <Skeleton
          key={i}
          height="h-3.5"
          width={i === lines - 1 ? 'w-2/3' : 'w-full'}
        />
      ))}
    </div>
  )
}

/** Pre-composed skeleton for avatar circles */
export function SkeletonAvatar({
  size = 'w-10 h-10',
  className = '',
}: {
  size?: string
  className?: string
}) {
  return <Skeleton width="" height="" rounded="rounded-full" className={`${size} ${className}`} />
}

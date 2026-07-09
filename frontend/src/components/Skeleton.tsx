// ─── Skeleton loading components ───
// Usage: import { Skeleton, SkeletonTable, SkeletonCards } from '../components/Skeleton'

export function Skeleton({ className = '' }: { className?: string }) {
  return <div className={`skeleton ${className}`} />
}

export function SkeletonTable({ rows = 5, cols = 5 }: { rows?: number; cols?: number }) {
  return (
    <div className="table-container">
      <table className="table">
        <thead>
          <tr>
            {Array.from({ length: cols }, (_, i) => (
              <th key={i}><Skeleton className="h-3 w-16" /></th>
            ))}
          </tr>
        </thead>
        <tbody>
          {Array.from({ length: rows }, (_, r) => (
            <tr key={r}>
              {Array.from({ length: cols }, (_, c) => (
                <td key={c}><Skeleton className={`h-3.5 ${c === 0 ? 'w-32' : c === 1 ? 'w-20' : 'w-16'}`} /></td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

export function SkeletonCards({ count = 4 }: { count?: number }) {
  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-5">
      {Array.from({ length: count }, (_, i) => (
        <div key={i} className="glass-card p-5">
          <div className="flex items-center justify-between mb-4">
            <Skeleton className="w-10 h-10 rounded-xl" />
            <Skeleton className="w-14 h-5 rounded-full" />
          </div>
          <Skeleton className="w-16 h-9 mb-2" />
          <Skeleton className="w-24 h-3" />
        </div>
      ))}
    </div>
  )
}

export function SkeletonDetail() {
  return (
    <div className="glass-card p-6 space-y-4">
      <div className="flex items-center gap-3 mb-6">
        <Skeleton className="w-12 h-12 rounded-xl" />
        <div className="flex-1">
          <Skeleton className="w-48 h-5 mb-2" />
          <Skeleton className="w-32 h-3" />
        </div>
      </div>
      {[1, 2, 3].map(i => (
        <div key={i}>
          <Skeleton className="w-24 h-3 mb-2" />
          <Skeleton className="w-full h-16 rounded-lg" />
        </div>
      ))}
    </div>
  )
}

export function SkeletonList({ rows = 6 }: { rows?: number }) {
  return (
    <div className="glass-card p-4 space-y-3">
      {Array.from({ length: rows }, (_, i) => (
        <div key={i} className="flex items-center gap-4 py-2">
          <Skeleton className="w-8 h-8 rounded-lg shrink-0" />
          <div className="flex-1">
            <Skeleton className="w-3/4 h-3.5 mb-1.5" />
            <Skeleton className="w-1/2 h-2.5" />
          </div>
          <Skeleton className="w-16 h-5 rounded-full" />
          <Skeleton className="w-20 h-3" />
        </div>
      ))}
    </div>
  )
}

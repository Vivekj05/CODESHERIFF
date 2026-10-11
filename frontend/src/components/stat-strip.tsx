import { cn } from '@/lib/utils'

/**
 * Big numbers in a row, each with a short label: "1.5M+ developers". The
 * numbers are white Montserrat and the labels grey; hairlines separate them
 * from sm up. Three or four stats read best.
 */
export function StatStrip({ stats, className }: { stats: { value: string; label: string }[]; className?: string }) {
  return (
    <dl className={cn('grid grid-cols-2 gap-y-8 sm:flex sm:divide-x sm:divide-card-edge', className)}>
      {stats.map((s) => (
        <div key={s.label} className="flex flex-col-reverse gap-1 sm:flex-1 sm:px-6 sm:first:pl-0 sm:last:pr-0">
          <dt className="text-sm text-gray-500 dark:text-gray-400">{s.label}</dt>
          <dd className="font-montserrat text-3xl font-semibold tracking-tight tabular-nums sm:text-4xl">{s.value}</dd>
        </div>
      ))}
    </dl>
  )
}

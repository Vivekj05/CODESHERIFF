import * as React from 'react'

import { cn } from '@/lib/utils'

/** A grey block that stands in for content while it loads. It pulses gently, and holds still for reduced motion. */
function Skeleton({ className, ...props }: React.ComponentProps<'div'>) {
  return <div data-slot="skeleton" aria-hidden="true" className={cn('rounded-md bg-black/[0.06] motion-safe:animate-pulse dark:bg-white/[0.06]', className)} {...props} />
}

export { Skeleton }

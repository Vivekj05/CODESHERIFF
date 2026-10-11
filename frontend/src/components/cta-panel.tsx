import { ArrowUpRight } from 'lucide-react'
import * as React from 'react'

import { cn } from '@/lib/utils'

/**
 * The closing call to action (cohorts/cta.tsx): a panel in the opposite
 * colour of the page (near-black on light, white on dark) with a faint
 * grain, a big heading, a tagline and one asymmetric button, also inverted.
 * One per page, at the end.
 */
export function CtaPanel({
  heading,
  tagline,
  action,
  className,
}: {
  heading: React.ReactNode
  tagline?: React.ReactNode
  action: { label: string; href: string; external?: boolean }
  className?: string
}) {
  const id = React.useId()
  return (
    <section className={cn('relative w-full', className)} aria-labelledby={`${id}-h`}>
      <div className="relative overflow-hidden rounded-2xl bg-[#111] px-5 sm:rounded-3xl sm:px-6 dark:bg-white">
        <svg className="pointer-events-none absolute inset-0 size-full opacity-10 [mask-image:radial-gradient(#fff,transparent_75%)] dark:invert" aria-hidden="true">
          <filter id={id}>
            <feTurbulence type="fractalNoise" baseFrequency="0.9" numOctaves="3" stitchTiles="stitch" />
            <feColorMatrix type="saturate" values="0" />
          </filter>
          <rect width="100%" height="100%" filter={`url(#${id})`} />
        </svg>
        <div className="relative py-10 sm:px-6 sm:py-20 lg:px-[4.5rem]">
          <h2 id={`${id}-h`} className="mx-auto text-2xl font-medium tracking-[-0.015em] text-balance text-white sm:text-3xl md:text-center md:text-5xl dark:text-black">
            {heading}
          </h2>
          {tagline && <p className="mx-auto mt-3 max-w-2xl text-sm leading-6 text-neutral-200 sm:mt-4 sm:text-base md:text-center dark:text-neutral-500">{tagline}</p>}
          <div className="relative z-10 mx-auto mt-5 flex sm:mt-6 md:justify-center">
            <a
              href={action.href}
              {...(action.external ? { target: '_blank', rel: 'noopener noreferrer' } : {})}
              className="btn-asym inline-flex h-10 w-full items-center justify-center gap-2 bg-white px-6 text-sm font-medium text-black transition-colors duration-200 outline-none hover:bg-neutral-200 focus-visible:ring-[3px] focus-visible:ring-white/50 sm:w-auto dark:bg-neutral-900 dark:text-white dark:hover:bg-black"
            >
              {action.label}
              <ArrowUpRight className="-ml-1 size-4" aria-hidden="true" />
            </a>
          </div>
        </div>
      </div>
    </section>
  )
}

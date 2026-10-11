import { ArrowUpRight, ChevronsDown } from 'lucide-react'
import * as React from 'react'

import { cn } from '@/lib/utils'
import { AnimatedBadge } from '@/components/animated-badge'
import { buttonVariants } from '@/components/chai/button'

type Action = { label: string; href: string; external?: boolean }

/**
 * chaicode.com's hero (landing/hero.tsx): a badge, a big tight headline, a
 * lead with one highlighted phrase, the solid and outline pair, and one
 * piece of media whose edges fade out. One central element only: the media
 * slot takes a single image or card, never a cluster of floating ones.
 * Without media the hero centres itself.
 *
 * It sizes itself by container queries, not the viewport, so it also lays
 * out right in a sidebar layout or a narrow column.
 */
export function Hero({
  badge,
  title,
  children,
  primary,
  secondary,
  media,
  className,
}: {
  badge?: React.ReactNode
  title: React.ReactNode
  /** The lead. Put one <Highlight> in it. */
  children?: React.ReactNode
  primary?: Action
  secondary?: Action
  media?: React.ReactNode
  className?: string
}) {
  const centred = !media
  const ext = (a: Action) => (a.external ? { target: '_blank', rel: 'noopener noreferrer' } : {})
  return (
    <section className={cn('@container w-full', className)}>
      <div className={cn('flex flex-col gap-4 @3xl:gap-8', !centred && '@3xl:flex-row', centred && 'items-center text-center')}>
        <div className={cn('my-auto flex flex-col gap-y-2.5 @xl:gap-y-4', centred ? 'items-center' : '@3xl:w-3/4')}>
          {badge && <AnimatedBadge className="mb-4 @xl:mb-6">{badge}</AnimatedBadge>}
          <h1 className="relative z-10 max-w-6xl text-[42px] leading-11 font-semibold tracking-tight text-black @3xl:text-6xl @3xl:leading-none @5xl:text-7xl dark:text-white">
            {title}
          </h1>
          {children && <p className="relative z-10 mt-4 max-w-3xl text-base text-neutral-700 @xl:mt-6 @3xl:text-xl dark:text-neutral-400">{children}</p>}
          {(primary || secondary) && (
            <div className={cn('mt-6 flex flex-wrap items-center gap-4', centred && 'justify-center')}>
              {primary && (
                <a href={primary.href} {...ext(primary)} className={buttonVariants({ variant: 'solid' })}>
                  {primary.label}
                  <ArrowUpRight className="-ml-1" aria-hidden="true" />
                </a>
              )}
              {secondary && (
                <a href={secondary.href} {...ext(secondary)} className={buttonVariants({ variant: 'outline' })}>
                  {secondary.label}
                  <ChevronsDown className="-ml-1" aria-hidden="true" />
                </a>
              )}
            </div>
          )}
        </div>
        {media && <div className="relative [mask-image:radial-gradient(60%_60%,#000_70%,transparent)] @3xl:w-2/4">{media}</div>}
      </div>
    </section>
  )
}


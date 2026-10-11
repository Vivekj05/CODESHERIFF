'use client'

import * as TabsPrimitive from '@radix-ui/react-tabs'
import * as React from 'react'

import { cn } from '@/lib/utils'

/**
 * Tabs on Radix: arrow keys move between them, Home and End jump to the ends.
 *
 * - `variant="line"` (default): grey text, the active tab in white with a
 *   1px white rule under it. For sections of a page.
 * - `variant="segmented"`: the toolbar box with the warm brown active
 *   segment, the same as Segmented. For switching views.
 */
const TabsVariant = React.createContext<'line' | 'segmented'>('line')

function Tabs({ className, ...props }: React.ComponentProps<typeof TabsPrimitive.Root>) {
  return <TabsPrimitive.Root data-slot="tabs" className={cn('flex flex-col gap-4', className)} {...props} />
}

function TabsList({ className, variant = 'line', ...props }: React.ComponentProps<typeof TabsPrimitive.List> & { variant?: 'line' | 'segmented' }) {
  return (
    <TabsVariant value={variant}>
      <TabsPrimitive.List
        data-slot="tabs-list"
        className={cn(
          'flex max-w-full overflow-x-auto [scrollbar-width:none]',
          variant === 'line'
            ? 'gap-5 border-b border-border'
            : 'w-fit rounded-md border border-gray-200 bg-white dark:border-gray-800 dark:bg-black/50',
          className,
        )}
        {...props}
      />
    </TabsVariant>
  )
}

function TabsTrigger({ className, ...props }: React.ComponentProps<typeof TabsPrimitive.Trigger>) {
  const variant = React.use(TabsVariant)
  return (
    <TabsPrimitive.Trigger
      data-slot="tabs-trigger"
      className={cn(
        "inline-flex shrink-0 cursor-pointer items-center gap-2 text-sm whitespace-nowrap transition-colors duration-150 outline-none focus-visible:ring-2 focus-visible:ring-ring/50 disabled:pointer-events-none disabled:opacity-50 [&_svg:not([class*='size-'])]:size-4",
        variant === 'line'
          ? '-mb-px border-b border-transparent pt-1 pb-2.5 font-medium text-muted-foreground hover:text-foreground data-[state=active]:border-foreground data-[state=active]:text-foreground'
          : 'h-9 px-3.5 text-[13px] text-gray-600 hover:bg-orange-50 hover:text-orange-900 focus-visible:ring-inset data-[state=active]:bg-orange-100 data-[state=active]:text-orange-900 dark:text-gray-400 dark:hover:bg-orange-900/20 dark:hover:text-orange-100 dark:data-[state=active]:bg-orange-900/40 dark:data-[state=active]:text-orange-100',
        className,
      )}
      {...props}
    />
  )
}

function TabsContent({ className, ...props }: React.ComponentProps<typeof TabsPrimitive.Content>) {
  return <TabsPrimitive.Content data-slot="tabs-content" className={cn('outline-none focus-visible:ring-2 focus-visible:ring-ring/50', className)} {...props} />
}

export { Tabs, TabsContent, TabsList, TabsTrigger }

import * as React from 'react'

import { cn } from '@/lib/utils'

/**
 * Chai Prep's sheet table (`.ui-table`): inside a warm hairline frame,
 * uppercase data-label heads (one of the few places caps are allowed),
 * hairline rows that lighten on hover. Wide tables scroll sideways inside
 * the frame, never the page.
 */
function Table({ className, ...props }: React.ComponentProps<'table'>) {
  return (
    <div data-slot="table-frame" className="relative w-full overflow-x-auto rounded-xl border border-card-edge bg-card-fill backdrop-blur-sm">
      <table data-slot="table" className={cn('w-full border-collapse text-left text-sm', className)} {...props} />
    </div>
  )
}

function TableHeader({ className, ...props }: React.ComponentProps<'thead'>) {
  return <thead data-slot="table-header" className={cn('[&_tr]:border-b [&_tr]:border-card-edge', className)} {...props} />
}

function TableBody({ className, ...props }: React.ComponentProps<'tbody'>) {
  return <tbody data-slot="table-body" className={cn('[&_tr:last-child]:border-0', className)} {...props} />
}

function TableRow({ className, ...props }: React.ComponentProps<'tr'>) {
  return (
    <tr
      data-slot="table-row"
      className={cn('border-b border-border transition-colors duration-150 hover:bg-black/[0.02] data-[state=selected]:bg-black/[0.03] dark:hover:bg-white/[0.03] dark:data-[state=selected]:bg-white/[0.04]', className)}
      {...props}
    />
  )
}

function TableHead({ className, ...props }: React.ComponentProps<'th'>) {
  return (
    <th
      data-slot="table-head"
      scope="col"
      className={cn('h-11 px-3 text-[11px] font-semibold tracking-[0.1em] whitespace-nowrap text-muted-foreground uppercase first:pl-4 last:pr-4', className)}
      {...props}
    />
  )
}

function TableCell({ className, ...props }: React.ComponentProps<'td'>) {
  return <td data-slot="table-cell" className={cn('px-3 py-2.5 align-middle first:pl-4 last:pr-4', className)} {...props} />
}

function TableCaption({ className, ...props }: React.ComponentProps<'caption'>) {
  return <caption data-slot="table-caption" className={cn('caption-bottom px-4 py-3 text-left text-xs text-muted-foreground', className)} {...props} />
}

export { Table, TableBody, TableCaption, TableCell, TableHead, TableHeader, TableRow }

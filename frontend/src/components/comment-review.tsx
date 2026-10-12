"use client";

import Link from "next/link";
import type { ComponentProps } from "react";
import ReactMarkdown, { type Components } from "react-markdown";
import remarkGfm from "remark-gfm";
import { ExternalLink } from "lucide-react";

import { buttonVariants } from "@/components/chai/button";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/chai/tabs";
import { Card, CardContent } from "@/components/ui/card";
import type { AuditDetail } from "@/lib/api";

/**
 * The summary comment this audit posted on the pull request, word for word (D-103).
 *
 * The text is read from the audit's own row. It is never fetched from GitHub, where one comment is
 * edited in place on every push and so only ever shows the latest audit, and never re-rendered,
 * which would show today's wording under an old audit.
 *
 * Markdown is rendered without raw HTML (`skipHtml`), and react-markdown's default URL transform
 * drops `javascript:` links. The body is built from closed sets and numbers, so neither should ever
 * trigger; they are here so a renderer change upstream cannot turn this page into an HTML sink.
 */
export function CommentReview({ audit }: { audit: AuditDetail }) {
  return (
    <section aria-labelledby="review-h" className="flex flex-col gap-4">
      <div className="flex flex-wrap items-end justify-between gap-2">
        <div>
          <h2 id="review-h" className="text-xl font-medium">
            Review
          </h2>
          <p className="text-sm text-muted-foreground">
            The comment this audit posted on the pull request, exactly as it was posted.
          </p>
        </div>
        {audit.github_comment_url && (
          <a
            href={audit.github_comment_url}
            target="_blank"
            rel="noreferrer"
            className={buttonVariants({ variant: "outline", size: "sm" })}
          >
            View comment on GitHub
            <ExternalLink className="-ml-1" aria-hidden="true" />
          </a>
        )}
      </div>

      {audit.comment_replaced_by && (
        <p className="text-sm text-muted-foreground">
          A later push has edited this comment, so GitHub now shows{" "}
          <Link
            href={`/audits/${audit.comment_replaced_by}`}
            className="text-foreground underline underline-offset-4"
          >
            a newer audit&apos;s version
          </Link>
          . Below is what this audit said.
        </p>
      )}

      {audit.github_comment_body ? (
        <Tabs defaultValue="rendered">
          <TabsList>
            <TabsTrigger value="rendered">Rendered</TabsTrigger>
            <TabsTrigger value="markdown">Markdown</TabsTrigger>
          </TabsList>
          <TabsContent value="rendered">
            <Card>
              <CardContent>
                <ReactMarkdown remarkPlugins={[remarkGfm]} skipHtml components={MARKDOWN}>
                  {audit.github_comment_body}
                </ReactMarkdown>
              </CardContent>
            </Card>
          </TabsContent>
          <TabsContent value="markdown">
            <Card>
              <CardContent>
                <pre className="overflow-x-auto font-mono text-xs leading-relaxed whitespace-pre-wrap break-words text-foreground/90">
                  {audit.github_comment_body}
                </pre>
              </CardContent>
            </Card>
          </TabsContent>
        </Tabs>
      ) : (
        <Card>
          <CardContent className="py-8 text-center text-sm text-muted-foreground">
            {emptyReason(audit)}
          </CardContent>
        </Card>
      )}
    </section>
  );
}

/** Why there is no text to show. Each case is a different fact, and none of them is "no review". */
function emptyReason(audit: AuditDetail): string {
  if (audit.github_comment_id !== null) {
    return "This comment was posted before CodeSheriff recorded comment text. Open it on GitHub, though a later push may have edited it since.";
  }
  switch (audit.status) {
    case "queued":
    case "running":
      return "Nothing has been posted yet. The comment is written when the audit finishes.";
    case "superseded":
      return "Nothing was posted: a newer push overtook this audit before it finished, and a comment about a commit no longer at the head would be worse than none.";
    case "failed":
      return "Nothing was posted, because this audit failed.";
    default:
      return "No comment was recorded for this audit.";
  }
}

function MarkdownLink({ href, children, ...rest }: ComponentProps<"a">) {
  return (
    <a
      {...rest}
      href={href}
      target="_blank"
      rel="noreferrer"
      className="text-foreground underline underline-offset-4"
    >
      {children}
    </a>
  );
}

/** GitHub-like comment styling, in the dashboard's own tokens. */
const MARKDOWN: Components = {
  h2: ({ children }) => <h3 className="mb-3 text-lg font-semibold">{children}</h3>,
  h3: ({ children }) => <h4 className="mt-6 mb-2 text-base font-semibold">{children}</h4>,
  p: ({ children }) => <p className="my-2 text-sm leading-relaxed text-foreground/90">{children}</p>,
  strong: ({ children }) => <strong className="font-semibold text-foreground">{children}</strong>,
  a: MarkdownLink,
  blockquote: ({ children }) => (
    <blockquote className="my-3 border-l-2 border-border pl-4 text-muted-foreground [&_p]:text-muted-foreground">
      {children}
    </blockquote>
  ),
  code: ({ children }) => (
    <code className="rounded bg-muted px-1 py-0.5 font-mono text-[0.85em]">{children}</code>
  ),
  ul: ({ children }) => <ul className="my-2 list-disc pl-5 text-sm">{children}</ul>,
  ol: ({ children }) => <ol className="my-2 list-decimal pl-5 text-sm">{children}</ol>,
  table: ({ children }) => (
    <div className="my-3 overflow-x-auto">
      <table className="w-full border-collapse text-sm">{children}</table>
    </div>
  ),
  th: ({ children, style }) => (
    <th style={style} className="border-b border-border px-3 py-2 font-medium text-muted-foreground">
      {children}
    </th>
  ),
  td: ({ children, style }) => (
    <td style={style} className="border-b border-border/60 px-3 py-2 align-top">
      {children}
    </td>
  ),
};

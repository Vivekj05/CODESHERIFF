"use client";

import { useEffect, useRef, useState } from "react";
import { Check, Code, Copy, RefreshCw } from "lucide-react";
import mermaid from "mermaid";

import { Button } from "@/components/ui/button";

interface MermaidViewerProps {
  chart: string;
  className?: string;
}

export function MermaidViewer({ chart, className = "" }: MermaidViewerProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const [svgContent, setSvgContent] = useState<string>("");
  const [error, setError] = useState<string | null>(null);
  const [showSource, setShowSource] = useState<boolean>(false);
  const [copied, setCopied] = useState<boolean>(false);

  useEffect(() => {
    let isMounted = true;

    async function renderChart() {
      if (!chart) return;
      setError(null);

      try {
        mermaid.initialize({
          startOnLoad: false,
          theme: "dark",
          securityLevel: "loose",
          themeVariables: {
            darkMode: true,
            background: "#090d16",
            primaryColor: "#3b82f6",
            primaryTextColor: "#f8fafc",
            primaryBorderColor: "#60a5fa",
            lineColor: "#64748b",
            secondaryColor: "#1e293b",
            tertiaryColor: "#0f172a",
          },
        });

        const id = `mermaid-${Math.random().toString(36).substring(2, 9)}`;
        const { svg } = await mermaid.render(id, chart);
        if (isMounted) {
          setSvgContent(svg);
        }
      } catch (err) {
        if (isMounted) {
          setError(err instanceof Error ? err.message : "Failed to render sequence diagram");
        }
      }
    }

    renderChart();

    return () => {
      isMounted = false;
    };
  }, [chart]);

  function copySource() {
    navigator.clipboard.writeText(chart);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }

  return (
    <div className={`rounded-xl border border-border/80 bg-card/60 backdrop-blur-sm overflow-hidden ${className}`}>
      {/* Viewer Header */}
      <div className="flex items-center justify-between border-b border-border/60 bg-muted/30 px-4 py-2.5">
        <div className="flex items-center gap-2 text-xs font-medium text-foreground">
          <span className="h-2 w-2 rounded-full bg-emerald-400 animate-pulse" />
          <span>Architecture & Control Flow</span>
        </div>

        <div className="flex items-center gap-2">
          <Button
            variant="ghost"
            size="sm"
            onClick={copySource}
            className="h-7 px-2 text-xs gap-1.5 text-muted-foreground hover:text-foreground"
          >
            {copied ? <Check className="h-3 w-3 text-emerald-400" /> : <Copy className="h-3 w-3" />}
            <span>{copied ? "Copied" : "Copy Code"}</span>
          </Button>

          <Button
            variant={showSource ? "secondary" : "ghost"}
            size="sm"
            onClick={() => setShowSource(!showSource)}
            className="h-7 px-2 text-xs gap-1.5 text-muted-foreground hover:text-foreground"
          >
            <Code className="h-3 w-3" />
            <span>{showSource ? "Diagram" : "Source"}</span>
          </Button>
        </div>
      </div>

      {/* Viewer Content */}
      <div className="p-4 sm:p-6 flex items-center justify-center min-h-[300px] overflow-x-auto">
        {showSource ? (
          <pre className="w-full rounded-lg bg-background/90 p-4 font-mono text-xs text-muted-foreground overflow-x-auto border border-border/60">
            {chart}
          </pre>
        ) : error ? (
          <div className="flex flex-col items-center gap-2 text-center text-xs text-destructive p-4">
            <p>Could not render diagram visually:</p>
            <pre className="text-[11px] font-mono bg-destructive/10 p-2 rounded max-w-md overflow-x-auto">
              {error}
            </pre>
            <pre className="mt-2 text-[11px] font-mono bg-muted/40 p-3 rounded text-muted-foreground text-left max-w-md w-full overflow-x-auto">
              {chart}
            </pre>
          </div>
        ) : svgContent ? (
          <div
            ref={containerRef}
            dangerouslySetInnerHTML={{ __html: svgContent }}
            className="w-full flex justify-center [&_svg]:max-w-full [&_svg]:h-auto"
          />
        ) : (
          <div className="flex items-center gap-2 text-xs text-muted-foreground">
            <RefreshCw className="h-3.5 w-3.5 animate-spin" />
            <span>Rendering sequence diagram...</span>
          </div>
        )}
      </div>
    </div>
  );
}

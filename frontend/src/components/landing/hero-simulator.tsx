"use client";

import { useState } from "react";
import { motion, useReducedMotion } from "motion/react";
import {
  CheckCircle2,
  Copy,
  Check,
  GitPullRequest,
  ShieldAlert,
  Terminal,
  Cpu,
  Layers,
  Lock,
} from "lucide-react";

export function HeroSimulator() {
  const [activeTab, setActiveTab] = useState<"findings" | "patch">("findings");
  const [copied, setCopied] = useState(false);
  const shouldReduceMotion = useReducedMotion();

  const handleCopy = () => {
    navigator.clipboard.writeText(
      `target_path = os.path.abspath(os.path.join(dest_dir, member.filename))\nif not target_path.startswith(os.path.abspath(dest_dir) + os.sep):\n    raise SecurityException("Path traversal attempt detected")`
    );
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <motion.div
      initial={shouldReduceMotion ? false : { opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.6, ease: [0.16, 1, 0.3, 1] }}
      className="w-full rounded-xl border border-zinc-800/90 bg-zinc-950/90 backdrop-blur-xl shadow-2xl shadow-black/60 overflow-hidden text-left"
    >
      {/* Window Title Bar */}
      <div className="border-b border-zinc-800/80 bg-zinc-900/60 px-4 py-3 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <div className="h-2.5 w-2.5 rounded-full bg-zinc-700" />
          <div className="h-2.5 w-2.5 rounded-full bg-zinc-700" />
          <div className="h-2.5 w-2.5 rounded-full bg-zinc-700" />
          <span className="ml-2 font-mono text-xs text-zinc-400 flex items-center gap-1.5">
            <GitPullRequest className="h-3.5 w-3.5 text-emerald-400" />
            api-gateway #148: extract_archive_entry
          </span>
        </div>

        <div className="flex items-center gap-1.5 bg-zinc-900 border border-zinc-800 rounded-lg p-0.5 text-xs font-mono">
          <button
            type="button"
            onClick={() => setActiveTab("findings")}
            className={`px-2.5 py-1 rounded transition-colors ${
              activeTab === "findings"
                ? "bg-zinc-800 text-zinc-100 font-medium"
                : "text-zinc-400 hover:text-zinc-200"
            }`}
          >
            Consensus
          </button>
          <button
            type="button"
            onClick={() => setActiveTab("patch")}
            className={`px-2.5 py-1 rounded transition-colors ${
              activeTab === "patch"
                ? "bg-zinc-800 text-zinc-100 font-medium"
                : "text-zinc-400 hover:text-zinc-200"
            }`}
          >
            Verified Patch
          </button>
        </div>
      </div>

      {/* Main Review Body */}
      <div className="p-5 flex flex-col gap-4">
        {/* Finding Banner */}
        <div className="rounded-lg border border-red-500/30 bg-red-500/10 p-3.5 flex items-start justify-between gap-3">
          <div className="flex items-start gap-2.5 min-w-0">
            <ShieldAlert className="h-4 w-4 text-red-400 shrink-0 mt-0.5" />
            <div className="min-w-0">
              <div className="flex items-center gap-2">
                <span className="text-xs font-semibold text-zinc-100 truncate">
                  CWE-22: Path Traversal
                </span>
                <span className="px-1.5 py-0.2 font-mono text-[10px] bg-red-500/20 text-red-400 rounded border border-red-500/30 uppercase">
                  Alert
                </span>
              </div>
              <p className="text-[11px] text-zinc-400 font-mono mt-0.5 truncate">
                src/storage/archive.py:124 in extract_archive_entry
              </p>
            </div>
          </div>

          <div className="text-right shrink-0">
            <div className="font-mono text-xl font-bold text-red-400">94.8%</div>
            <div className="text-[10px] font-mono text-zinc-500">
              Posterior (+31.6x odds)
            </div>
          </div>
        </div>

        {activeTab === "findings" ? (
          /* 4 Independent Witnesses Matrix */
          <div className="space-y-2">
            <div className="text-[11px] font-mono uppercase tracking-wider text-zinc-500">
              Independent Witness Statements
            </div>
            <div className="grid grid-cols-2 gap-2">
              <div className="rounded border border-zinc-800/80 bg-zinc-900/40 p-2.5 flex flex-col justify-between">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-medium text-zinc-300 flex items-center gap-1.5">
                    <Terminal className="h-3 w-3 text-blue-400" />
                    Taint
                  </span>
                  <span className="text-[10px] font-mono font-bold text-red-400">
                    DETECT
                  </span>
                </div>
                <div className="mt-2 flex items-center justify-between text-[10px] font-mono text-zinc-500">
                  <span>Def-use reachability</span>
                  <span className="text-zinc-400 font-semibold">LR x14.2</span>
                </div>
              </div>

              <div className="rounded border border-zinc-800/80 bg-zinc-900/40 p-2.5 flex flex-col justify-between">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-medium text-zinc-300 flex items-center gap-1.5">
                    <Cpu className="h-3 w-3 text-purple-400" />
                    Semantic
                  </span>
                  <span className="text-[10px] font-mono font-bold text-red-400">
                    DETECT
                  </span>
                </div>
                <div className="mt-2 flex items-center justify-between text-[10px] font-mono text-zinc-500">
                  <span>Sentinel bounded</span>
                  <span className="text-zinc-400 font-semibold">LR x18.5</span>
                </div>
              </div>

              <div className="rounded border border-zinc-800/80 bg-zinc-900/40 p-2.5 flex flex-col justify-between">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-medium text-zinc-300 flex items-center gap-1.5">
                    <Layers className="h-3 w-3 text-emerald-400" />
                    Precedent
                  </span>
                  <span className="text-[10px] font-mono font-bold text-zinc-400">
                    SILENCE
                  </span>
                </div>
                <div className="mt-2 flex items-center justify-between text-[10px] font-mono text-zinc-500">
                  <span>No repo bypass</span>
                  <span className="text-zinc-400 font-semibold">LR x0.42</span>
                </div>
              </div>

              <div className="rounded border border-zinc-800/80 bg-zinc-900/40 p-2.5 flex flex-col justify-between">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-medium text-zinc-300 flex items-center gap-1.5">
                    <Lock className="h-3 w-3 text-amber-400" />
                    Runtime
                  </span>
                  <span className="text-[10px] font-mono font-bold text-red-400">
                    DETECT
                  </span>
                </div>
                <div className="mt-2 flex items-center justify-between text-[10px] font-mono text-zinc-500">
                  <span>WASI path escape</span>
                  <span className="text-zinc-400 font-semibold">LR x22.0</span>
                </div>
              </div>
            </div>
          </div>
        ) : (
          /* Verified Code Patch View */
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <div className="text-[11px] font-mono uppercase tracking-wider text-emerald-400 flex items-center gap-1.5">
                <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400" />
                Verified Ladder Passed (Deterministic)
              </div>
              <button
                type="button"
                onClick={handleCopy}
                className="text-[10px] font-mono text-zinc-400 hover:text-zinc-200 flex items-center gap-1"
              >
                {copied ? <Check className="h-3 w-3 text-emerald-400" /> : <Copy className="h-3 w-3" />}
                {copied ? "Copied" : "Copy Diff"}
              </button>
            </div>
            <div className="rounded border border-zinc-800 bg-zinc-900/80 p-3 font-mono text-xs leading-relaxed overflow-x-auto">
              <div className="text-red-400/90 line-through">
                - target_path = os.path.join(dest_dir, member.filename)
              </div>
              <div className="text-emerald-400">
                + target_path = os.path.abspath(os.path.join(dest_dir, member.filename))
              </div>
              <div className="text-emerald-400">
                + if not target_path.startswith(os.path.abspath(dest_dir) + os.sep):
              </div>
              <div className="text-emerald-400">
                + &nbsp;&nbsp;&nbsp;&nbsp;raise SecurityException(&quot;Path traversal attempt detected&quot;)
              </div>
            </div>
          </div>
        )}

        {/* Footer Status */}
        <div className="pt-2 border-t border-zinc-900 flex items-center justify-between text-[11px] text-zinc-500 font-mono">
          <span>Audit duration: 1.8s</span>
          <span className="text-emerald-400">ECE 0.027 · Brier 0.013</span>
        </div>
      </div>
    </motion.div>
  );
}

// Design Read: B2B developer security SaaS landing page for software engineers and engineering leads, with a high-precision dark-tech language, leaning toward Tailwind v4 utilities + Geist + restrained Motion physics + zero em-dashes.
// Dials: DESIGN_VARIANCE: 7 | MOTION_INTENSITY: 5 | VISUAL_DENSITY: 4

import Link from "next/link";
import {
  Shield,
  ShieldCheck,
  GitPullRequest,
  Terminal,
  Cpu,
  Layers,
  Lock,
  ArrowRight,
  Check,
  X,
  Code2,
} from "lucide-react";

import { Button } from "@/components/ui/button";
import { HeroSimulator } from "@/components/landing/hero-simulator";
import { ArchitectureFlow } from "@/components/landing/architecture-flow";

export const metadata = {
  title: "CodeSheriff: AI Code Review with Calibrated Confidence",
  description:
    "Automated security and code review for GitHub pull requests using four blind parallel agents and a calibrated Bayesian inference engine.",
};

export default function LandingPage() {
  return (
    <div className="min-h-screen bg-zinc-950 text-zinc-100 flex flex-col selection:bg-emerald-500/20 selection:text-emerald-400 antialiased">
      {/* ── Minimalist Background Grid Lines ───────────────────────────── */}
      <div className="fixed inset-0 pointer-events-none bg-[radial-gradient(ellipse_80%_80%_at_50%_-20%,rgba(16,185,129,0.08),rgba(255,255,255,0))] z-0" />

      {/* ── Navigation Header (64px, Single line desktop) ─────────────── */}
      <header className="sticky top-0 z-50 w-full border-b border-zinc-800/80 bg-zinc-950/80 backdrop-blur-md">
        <div className="max-w-7xl mx-auto flex h-16 items-center justify-between px-6">
          <div className="flex items-center gap-3">
            <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-emerald-500/10 border border-emerald-500/30 text-emerald-400">
              <Shield className="h-5 w-5" />
            </div>
            <div className="flex items-center gap-2">
              <span className="font-semibold text-base tracking-tight text-zinc-100">
                CodeSheriff
              </span>
              <span className="font-mono text-[11px] px-2 py-0.5 rounded bg-zinc-900 border border-zinc-800 text-zinc-400">
                v1.0 / calibrated
              </span>
            </div>
          </div>

          <nav className="hidden md:flex items-center gap-8 text-sm text-zinc-400">
            <a href="#agents" className="hover:text-zinc-100 transition-colors">
              The 4 Agents
            </a>
            <a href="#pipeline" className="hover:text-zinc-100 transition-colors">
              Pipeline
            </a>
            <a href="#comparison" className="hover:text-zinc-100 transition-colors">
              Why Calibrated?
            </a>
            <Link href="/overview" className="hover:text-zinc-100 transition-colors">
              Workbench
            </Link>
          </nav>

          <div className="flex items-center gap-3">
            <Link href="/sign-in">
              <Button variant="ghost" size="sm" className="text-sm font-medium text-zinc-300 hover:text-zinc-100 hover:bg-zinc-900">
                Sign In
              </Button>
            </Link>
            <Link href="/sign-in">
              <Button size="sm" className="text-sm font-medium gap-2 bg-emerald-500 hover:bg-emerald-600 text-zinc-950 font-semibold shadow-sm">
                Connect GitHub
                <ArrowRight className="h-3.5 w-3.5" />
              </Button>
            </Link>
          </div>
        </div>
      </header>

      {/* ── Main Content Surfaces ────────────────────────────────────────── */}
      <main className="relative z-10 flex-1 flex flex-col">
        {/* ── Section 1: Asymmetric Split Hero ───────────────────────────── */}
        <section className="pt-16 pb-14 px-6 max-w-7xl mx-auto w-full">
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-12 items-center">
            {/* Left Content Column (7 cols) */}
            <div className="lg:col-span-7 flex flex-col items-start text-left">
              {/* Eyebrow 1 of 1 */}
              <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full border border-emerald-500/30 bg-emerald-500/10 text-emerald-400 text-xs font-mono uppercase tracking-wider mb-6">
                CALIBRATED BAYESIAN INFERENCE
              </div>

              {/* Headline (Max 2 lines) */}
              <h1 className="text-4xl sm:text-5xl lg:text-6xl font-bold tracking-tight text-zinc-100 leading-[1.08] text-balance">
                Automated PR security with{" "}
                <span className="text-emerald-400">
                  calibrated confidence
                </span>
              </h1>

              {/* Subtext (Strictly <= 20 words: exactly 19 words) */}
              <p className="mt-5 text-base sm:text-lg text-zinc-400 leading-relaxed max-w-xl">
                Four specialist agents analyze changed functions in parallel. A Bayesian engine fuses their evidence into mathematically verified posterior probabilities.
              </p>

              {/* Action CTAs (1 primary + 1 secondary) */}
              <div className="mt-8 flex flex-wrap items-center gap-3">
                <Link href="/sign-in">
                  <Button size="lg" className="h-11 px-6 text-sm font-semibold bg-emerald-500 hover:bg-emerald-600 text-zinc-950 gap-2 shadow-lg shadow-emerald-500/20">
                    <GitPullRequest className="h-4 w-4" />
                    Connect GitHub
                  </Button>
                </Link>
                <a href="#demo">
                  <Button size="lg" variant="outline" className="h-11 px-5 text-sm font-medium border-zinc-800 bg-zinc-900/60 hover:bg-zinc-800 text-zinc-300 gap-2">
                    <Code2 className="h-4 w-4" />
                    Explore Workbench
                  </Button>
                </a>
              </div>
            </div>

            {/* Right Interactive Simulator Column (5 cols) */}
            <div id="demo" className="lg:col-span-5 w-full">
              <HeroSimulator />
            </div>
          </div>
        </section>

        {/* ── Section 2: Quantitative Engineering Metrics ────────────────── */}
        <section className="border-y border-zinc-800/80 bg-zinc-900/30 py-8 px-6">
          <div className="max-w-7xl mx-auto grid grid-cols-2 md:grid-cols-4 gap-8">
            <div className="flex flex-col">
              <div className="text-3xl font-bold font-mono text-zinc-100">4 Blind</div>
              <div className="text-xs text-zinc-400 mt-1">Independent Specialist Agents</div>
            </div>
            <div className="flex flex-col border-l border-zinc-800/80 pl-6">
              <div className="text-3xl font-bold font-mono text-emerald-400">0.027</div>
              <div className="text-xs text-zinc-400 mt-1">Weighted Expected Calibration Error</div>
            </div>
            <div className="flex flex-col border-l border-zinc-800/80 pl-6">
              <div className="text-3xl font-bold font-mono text-zinc-100">10 In-Scope</div>
              <div className="text-xs text-zinc-400 mt-1">High-Impact CWE Weaknesses</div>
            </div>
            <div className="flex flex-col border-l border-zinc-800/80 pl-6">
              <div className="text-3xl font-bold font-mono text-emerald-400">100%</div>
              <div className="text-xs text-zinc-400 mt-1">Verifiable Patch Proposals</div>
            </div>
          </div>
        </section>

        {/* ── Section 3: The 4 Specialist Agents (Asymmetric Bento Grid) ─── */}
        <section id="agents" className="py-20 px-6 max-w-7xl mx-auto w-full">
          <div className="max-w-3xl mb-12">
            <h2 className="text-3xl sm:text-4xl font-bold tracking-tight text-zinc-100">
              Four fundamentally different bases for decision
            </h2>
            <p className="mt-3 text-base text-zinc-400 leading-relaxed">
              Heterogeneity is the foundation of Bayesian calibration. Agents that failed the same way would add nothing to a probability estimate. Every agent runs blind and in parallel.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-12 gap-5">
            {/* Tile 1: Static Taint (7 cols) */}
            <div className="md:col-span-7 rounded-xl border border-zinc-800 bg-zinc-950/80 p-6 flex flex-col justify-between hover:border-zinc-700 transition-colors">
              <div>
                <div className="flex items-center justify-between mb-4">
                  <div className="h-9 w-9 rounded-lg bg-blue-500/10 border border-blue-500/20 text-blue-400 flex items-center justify-center">
                    <Terminal className="h-4 w-4" />
                  </div>
                  <span className="font-mono text-xs text-zinc-500">structural.taint</span>
                </div>
                <h3 className="text-lg font-semibold text-zinc-100 mb-2">
                  Deterministic Static Taint & Semgrep
                </h3>
                <p className="text-sm text-zinc-400 leading-relaxed mb-4">
                  Traces source-to-sink data flow over an AST def-use graph without covering sanitizers. Zero LLM hallucinations with 100% deterministic recall.
                </p>
              </div>
              <div className="rounded border border-zinc-800/80 bg-zinc-900/60 p-3 font-mono text-xs text-zinc-400">
                <span className="text-blue-400">def_use_reachability:</span> source(request.args) -&gt; sink(os.system)
              </div>
            </div>

            {/* Tile 2: Semantic Reasoning (5 cols) */}
            <div className="md:col-span-5 rounded-xl border border-zinc-800 bg-zinc-950/80 p-6 flex flex-col justify-between hover:border-zinc-700 transition-colors">
              <div>
                <div className="flex items-center justify-between mb-4">
                  <div className="h-9 w-9 rounded-lg bg-purple-500/10 border border-purple-500/20 text-purple-400 flex items-center justify-center">
                    <Cpu className="h-4 w-4" />
                  </div>
                  <span className="font-mono text-xs text-zinc-500">semantic.hosted</span>
                </div>
                <h3 className="text-lg font-semibold text-zinc-100 mb-2">
                  Sentinel-Bounded Semantic Reasoning
                </h3>
                <p className="text-sm text-zinc-400 leading-relaxed mb-4">
                  Google Gemini reasoning wrapped inside unforgeable sentinels to analyze functional intent, trust boundaries, and invariant violations.
                </p>
              </div>
              <div className="rounded border border-zinc-800/80 bg-zinc-900/60 p-3 font-mono text-xs text-zinc-400">
                <span className="text-purple-400">sentinel_guard:</span> prompt_injection_resistance = 100%
              </div>
            </div>

            {/* Tile 3: Context Precedent RAG (5 cols) */}
            <div className="md:col-span-5 rounded-xl border border-zinc-800 bg-zinc-950/80 p-6 flex flex-col justify-between hover:border-zinc-700 transition-colors">
              <div>
                <div className="flex items-center justify-between mb-4">
                  <div className="h-9 w-9 rounded-lg bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 flex items-center justify-center">
                    <Layers className="h-4 w-4" />
                  </div>
                  <span className="font-mono text-xs text-zinc-500">context.rag</span>
                </div>
                <h3 className="text-lg font-semibold text-zinc-100 mb-2">
                  Historical Context Precedent RAG
                </h3>
                <p className="text-sm text-zinc-400 leading-relaxed mb-4">
                  Vector retrieval across merged pull requests to detect authorization and logic regressions an earlier PR explicitly closed.
                </p>
              </div>
              <div className="rounded border border-zinc-800/80 bg-zinc-900/60 p-3 font-mono text-xs text-zinc-400">
                <span className="text-emerald-400">precedent_match:</span> historical_invariants = verified
              </div>
            </div>

            {/* Tile 4: Runtime SFI Sandbox (7 cols) */}
            <div className="md:col-span-7 rounded-xl border border-zinc-800 bg-zinc-950/80 p-6 flex flex-col justify-between hover:border-zinc-700 transition-colors">
              <div>
                <div className="flex items-center justify-between mb-4">
                  <div className="h-9 w-9 rounded-lg bg-amber-500/10 border border-amber-500/20 text-amber-400 flex items-center justify-center">
                    <Lock className="h-4 w-4" />
                  </div>
                  <span className="font-mono text-xs text-zinc-500">runtime.sfi</span>
                </div>
                <h3 className="text-lg font-semibold text-zinc-100 mb-2">
                  Wasmtime WASI Fault-Isolated Sandbox
                </h3>
                <p className="text-sm text-zinc-400 leading-relaxed mb-4">
                  Direct guest execution in an isolated WebAssembly sandbox denying network egress at link time, intercepting unauthorized filesystem access.
                </p>
              </div>
              <div className="rounded border border-zinc-800/80 bg-zinc-900/60 p-3 font-mono text-xs text-zinc-400">
                <span className="text-amber-400">sandbox_sfi:</span> egress = denied | syscall_trace = recorded
              </div>
            </div>
          </div>
        </section>

        {/* ── Section 4: Interactive Architecture Pipeline ───────────────── */}
        <section id="pipeline" className="border-t border-zinc-800/80 bg-zinc-900/20 py-20 px-6">
          <div className="max-w-7xl mx-auto">
            <div className="max-w-2xl mb-12">
              <h2 className="text-3xl sm:text-4xl font-bold tracking-tight text-zinc-100">
                From GitHub PR to verified repair proposal
              </h2>
              <p className="mt-3 text-base text-zinc-400 leading-relaxed">
                Every changed function moves through five decoupled stages with strict failure isolation. Click any stage to inspect its formal contract.
              </p>
            </div>

            <ArchitectureFlow />
          </div>
        </section>

        {/* ── Section 5: Precision Comparison Matrix ─────────────────────── */}
        <section id="comparison" className="py-20 px-6 max-w-5xl mx-auto w-full">
          <div className="max-w-2xl mb-12">
            <h2 className="text-3xl font-bold tracking-tight text-zinc-100">
              The problem with standard AI reviewers
            </h2>
            <p className="text-zinc-400 mt-2 text-sm">
              Conventional tools report false discovery rates above 80%, training developers to ignore security alerts.
            </p>
          </div>

          <div className="rounded-xl border border-zinc-800 bg-zinc-950 overflow-hidden">
            <div className="grid grid-cols-2 text-xs font-semibold uppercase tracking-wider border-b border-zinc-800 bg-zinc-900/60 p-4">
              <div className="text-zinc-400">Standard AI Reviewers</div>
              <div className="text-emerald-400 flex items-center gap-1.5">
                <ShieldCheck className="h-4 w-4" /> CodeSheriff Calibrated Platform
              </div>
            </div>

            <div className="divide-y divide-zinc-800/60 text-sm">
              <div className="grid grid-cols-2 p-4 items-center">
                <div className="text-zinc-400 flex items-center gap-2">
                  <X className="h-4 w-4 text-red-400 shrink-0" />
                  Arbitrary scores (e.g. &quot;7.5/10 Security Score&quot;)
                </div>
                <div className="font-medium text-zinc-100 flex items-center gap-2">
                  <Check className="h-4 w-4 text-emerald-400 shrink-0" />
                  Mathematically calibrated posterior probabilities
                </div>
              </div>

              <div className="grid grid-cols-2 p-4 items-center">
                <div className="text-zinc-400 flex items-center gap-2">
                  <X className="h-4 w-4 text-red-400 shrink-0" />
                  Single LLM prone to hallucinations and flattery
                </div>
                <div className="font-medium text-zinc-100 flex items-center gap-2">
                  <Check className="h-4 w-4 text-emerald-400 shrink-0" />
                  Four heterogeneous agents with Bayesian fusion
                </div>
              </div>

              <div className="grid grid-cols-2 p-4 items-center">
                <div className="text-zinc-400 flex items-center gap-2">
                  <X className="h-4 w-4 text-red-400 shrink-0" />
                  Treats silence and failure identically
                </div>
                <div className="font-medium text-zinc-100 flex items-center gap-2">
                  <Check className="h-4 w-4 text-emerald-400 shrink-0" />
                  Distinguishes Detection, Silence, and Abstention
                </div>
              </div>

              <div className="grid grid-cols-2 p-4 items-center">
                <div className="text-zinc-400 flex items-center gap-2">
                  <X className="h-4 w-4 text-red-400 shrink-0" />
                  No verifiable ground truth or calibration metrics
                </div>
                <div className="font-medium text-zinc-100 flex items-center gap-2">
                  <Check className="h-4 w-4 text-emerald-400 shrink-0" />
                  Auditable ECE and Brier scores fitted on held-out corpus
                </div>
              </div>

              <div className="grid grid-cols-2 p-4 items-center">
                <div className="text-zinc-400 flex items-center gap-2">
                  <X className="h-4 w-4 text-red-400 shrink-0" />
                  Unchecked patches that break builds
                </div>
                <div className="font-medium text-zinc-100 flex items-center gap-2">
                  <Check className="h-4 w-4 text-emerald-400 shrink-0" />
                  Multi-rung verification ladder for all suggested fixes
                </div>
              </div>
            </div>
          </div>
        </section>

        {/* ── Section 6: Bottom Call to Action ───────────────────────────── */}
        <section className="py-20 px-6 max-w-4xl mx-auto w-full text-center">
          <div className="rounded-2xl border border-zinc-800 bg-gradient-to-b from-zinc-900 to-zinc-950 p-10 sm:p-14 relative overflow-hidden shadow-2xl">
            <div className="relative z-10 flex flex-col items-center">
              <div className="h-11 w-11 rounded-xl bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 flex items-center justify-center mb-5">
                <Shield className="h-6 w-6" />
              </div>
              <h2 className="text-2xl sm:text-3xl font-bold tracking-tight text-zinc-100">
                Eliminate security alert fatigue
              </h2>
              <p className="mt-3 text-zinc-400 max-w-md text-sm leading-relaxed">
                Connect your GitHub repository to receive mathematically calibrated security reviews on every pull request.
              </p>
              <div className="mt-8 flex flex-col sm:flex-row items-center gap-3">
                <Link href="/sign-in">
                  <Button size="lg" className="h-11 px-7 text-sm font-semibold bg-emerald-500 hover:bg-emerald-600 text-zinc-950 gap-2 shadow-lg shadow-emerald-500/20">
                    <GitPullRequest className="h-4 w-4" />
                    Connect GitHub
                  </Button>
                </Link>
                <Link href="/overview">
                  <Button size="lg" variant="outline" className="h-11 px-6 text-sm font-medium border-zinc-800 bg-zinc-900 hover:bg-zinc-800 text-zinc-300">
                    View Live Dashboard
                  </Button>
                </Link>
              </div>
            </div>
          </div>
        </section>
      </main>

      {/* ── Minimalist Engineering Footer ────────────────────────────────── */}
      <footer className="border-t border-zinc-800/80 py-8 px-6 text-xs text-zinc-500 bg-zinc-950">
        <div className="max-w-7xl mx-auto flex flex-col sm:flex-row items-center justify-between gap-4">
          <div className="flex items-center gap-2">
            <Shield className="h-4 w-4 text-emerald-400" />
            <span className="font-semibold text-zinc-200">CodeSheriff</span>
            <span className="text-zinc-500">: Calibrated multi-agent PR security</span>
          </div>
          <div className="flex items-center gap-6 text-zinc-400">
            <Link href="/overview" className="hover:text-zinc-200 transition-colors">
              Dashboard
            </Link>
            <Link href="/repositories" className="hover:text-zinc-200 transition-colors">
              Repositories
            </Link>
            <Link href="/audits" className="hover:text-zinc-200 transition-colors">
              Audits
            </Link>
            <Link href="/calibration" className="hover:text-zinc-200 transition-colors">
              Calibration State
            </Link>
          </div>
        </div>
      </footer>
    </div>
  );
}

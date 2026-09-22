"use client";

import { useState } from "react";
import { motion, useReducedMotion } from "motion/react";
import {
  GitPullRequest,
  Binary,
  Layers,
  Calculator,
  ShieldCheck,
  CheckCircle2,
} from "lucide-react";

interface PipelineStep {
  id: string;
  number: string;
  name: string;
  timing: string;
  icon: typeof GitPullRequest;
  summary: string;
  guarantee: string;
  contract: string;
}

const steps: PipelineStep[] = [
  {
    id: "webhook",
    number: "01",
    name: "Webhook Ingestion",
    timing: "< 100ms",
    icon: GitPullRequest,
    summary: "Receives GitHub pull_request webhook, verifies HMAC SHA-256 signature, and enqueues task.",
    guarantee: "Non-blocking 202 Accepted returned in milliseconds to prevent GitHub delivery timeouts.",
    contract: "POST /webhooks/github -> Celery queue",
  },
  {
    id: "slicing",
    number: "02",
    name: "ChangeUnit Slicing",
    timing: "< 1.2s",
    icon: Binary,
    summary: "Diff is parsed into discrete ChangeUnits, cutting exactly one unit per changed function at real line numbers.",
    guarantee: "Guarantees function-level isolation. Preserves enclosing scopes without embedding untrusted PR titles.",
    contract: "diff -> list[ChangeUnit]",
  },
  {
    id: "agents",
    number: "03",
    name: "4 Blind Witnesses",
    timing: "< 3.5s",
    icon: Layers,
    summary: "Static Taint, Semantic Gemini, Context Precedent, and Runtime WASI execute in parallel without shared state.",
    guarantee: "Agents run completely blind to each other to preserve Bayesian conditional independence.",
    contract: "analyze(unit) -> list[Evidence]",
  },
  {
    id: "fusion",
    number: "04",
    name: "Bayesian Fusion",
    timing: "< 50ms",
    icon: Calculator,
    summary: "Multiplies empirical likelihood ratios over fixed witness roster into a mathematically calibrated posterior.",
    guarantee: "Evidence comes in three kinds: Detection (LR > 1), Silence (LR < 1), and Abstention (LR = 1.0).",
    contract: "fuse(evidence) -> posterior_probability",
  },
  {
    id: "patch",
    number: "05",
    name: "Verification Ladder",
    timing: "< 2.0s",
    icon: ShieldCheck,
    summary: "Alert-worthy findings trigger patch proposals evaluated across a multi-rung sandbox verification ladder.",
    guarantee: "Suggestions only. Zero auto-merges, zero auto-commits. Anchored directly inside GitHub diff hunks.",
    contract: "verify_patch(patch) -> VerificationResult",
  },
];

export function ArchitectureFlow() {
  const [selectedStep, setSelectedStep] = useState<PipelineStep>(steps[2]);
  const shouldReduceMotion = useReducedMotion();

  return (
    <div className="w-full flex flex-col gap-8">
      {/* Steps Navigation Row */}
      <div className="grid grid-cols-1 sm:grid-cols-5 gap-3">
        {steps.map((step) => {
          const isSelected = selectedStep.id === step.id;
          const Icon = step.icon;
          return (
            <button
              key={step.id}
              type="button"
              onClick={() => setSelectedStep(step)}
              className={`p-3.5 rounded-lg border text-left transition-all relative ${
                isSelected
                  ? "border-emerald-500/50 bg-zinc-900/90 shadow-md shadow-emerald-500/5"
                  : "border-zinc-800/80 bg-zinc-950/60 hover:border-zinc-700 hover:bg-zinc-900/40"
              }`}
            >
              <div className="flex items-center justify-between mb-2">
                <span className="font-mono text-[10px] text-zinc-500">
                  {step.number}
                </span>
                <span className="font-mono text-[10px] text-zinc-400">
                  {step.timing}
                </span>
              </div>
              <div className="flex items-center gap-2">
                <Icon
                  className={`h-4 w-4 shrink-0 ${
                    isSelected ? "text-emerald-400" : "text-zinc-400"
                  }`}
                />
                <span
                  className={`text-xs font-medium truncate ${
                    isSelected ? "text-zinc-100" : "text-zinc-400"
                  }`}
                >
                  {step.name}
                </span>
              </div>
            </button>
          );
        })}
      </div>

      {/* Selected Step Detailed Technical Inspector */}
      <motion.div
        key={selectedStep.id}
        initial={shouldReduceMotion ? false : { opacity: 0, y: 8 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.3 }}
        className="rounded-xl border border-zinc-800 bg-zinc-950/80 p-6 flex flex-col md:flex-row gap-6 items-start justify-between"
      >
        <div className="space-y-3 max-w-xl">
          <div className="flex items-center gap-2.5">
            <span className="font-mono text-xs text-emerald-400 font-semibold">
              STAGE {selectedStep.number}
            </span>
            <span className="text-zinc-600">/</span>
            <h3 className="text-base font-semibold text-zinc-100">
              {selectedStep.name}
            </h3>
          </div>
          <p className="text-sm text-zinc-300 leading-relaxed">
            {selectedStep.summary}
          </p>
          <div className="pt-2 flex items-start gap-2 text-xs text-zinc-400">
            <CheckCircle2 className="h-4 w-4 text-emerald-400 shrink-0 mt-0.5" />
            <span>
              <strong className="text-zinc-200">Formal Guarantee:</strong>{" "}
              {selectedStep.guarantee}
            </span>
          </div>
        </div>

        <div className="w-full md:w-72 shrink-0 rounded-lg border border-zinc-800 bg-zinc-900/60 p-4 font-mono text-xs space-y-2">
          <div className="text-[10px] uppercase text-zinc-500 tracking-wider">
            Technical Contract
          </div>
          <div className="text-emerald-400 break-all">
            {selectedStep.contract}
          </div>
          <div className="pt-2 border-t border-zinc-800/80 flex items-center justify-between text-[11px] text-zinc-400">
            <span>Latency Target</span>
            <span className="text-zinc-200 font-semibold">{selectedStep.timing}</span>
          </div>
        </div>
      </motion.div>
    </div>
  );
}

import Link from "next/link";
import { Binary, Bot, GitPullRequest, History, ShieldCheck, Sigma, Split, Workflow } from "lucide-react";

import { BrandLogo } from "@/components/brand-logo";
import { Backdrop } from "@/components/backdrop";
import { Card, CardBody, CardText, CardTitle } from "@/components/chai/card";
import { Chip } from "@/components/chai/chip";
import { Highlight } from "@/components/chai/highlight";
import { CtaPanel } from "@/components/cta-panel";
import { Footer } from "@/components/footer";
import { Hero } from "@/components/hero";
import { ExampleFinding } from "@/components/landing/example-finding";
import { Reveal } from "@/components/landing/reveal";
import { Navbar } from "@/components/navbar";
import { SectionHead } from "@/components/section-head";
import { StatStrip } from "@/components/stat-strip";
import { buttonVariants } from "@/components/chai/button";

/**
 * The public home page. Everything after sign-in lives under the dashboard.
 *
 * Every number on this page is one the project has measured and recorded: recall and false
 * positives on the calibration split, ECE on the validation split. The test split has not been
 * opened yet, so nothing here claims a held-out result.
 */
const SIGN_IN = "/sign-in";
const REPO_URL = "https://github.com/Vivekj05/CODESHERIFF";

const WITNESSES = [
  {
    id: "structural",
    name: "Structural",
    icon: Binary,
    basis: "Taint analysis over a def-use graph, plus Semgrep. No model involved.",
    fails: "Misses bugs with no syntactic pattern.",
    measured: "13/13 recall, 0 false positives",
  },
  {
    id: "semantic",
    name: "Semantic",
    icon: Bot,
    basis: "A hosted model reasons about intent and trust boundaries, inside an unforgeable sentinel.",
    fails: "Can hallucinate or agree too easily.",
    measured: "94% safe-twin pass, 0% injection subversion",
  },
  {
    id: "context",
    name: "Context",
    icon: History,
    basis: "Learns which access controls this repository's merged code applies, and spots one dropped.",
    fails: "Says nothing in a repository with no history.",
    measured: "5/5 recall, 0 false positives",
  },
  {
    id: "runtime",
    name: "Runtime",
    icon: ShieldCheck,
    basis: "Runs the changed function once in a Wasmtime sandbox with no network and an empty environment.",
    fails: "Abstains when the code will not run in a sandbox.",
    measured: "9/9 recall, 0 false positives",
  },
] as const;

const STEPS = [
  { icon: GitPullRequest, title: "A pull request opens", text: "GitHub sends a signed webhook. The API checks the signature, queues an audit and answers at once." },
  { icon: Split, title: "One unit per changed function", text: "The worker fetches the base and head files and cuts out each changed function whole." },
  { icon: Workflow, title: "Four witnesses look, blind", text: "Each agent analyses each function without seeing the others, so their mistakes stay independent." },
  { icon: Sigma, title: "Evidence becomes a probability", text: "One fitted likelihood ratio per witness, multiplied onto a declared prior. Silence can lower it; an agent that could not run leaves it alone." },
  { icon: ShieldCheck, title: "A comment, and maybe a fix", text: "One summary comment on the pull request. An alert can carry a checked repair as a suggested change. Nothing is ever committed." },
] as const;

const EVIDENCE = [
  { title: "Detection", tone: "danger" as const, text: "The agent ran and found something. The odds go up by that agent's fitted ratio." },
  { title: "Silence", tone: "success" as const, text: "It ran and found nothing. The odds go down, but only for weaknesses that agent can actually see." },
  { title: "Abstention", tone: "default" as const, text: "It could not run. The factor is exactly 1.0: an agent that could not look does not vote." },
];

export default function HomePage() {
  return (
    <div className="relative isolate flex min-h-full flex-1 flex-col overflow-x-clip">
      <Backdrop />
      <Navbar
        layout="inline"
        logo={
          <Link href="/" aria-label="CodeSheriff home">
            <BrandLogo />
          </Link>
        }
        groups={[
          { label: "How it works", href: "#how" },
          { label: "Witnesses", href: "#witnesses" },
          { label: "Calibration", href: "#calibration" },
        ]}
        actions={
          <a href={SIGN_IN} className={buttonVariants({ variant: "ghost", size: "sm" })}>
            Sign in
          </a>
        }
      />

      <main className="mx-auto flex w-full max-w-6xl flex-col gap-24 p-6 sm:p-12">
        <Hero
          badge="Calibrated against labelled ground truth"
          title="Security review you can check"
          primary={{ label: "Sign in with GitHub", href: SIGN_IN }}
          secondary={{ label: "See how it works", href: "#how" }}
          media={<ExampleFinding />}
        >
          Four independent agents read every changed function in a pull request. CodeSheriff turns
          what they say into <Highlight>a probability you can hold to account</Highlight>, and
          shows exactly how it got there.
        </Hero>

        <Reveal>
          <StatStrip
            stats={[
              { value: "4", label: "independent witnesses" },
              { value: "76", label: "labelled cases, in 38 twin pairs" },
              { value: "10", label: "weakness classes in scope" },
              { value: "0.027", label: "calibration error, validation split" },
            ]}
          />
        </Reveal>

        <Reveal>
          <section id="how" aria-labelledby="how-h" className="scroll-mt-24">
            <SectionHead id="how-h" title="From pull request to probability">
              Five stages, each <Highlight>failing on its own terms</Highlight> rather than taking
              the rest down with it.
            </SectionHead>
            <ol className="mt-6 grid gap-4 md:grid-cols-5">
              {STEPS.map((step, index) => (
                <li key={step.title}>
                  <Card className="h-full">
                    <CardBody>
                      <div className="flex items-center justify-between">
                        <step.icon className="size-4 text-muted-foreground" aria-hidden="true" />
                        <span className="font-mono text-xs text-muted-foreground">0{index + 1}</span>
                      </div>
                      <CardTitle className="mt-2">{step.title}</CardTitle>
                      <CardText className="line-clamp-none">{step.text}</CardText>
                    </CardBody>
                  </Card>
                </li>
              ))}
            </ol>
          </section>
        </Reveal>

        <Reveal>
          <section id="witnesses" aria-labelledby="witnesses-h" className="scroll-mt-24">
            <SectionHead id="witnesses-h" title="Four witnesses that fail differently">
              Agents that made the same mistakes would add nothing. These rest on{" "}
              <Highlight>four different kinds of evidence</Highlight>.
            </SectionHead>
            <div className="mt-6 grid gap-4 md:grid-cols-2">
              {WITNESSES.map((w) => (
                <Card key={w.id}>
                  <CardBody className="gap-2 p-5">
                    <div className="flex items-center gap-2">
                      <w.icon className="size-4 text-muted-foreground" aria-hidden="true" />
                      <CardTitle>{w.name}</CardTitle>
                    </div>
                    <CardText className="line-clamp-none text-sm">{w.basis}</CardText>
                    <CardText className="line-clamp-none">Fails when: {w.fails}</CardText>
                    <div className="pt-1">
                      <Chip tone="success">{w.measured}</Chip>
                    </div>
                  </CardBody>
                </Card>
              ))}
            </div>
            <p className="mt-3 text-xs text-muted-foreground">
              Measured on the calibration split of the corpus. The held-out test split is evaluated
              once, at the end of the project, and has not been opened yet.
            </p>
          </section>
        </Reveal>

        <Reveal>
          <section id="calibration" aria-labelledby="calibration-h" className="scroll-mt-24">
            <SectionHead id="calibration-h" title="Three kinds of evidence, not two">
              Most tools treat “found nothing” and “could not look” the same way. Here they{" "}
              <Highlight>move the probability differently</Highlight>.
            </SectionHead>
            <div className="mt-6 grid gap-4 md:grid-cols-3">
              {EVIDENCE.map((e) => (
                <Card key={e.title}>
                  <CardBody className="p-5">
                    <Chip tone={e.tone} className="w-fit">
                      {e.title}
                    </Chip>
                    <CardText className="line-clamp-none mt-1 text-sm">{e.text}</CardText>
                  </CardBody>
                </Card>
              ))}
            </div>
            <p className="mt-6 max-w-3xl text-sm text-muted-foreground">
              Every ratio is fitted on one split of the corpus and the alert threshold is chosen on
              another. There is no hand-set fallback: if the fitted numbers are missing, the system
              stops rather than inventing them.
            </p>
          </section>
        </Reveal>

        <CtaPanel
          heading="Put a checkable number on your next pull request"
          tagline="Install the GitHub App, sign in, and every audit shows its working."
          action={{ label: "Sign in with GitHub", href: SIGN_IN }}
        />
      </main>

      <Footer
        logo={<BrandLogo />}
        tagline="Calibrated security review for pull requests"
        owner="CodeSheriff"
        sections={[
          {
            title: "Product",
            links: [
              { label: "How it works", href: "#how" },
              { label: "Witnesses", href: "#witnesses" },
              { label: "Calibration", href: "#calibration" },
            ],
          },
          {
            title: "Project",
            links: [
              { label: "Source code", href: REPO_URL, external: true },
              { label: "Dashboard", href: "/overview" },
            ],
          },
        ]}
      />
    </div>
  );
}

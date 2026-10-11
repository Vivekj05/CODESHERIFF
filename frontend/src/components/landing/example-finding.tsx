import { Card, CardBody } from "@/components/chai/card";
import { Chip } from "@/components/chai/chip";

/**
 * The hero's one central element: a worked example of how a posterior is reached.
 *
 * The finding is illustrative, but the arithmetic is not. Every factor is a fitted likelihood ratio
 * from the committed calibration.json, the prior is the declared 3% base rate, and the posterior is
 * their product: 0.03/0.97 x 15.56 x 9.48 x 1.00 x 6.92 = odds 31.6, which is 96.9%. The context
 * witness covers only CWE-862 and CWE-639, so on a path traversal its factor is exactly 1.0.
 */
const ROWS = [
  { witness: "Structural", basis: "Taint reaches the path join", stance: "detected", factor: "x15.56" },
  { witness: "Semantic", basis: "Archive member name is trusted", stance: "detected", factor: "x9.48" },
  { witness: "Context", basis: "Does not cover CWE-22", stance: "no vote", factor: "x1.00" },
  { witness: "Runtime", basis: "Tainted path reached open()", stance: "detected", factor: "x6.92" },
] as const;

export function ExampleFinding() {
  // The hero masks its media with a radial fade; the padding keeps the fade off the numbers.
  return (
    <div className="p-6 sm:p-10">
    <Card className="w-full sm:opacity-100">
      <CardBody className="gap-4 p-5">
        <div className="flex items-start justify-between gap-4">
          <div className="min-w-0">
            <p className="text-xs text-muted-foreground">Example finding</p>
            <h3 className="font-montserrat text-base font-semibold">CWE-22 path traversal</h3>
            <p className="mt-0.5 truncate font-mono text-xs text-muted-foreground">
              storage/archive.py · extract_archive_entry
            </p>
          </div>
          <div className="text-right">
            <p className="font-montserrat text-3xl font-semibold tabular-nums">96.9%</p>
            <p className="text-xs text-muted-foreground">alert at 22.7%</p>
          </div>
        </div>

        <ul className="flex flex-col divide-y divide-card-edge rounded-lg border border-card-edge">
          {ROWS.map((row) => (
            <li key={row.witness} className="flex items-center justify-between gap-3 px-3 py-2.5">
              <div className="min-w-0">
                <p className="text-sm font-medium">{row.witness}</p>
                <p className="truncate text-xs text-muted-foreground">{row.basis}</p>
              </div>
              <div className="flex shrink-0 items-center gap-2">
                <Chip tone={row.stance === "detected" ? "danger" : "default"}>{row.stance}</Chip>
                <span className="w-14 text-right font-mono text-sm tabular-nums">{row.factor}</span>
              </div>
            </li>
          ))}
        </ul>

        <p className="text-xs leading-relaxed text-muted-foreground">
          3% prior, times one fitted ratio per witness. The ratios are the real ones in
          calibration.json; the code is an example.
        </p>
      </CardBody>
    </Card>
    </div>
  );
}

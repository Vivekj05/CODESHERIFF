"use client";

import { useMemo } from "react";
import { Flame } from "lucide-react";

import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";
import { generateContributionData, type ContributionDay } from "@/lib/github";

interface ContributionGraphProps {
  initialDays?: ContributionDay[];
  title?: string;
  description?: string;
}

const LEVEL_CLASSES: Record<number, string> = {
  0: "bg-muted/40 border-border/30 hover:ring-1 hover:ring-muted-foreground/30",
  1: "bg-emerald-950/80 border-emerald-800/40 hover:ring-1 hover:ring-emerald-600",
  2: "bg-emerald-800 border-emerald-700/60 hover:ring-1 hover:ring-emerald-500",
  3: "bg-emerald-600 border-emerald-500/70 hover:ring-1 hover:ring-emerald-400",
  4: "bg-emerald-400 border-emerald-300 hover:ring-1 hover:ring-emerald-200",
};

export function ContributionGraph({
  initialDays,
  title = "Contribution & Review Activity",
  description = "6-month activity across commits, pull requests, and AI code reviews",
}: ContributionGraphProps) {
  const { days, totalContributions } = useMemo(() => {
    if (initialDays && initialDays.length > 0) {
      const total = initialDays.reduce((acc, curr) => acc + curr.count, 0);
      return { days: initialDays, totalContributions: total };
    }
    return generateContributionData(182); // 26 weeks
  }, [initialDays]);

  // Group into columns of 7 days (weeks)
  const weeks = useMemo(() => {
    const result: ContributionDay[][] = [];
    let currentWeek: ContributionDay[] = [];

    days.forEach((day, index) => {
      currentWeek.push(day);
      if (currentWeek.length === 7 || index === days.length - 1) {
        result.push(currentWeek);
        currentWeek = [];
      }
    });

    return result;
  }, [days]);

  return (
    <Card className="border-border/70 bg-card/70 backdrop-blur-sm">
      <CardHeader className="flex flex-row items-start justify-between pb-3">
        <div>
          <CardTitle className="text-base flex items-center gap-2">
            <Flame className="h-4 w-4 text-emerald-400" />
            <span>{title}</span>
          </CardTitle>
          <CardDescription className="text-xs">{description}</CardDescription>
        </div>
        <div className="text-right">
          <span className="font-mono text-xl font-bold text-foreground tabular-nums">
            {totalContributions}
          </span>
          <p className="text-[11px] text-muted-foreground">total events</p>
        </div>
      </CardHeader>

      <CardContent>
        <div className="overflow-x-auto pb-2">
          <div className="inline-flex flex-col gap-1 min-w-[620px]">
            {/* Days grid */}
            <div className="flex gap-1.5 items-center">
              {/* Day Labels */}
              <div className="flex flex-col gap-1 text-[10px] text-muted-foreground font-mono pr-2 select-none">
                <span className="h-3">Mon</span>
                <span className="h-3"></span>
                <span className="h-3">Wed</span>
                <span className="h-3"></span>
                <span className="h-3">Fri</span>
                <span className="h-3"></span>
                <span className="h-3">Sun</span>
              </div>

              {/* Heatmap Columns */}
              <TooltipProvider delay={100}>
                <div className="flex gap-1">
                  {weeks.map((week, weekIndex) => (
                    <div key={weekIndex} className="flex flex-col gap-1">
                      {week.map((day) => {
                        const dateFormatted = new Date(day.date).toLocaleDateString("en-US", {
                          month: "short",
                          day: "numeric",
                          year: "numeric",
                        });

                        return (
                          <Tooltip key={day.date}>
                            <TooltipTrigger
                              className={`h-3 w-3 rounded-[2.5px] border transition-all cursor-pointer ${
                                LEVEL_CLASSES[day.level]
                              }`}
                              aria-label={`${day.count} activities on ${day.date}`}
                            />
                            <TooltipContent side="top" className="text-xs font-mono py-1 px-2.5">
                              <span className="font-semibold text-emerald-400">
                                {day.count} {day.count === 1 ? "activity" : "activities"}
                              </span>{" "}
                              on {dateFormatted}
                            </TooltipContent>
                          </Tooltip>
                        );
                      })}
                    </div>
                  ))}
                </div>
              </TooltipProvider>
            </div>

            {/* Bottom Legend */}
            <div className="mt-3 flex items-center justify-between text-xs text-muted-foreground pt-2 border-t border-border/40">
              <span className="text-[11px]">Last 26 weeks</span>
              <div className="flex items-center gap-1.5 text-[11px]">
                <span>Less</span>
                <div className="h-2.5 w-2.5 rounded-[2px] bg-muted/40 border border-border/30" />
                <div className="h-2.5 w-2.5 rounded-[2px] bg-emerald-950/80 border border-emerald-800/40" />
                <div className="h-2.5 w-2.5 rounded-[2px] bg-emerald-800 border border-emerald-700/60" />
                <div className="h-2.5 w-2.5 rounded-[2px] bg-emerald-600 border border-emerald-500/70" />
                <div className="h-2.5 w-2.5 rounded-[2px] bg-emerald-400 border border-emerald-300" />
                <span>More</span>
              </div>
            </div>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

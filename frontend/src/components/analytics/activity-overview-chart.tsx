"use client";

import { useMemo } from "react";
import {
  Area,
  AreaChart,
  CartesianGrid,
  Legend,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { Activity } from "lucide-react";

import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { getSixMonthActivityData, type MonthlyActivity } from "@/lib/github";

interface ActivityOverviewChartProps {
  data?: MonthlyActivity[];
}

export function ActivityOverviewChart({ data }: ActivityOverviewChartProps) {
  const chartData = useMemo(() => data || getSixMonthActivityData(), [data]);

  return (
    <Card className="border-border/70 bg-card/70 backdrop-blur-sm">
      <CardHeader className="pb-2">
        <CardTitle className="text-base flex items-center gap-2">
          <Activity className="h-4 w-4 text-primary" />
          <span>6-Month Activity Trends</span>
        </CardTitle>
        <CardDescription className="text-xs">
          Monthly breakdown of commits, pull requests, and AI reviews analyzed
        </CardDescription>
      </CardHeader>

      <CardContent className="pt-2">
        <div className="h-[260px] w-full">
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={chartData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
              <defs>
                <linearGradient id="colorCommits" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#38bdf8" stopOpacity={0.4} />
                  <stop offset="95%" stopColor="#38bdf8" stopOpacity={0.0} />
                </linearGradient>
                <linearGradient id="colorPRs" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#a855f7" stopOpacity={0.4} />
                  <stop offset="95%" stopColor="#a855f7" stopOpacity={0.0} />
                </linearGradient>
                <linearGradient id="colorReviews" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#34d399" stopOpacity={0.4} />
                  <stop offset="95%" stopColor="#34d399" stopOpacity={0.0} />
                </linearGradient>
              </defs>

              <CartesianGrid strokeDasharray="3 3" vertical={false} stroke="rgba(255,255,255,0.07)" />
              <XAxis
                dataKey="month"
                stroke="currentColor"
                className="text-[11px] text-muted-foreground font-mono"
                tickLine={false}
                axisLine={false}
              />
              <YAxis
                stroke="currentColor"
                className="text-[11px] text-muted-foreground font-mono"
                tickLine={false}
                axisLine={false}
                allowDecimals={false}
              />

              <Tooltip
                content={({ active, payload, label }) => {
                  if (active && payload && payload.length) {
                    return (
                      <div className="rounded-lg border border-border/80 bg-background/95 p-3 shadow-xl backdrop-blur-md font-mono text-xs">
                        <div className="font-semibold text-foreground mb-1.5">{label} Activity</div>
                        {payload.map((item) => (
                          <div key={item.name} className="flex items-center justify-between gap-4 py-0.5">
                            <span className="flex items-center gap-1.5 text-muted-foreground">
                              <span
                                className="h-2 w-2 rounded-full"
                                style={{ backgroundColor: item.color }}
                              />
                              {item.name}:
                            </span>
                            <span className="font-bold text-foreground tabular-nums">
                              {item.value}
                            </span>
                          </div>
                        ))}
                      </div>
                    );
                  }
                  return null;
                }}
              />

              <Legend
                verticalAlign="top"
                align="right"
                wrapperStyle={{ paddingBottom: "10px", fontSize: "11px" }}
                iconType="circle"
              />

              <Area
                type="monotone"
                dataKey="commits"
                name="Commits"
                stroke="#38bdf8"
                strokeWidth={2}
                fillOpacity={1}
                fill="url(#colorCommits)"
              />
              <Area
                type="monotone"
                dataKey="pullRequests"
                name="Pull Requests"
                stroke="#a855f7"
                strokeWidth={2}
                fillOpacity={1}
                fill="url(#colorPRs)"
              />
              <Area
                type="monotone"
                dataKey="reviews"
                name="AI Reviews"
                stroke="#34d399"
                strokeWidth={2}
                fillOpacity={1}
                fill="url(#colorReviews)"
              />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      </CardContent>
    </Card>
  );
}

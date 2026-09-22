import { NextResponse } from "next/server";

import { searchCodebaseContext } from "@/lib/pinecone";

export async function GET(request: Request) {
  const { searchParams } = new URL(request.url);
  const repo = searchParams.get("repo");
  const query = searchParams.get("q");
  const topK = parseInt(searchParams.get("topK") || "5", 10);

  if (!repo || !query) {
    return NextResponse.json(
      { error: "Missing required parameters: 'repo' and 'q' are required." },
      { status: 400 },
    );
  }

  try {
    const matches = await searchCodebaseContext(repo, query, topK);
    return NextResponse.json({ repo, query, matches, count: matches.length });
  } catch (error) {
    const message = error instanceof Error ? error.message : "Failed to execute semantic search";
    return NextResponse.json({ error: message }, { status: 500 });
  }
}

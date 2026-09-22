import { NextResponse } from "next/server";

import { chunkFile, type CodeChunk } from "@/lib/chunker";
import { indexCodebaseChunks } from "@/lib/pinecone";

export async function POST(request: Request) {
  try {
    const body = await request.json();
    const { repo, files } = body as {
      repo?: string;
      files?: Array<{ path: string; content: string }>;
    };

    if (!repo) {
      return NextResponse.json({ error: "Missing required parameter: 'repo'" }, { status: 400 });
    }

    const allChunks: CodeChunk[] = [];

    if (files && Array.isArray(files) && files.length > 0) {
      for (const file of files) {
        const fileChunks = chunkFile(file.path, file.content);
        allChunks.push(...fileChunks);
      }
    } else {
      // Create baseline architectural overview chunks for initial indexing
      const baseOverview = `// Architecture index for repository: ${repo}\n// Contains primary API endpoints, authentication flows, and data models.`;
      allChunks.push({
        id: `${repo.replace(/[^a-zA-Z0-9-_]/g, "_")}_overview`,
        filePath: "README.md",
        content: baseOverview,
        lineStart: 1,
        lineEnd: 2,
        tokensEstimate: 20,
      });
    }

    const result = await indexCodebaseChunks(repo, allChunks);

    return NextResponse.json({
      success: true,
      repo,
      chunksIndexed: result.indexedCount,
      storageDestination: result.destination,
      message: `Indexed ${result.indexedCount} chunk(s) for ${repo} in ${result.destination}.`,
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : "Failed to index codebase";
    return NextResponse.json({ error: message }, { status: 500 });
  }
}

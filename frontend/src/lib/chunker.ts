/**
 * Codebase chunking utility for RAG indexing.
 *
 * Slices source code files into semantic chunks suitable for embedding with
 * Google's `text-embedding-004` (768-dim) and upserting to Pinecone.
 */

export interface CodeChunk {
  id: string;
  filePath: string;
  content: string;
  lineStart: number;
  lineEnd: number;
  tokensEstimate: number;
}

const IGNORED_EXTENSIONS = new Set([
  "png", "jpg", "jpeg", "gif", "ico", "svg", "webp",
  "woff", "woff2", "ttf", "eot",
  "zip", "tar", "gz", "wasm", "pdf",
  "lock", "min.js", "min.css", "map",
]);

const IGNORED_DIRECTORIES = [
  "node_modules/", ".git/", ".venv/", "dist/", "build/",
  ".next/", "__pycache__/", ".cache/", ".pytest_cache/",
];

/**
 * Checks whether a given file path should be indexed for RAG.
 */
export function isIndexableFile(filePath: string): boolean {
  const normalized = filePath.replace(/\\/g, "/");

  // Check directories
  for (const dir of IGNORED_DIRECTORIES) {
    if (normalized.includes(dir)) return false;
  }

  // Check extension
  const parts = normalized.split(".");
  const ext = parts[parts.length - 1]?.toLowerCase() || "";
  if (IGNORED_EXTENSIONS.has(ext)) return false;

  return true;
}

/**
 * Chunks a single file's content into overlapping slices.
 */
export function chunkFile(
  filePath: string,
  content: string,
  maxChunkLines = 50,
  overlapLines = 10,
): CodeChunk[] {
  if (!isIndexableFile(filePath) || !content || content.trim() === "") {
    return [];
  }

  const lines = content.split("\n");
  const chunks: CodeChunk[] = [];
  let start = 0;
  let chunkIndex = 0;

  while (start < lines.length) {
    const end = Math.min(start + maxChunkLines, lines.length);
    const chunkLines = lines.slice(start, end);
    const chunkText = chunkLines.join("\n");

    // Estimate tokens (roughly 4 chars per token)
    const tokensEstimate = Math.ceil(chunkText.length / 4);

    // Only keep chunks with actual content
    if (chunkText.trim().length > 10) {
      chunks.push({
        id: `${filePath.replace(/[^a-zA-Z0-9-_]/g, "_")}_chunk_${chunkIndex}`,
        filePath,
        content: `// File: ${filePath} (lines ${start + 1}-${end})\n${chunkText}`,
        lineStart: start + 1,
        lineEnd: end,
        tokensEstimate,
      });
      chunkIndex++;
    }

    if (end >= lines.length) break;
    start += maxChunkLines - overlapLines;
  }

  return chunks;
}

/**
 * Pinecone Vector Database & Google text-embedding-004 RAG service.
 *
 * Provides:
 * - Embedding generation with Google's `text-embedding-004`
 * - Codebase chunk upsert to Pinecone per-repository namespaces
 * - Semantic similarity search for context retrieval during PR reviews
 */

import { GoogleGenerativeAI } from "@google/generative-ai";
import { Pinecone } from "@pinecone-database/pinecone";

import type { CodeChunk } from "@/lib/chunker";

export interface SearchMatch {
  id: string;
  filePath: string;
  content: string;
  lineStart: number;
  lineEnd: number;
  score: number;
}

const PINECONE_INDEX_NAME = process.env.PINECONE_INDEX || "codesheriff-rag";
const EMBEDDING_MODEL = "text-embedding-004";

// In-memory fallback cache for development when Pinecone is unconfigured
const inMemoryVectorStore = new Map<string, Array<{ chunk: CodeChunk; embedding: number[] }>>();

/**
 * Returns a configured Google Generative AI instance.
 */
function getGeminiClient(): GoogleGenerativeAI | null {
  const apiKey = process.env.GEMINI_API_KEY;
  if (!apiKey) return null;
  return new GoogleGenerativeAI(apiKey);
}

/**
 * Returns a configured Pinecone client.
 */
function getPineconeClient(): Pinecone | null {
  const apiKey = process.env.PINECONE_API_KEY;
  if (!apiKey) return null;
  return new Pinecone({ apiKey });
}

/**
 * Generates embeddings using Google's text-embedding-004.
 */
export async function generateEmbedding(text: string): Promise<number[]> {
  const gemini = getGeminiClient();
  if (!gemini) {
    // Generate deterministic pseudo-embedding (768 dimensions) for local dev fallback
    const pseudo = new Array(768).fill(0);
    for (let i = 0; i < text.length; i++) {
      pseudo[i % 768] += text.charCodeAt(i) / 1000;
    }
    return pseudo;
  }

  const model = gemini.getGenerativeModel({ model: EMBEDDING_MODEL });
  const result = await model.embedContent(text);
  return result.embedding.values;
}

/**
 * Converts repository full name (e.g. "owner/repo") into a safe Pinecone namespace.
 */
export function getNamespaceForRepo(repoFullName: string): string {
  return `repo_${repoFullName.replace(/[^a-zA-Z0-9_-]/g, "_")}`;
}

/**
 * Indexes code chunks into Pinecone.
 */
export async function indexCodebaseChunks(
  repoFullName: string,
  chunks: CodeChunk[],
): Promise<{ indexedCount: number; destination: "pinecone" | "in-memory" }> {
  if (chunks.length === 0) {
    return { indexedCount: 0, destination: "in-memory" };
  }

  const pinecone = getPineconeClient();
  const namespace = getNamespaceForRepo(repoFullName);

  // If Pinecone is configured, upsert into the Pinecone index
  if (pinecone) {
    try {
      const index = pinecone.Index(PINECONE_INDEX_NAME);
      const vectors = [];

      // Process in batches of 20 to respect rate limits
      for (let i = 0; i < chunks.length; i += 20) {
        const batch = chunks.slice(i, i + 20);
        const batchVectors = await Promise.all(
          batch.map(async (chunk) => {
            const values = await generateEmbedding(chunk.content);
            return {
              id: chunk.id,
              values,
              metadata: {
                filePath: chunk.filePath,
                lineStart: chunk.lineStart,
                lineEnd: chunk.lineEnd,
                content: chunk.content.slice(0, 1000), // metadata limit
              },
            };
          }),
        );
        vectors.push(...batchVectors);
      }

      await index.namespace(namespace).upsert({ records: vectors });
      return { indexedCount: vectors.length, destination: "pinecone" };
    } catch (err) {
      console.warn("Pinecone upsert failed, falling back to local memory store:", err);
    }
  }

  // Fallback: store in memory for local testing
  const fallbackRecords = await Promise.all(
    chunks.map(async (chunk) => ({
      chunk,
      embedding: await generateEmbedding(chunk.content),
    })),
  );

  const existing = inMemoryVectorStore.get(namespace) || [];
  inMemoryVectorStore.set(namespace, [...existing, ...fallbackRecords]);

  return { indexedCount: chunks.length, destination: "in-memory" };
}

/**
 * Queries Pinecone for context relevant to a query or PR diff.
 */
export async function searchCodebaseContext(
  repoFullName: string,
  query: string,
  topK = 5,
): Promise<SearchMatch[]> {
  const namespace = getNamespaceForRepo(repoFullName);
  const pinecone = getPineconeClient();
  const queryVector = await generateEmbedding(query);

  if (pinecone) {
    try {
      const index = pinecone.Index(PINECONE_INDEX_NAME);
      const response = await index.namespace(namespace).query({
        vector: queryVector,
        topK,
        includeMetadata: true,
      });

      return (response.matches || []).map((match) => ({
        id: match.id,
        filePath: String(match.metadata?.filePath || "unknown"),
        content: String(match.metadata?.content || ""),
        lineStart: Number(match.metadata?.lineStart || 1),
        lineEnd: Number(match.metadata?.lineEnd || 1),
        score: match.score ?? 0,
      }));
    } catch (err) {
      console.warn("Pinecone search failed, using local memory store:", err);
    }
  }

  // In-memory fallback search (cosine similarity)
  const localList = inMemoryVectorStore.get(namespace) || [];
  if (localList.length === 0) return [];

  const scored = localList.map(({ chunk, embedding }) => {
    // Cosine similarity
    let dot = 0;
    let normA = 0;
    let normB = 0;
    for (let i = 0; i < Math.min(embedding.length, queryVector.length); i++) {
      dot += embedding[i] * queryVector[i];
      normA += embedding[i] * embedding[i];
      normB += queryVector[i] * queryVector[i];
    }
    const score = normA && normB ? dot / (Math.sqrt(normA) * Math.sqrt(normB)) : 0;
    return {
      id: chunk.id,
      filePath: chunk.filePath,
      content: chunk.content,
      lineStart: chunk.lineStart,
      lineEnd: chunk.lineEnd,
      score,
    };
  });

  return scored.sort((a, b) => b.score - a.score).slice(0, topK);
}

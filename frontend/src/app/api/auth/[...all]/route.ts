import { toNextJsHandler } from "better-auth/next-js";

import { auth } from "@/lib/auth";

/**
 * The one Next.js API route in this project (D-101): Better Auth's sign-in, callback, sign-out,
 * token and JWKS endpoints. Everything else the dashboard reads comes from the Python API.
 */
export const { GET, POST } = toNextJsHandler(auth);

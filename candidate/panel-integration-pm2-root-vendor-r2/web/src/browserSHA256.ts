import { sha256 } from "@noble/hashes/sha2.js";

// Receipt fingerprints must also work on ordinary HTTP origins, where
// SubtleCrypto is unavailable. No request, credential or digest is persisted
// or sent to a hashing endpoint. This is not an authentication/MAC primitive.
export function browserSHA256(value: string | Uint8Array): string {
  return Array.from(sha256(typeof value === "string" ? new TextEncoder().encode(value) : value), byte =>
    byte.toString(16).padStart(2, "0"),
  ).join("");
}

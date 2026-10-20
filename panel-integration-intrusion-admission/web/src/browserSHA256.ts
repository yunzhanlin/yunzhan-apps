import { sha256 } from "@noble/hashes/sha2.js";

// Receipt fingerprints must also work on ordinary HTTP origins, where
// SubtleCrypto is unavailable. No request, credential or digest is persisted
// or sent to a hashing endpoint. This is not an authentication/MAC primitive.
export function browserSHA256(value: string): string {
  return Array.from(sha256(new TextEncoder().encode(value)), byte =>
    byte.toString(16).padStart(2, "0"),
  ).join("");
}

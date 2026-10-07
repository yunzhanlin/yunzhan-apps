// Search is presentation-only: never use this normalization for identities,
// versions, signatures, API parameters or authorization checks.
export function normalizeStoreSearch(value: string): string {
  return value.normalize("NFKC").toLowerCase().replace(/\s+/gu, "");
}

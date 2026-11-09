// Search is presentation-only: never use this normalization for identities,
// versions, signatures, API parameters or authorization checks.
export function normalizeStoreSearch(value: string): string {
  // Publishers and users spell names as "PHP 8.5", "PHP-8.5" or
  // "PHP_8.5". Ignore presentation separators only: dots, plus signs and
  // every signed catalog/API value remain untouched.
  return value.normalize("NFKC").toLowerCase().replace(/[\s_\p{Dash_Punctuation}]+/gu, "");
}

// Rank already-filtered presentation results, never catalog identities or API
// parameters. Keep ties and empty queries in the publisher's original order.
export function sortStoreSearchResults<T>(
  items: readonly T[],
  query: string,
  identities: (item: T) => readonly string[],
): T[] {
  const term = normalizeStoreSearch(query);
  if (!term) return [...items];
  const score = (item: T) => {
    const names = identities(item).flatMap(name => name.split(/[·|]/u))
      .map(normalizeStoreSearch).filter(Boolean);
    if (names.some(name => name === term)) return 0;
    if (names.some(name => name.startsWith(term))) return 1;
    if (names.some(name => name.includes(term))) return 2;
    return 3;
  };
  return items.map((item, index) => ({ item, index, rank: score(item) }))
    .sort((a, b) => a.rank - b.rank || a.index - b.index).map(entry => entry.item);
}

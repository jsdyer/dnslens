/** Copy a legacy preference once. Failed writes leave the original untouched. */
export function readMigrated(storage, key, legacyKey) {
  try {
    const current = storage.getItem(key);
    if (current !== null) return current;
    const previous = storage.getItem(legacyKey);
    if (previous === null) return null;
    try {
      storage.setItem(key, previous);
      storage.removeItem(legacyKey);
    } catch { /* Keep using the legacy value if storage is read-only or full. */ }
    return previous;
  } catch { return null; }
}

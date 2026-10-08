// Only refresh read-only evidence. Never reload configuration or replace drafts.
export function createRotationRefresh<T>(options: {
  supported: () => boolean;
  readStatus: () => Promise<T>;
  applyStatus: (status: T) => void;
  fingerprint: (status: T) => string;
  refreshEvidence: () => Promise<boolean>;
  clearError: () => void;
  onError: (error: unknown) => void;
}) {
  let inFlight: Promise<void> | undefined;
  let verifiedEvidence: string | undefined;
  return function refresh(): Promise<void> {
    if (!options.supported()) return Promise.resolve();
    if (inFlight) return inFlight;
    inFlight = (async () => {
      try {
        const status = await options.readStatus();
        options.applyStatus(status);
        const fingerprint = options.fingerprint(status);
        if (fingerprint !== verifiedEvidence) {
          if (!(await options.refreshEvidence())) return;
          verifiedEvidence = fingerprint;
        }
        options.clearError();
      } catch (error) {
        // Do not accept the new fingerprint on an incomplete evidence refresh.
        // A later poll retries it, including after a transient mutation lock.
        options.onError(error);
      }
    })().finally(() => { inFlight = undefined; });
    return inFlight;
  };
}

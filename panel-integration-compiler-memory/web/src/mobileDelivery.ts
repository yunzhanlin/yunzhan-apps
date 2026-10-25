// Closed, immutable delivery cohorts. This validates link metadata only;
// downloading/installing bytes and device acceptance remain separate checks.
const releases: Readonly<Record<string, { prefix: string; files: Readonly<Record<string, string>> }>> = Object.freeze({
  "1.3.0": {
    prefix: "https://github.com/yunzhanlin/yunzhan-apps/releases/download/v0.1.0-dev.proapps11/",
    files: Object.freeze({
      "yunzhan-mobile-1.3.0-android.apk": "45dd8bc7048ad0df15805dc1887f509b8905390eace6a223c552c9425fc74db2",
      "yunzhan-mobile-1.3.0-ios-unsigned.tar.gz": "272d6ffbf0b636b121311f6565f3203ae4f460852d023db3882523507071c219",
      "yunzhan-mobile-1.3.0-source.tar.gz": "797f47e79e8ef799c813fc9a6c2c9ce2f56e8cb159c8896defbcfed1b61e865d",
    }),
  },
  "1.3.2": {
    prefix: "https://github.com/yunzhanlin/yunzhan-apps/releases/download/mobile-v1.3.2/",
    files: Object.freeze({
      "yunzhan-mobile-1.3.2-android.apk": "a76d4a9a04b4d46c35332b36e04590078a27e25885fd5abe6ede611be55b09e3",
      "yunzhan-mobile-1.3.2-ios-unsigned.tar.gz": "ef86e336b7334bb29cad8570cc29eea0af0f9f26217b77bd914a94c429d4f365",
      "yunzhan-mobile-1.3.2-source.tar.gz": "6fcbbaa8d18ba1cb22aa050b849dd8d3e1488e8f845b32c1930cb0eea2cc313f",
    }),
  },
});

export function mobileArtifactURL(version: unknown, item: unknown): string | undefined {
  if (typeof version !== "string" || !Object.hasOwn(releases, version) || !item || typeof item !== "object" || Array.isArray(item)) return;
  try {
    const own = (key: string): unknown => {
      const field = Object.getOwnPropertyDescriptor(item, key);
      return field && Object.hasOwn(field, "value") ? field.value : undefined;
    };
    const filename = own("filename"), sha256 = own("sha256"), url = own("url"), cohort = releases[version];
    if (typeof filename !== "string" || typeof sha256 !== "string" || typeof url !== "string" || !Object.hasOwn(cohort.files, filename)) return;
    if (cohort.files[filename] !== sha256 || url !== cohort.prefix + filename) return;
    return cohort.prefix + filename;
  } catch {
    // Proxy/accessor objects are not a network JSON delivery record.
    return;
  }
}

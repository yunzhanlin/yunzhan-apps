export interface IDSRuleFeedSelection {
  feed_id: string;
  app_version: string;
  app_manifest_sha256: string;
  rule_manifest_sha256: string;
}
export interface IDSRuleProfile {
  source: "original" | "verified-feed";
  selection?: IDSRuleFeedSelection;
}
export function validIDSRuleProfile(value: unknown): value is IDSRuleProfile {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const choice = value as IDSRuleProfile;
  if (choice.source === "original") return Object.keys(choice).length === 1;
  if (
    choice.source !== "verified-feed" ||
    Object.keys(choice).length !== 2 ||
    !Object.hasOwn(choice, "selection")
  )
    return false;
  const selected = choice.selection;
  if (!selected || typeof selected !== "object" || Array.isArray(selected))
    return false;
  const names = [
    "feed_id",
    "app_version",
    "app_manifest_sha256",
    "rule_manifest_sha256",
  ];
  if (
    Object.keys(selected).length !== 4 ||
    !names.every((name) => Object.hasOwn(selected, name))
  )
    return false;
  return (
    typeof selected.feed_id === "string" &&
    /^et-open-web-[0-9]{8}$/.test(selected.feed_id) &&
    typeof selected.app_version === "string" &&
    selected.app_version.length <= 64 &&
    /^[0-9]+(?:\.[0-9]+){0,3}(?:-[A-Za-z0-9]+(?:[.-][A-Za-z0-9]+)*)?$/.test(
      selected.app_version,
    ) &&
    typeof selected.app_manifest_sha256 === "string" &&
    /^[a-f0-9]{64}$/.test(selected.app_manifest_sha256) &&
    typeof selected.rule_manifest_sha256 === "string" &&
    /^[a-f0-9]{64}$/.test(selected.rule_manifest_sha256)
  );
}
export interface IDSOperation {
  id: string;
  action: string;
  input: {
    expected_revision: number;
    network_interface?: string;
    home_networks?: string[];
    enabled?: boolean;
    rule_profile?: IDSRuleProfile;
  };
  state: string;
  error?: string;
  created_at: string;
  updated_at: string;
  steps: { time: string; message: string }[];
}
export const idsBackgroundActions = [
  "ids-config",
  "ids-rules",
  "ids-start",
  "ids-stop",
  "ids-boot",
  "ids-recover",
  "ids-rotate",
];
export function validIDSOperation(value: unknown): value is IDSOperation {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const out = value as IDSOperation;
  const fields = [
    "id",
    "action",
    "input",
    "state",
    "created_at",
    "updated_at",
    "steps",
  ];
  if (
    !fields.every((name) => Object.hasOwn(out, name)) ||
    Object.keys(out).some(
      (name) => !fields.includes(name) && name !== "error",
    ) ||
    typeof out.id !== "string" ||
    typeof out.action !== "string" ||
    typeof out.state !== "string"
  )
    return false;
  if (
    !/^[a-f0-9]{32}$/.test(out.id) ||
    !idsBackgroundActions.includes(out.action) ||
    !["queued", "running", "succeeded", "failed", "needs-attention"].includes(
      out.state,
    ) ||
    !out.input ||
    !Number.isSafeInteger(out.input.expected_revision) ||
    out.input.expected_revision < 0 ||
    typeof out.created_at !== "string" ||
    !Number.isFinite(Date.parse(out.created_at)) ||
    typeof out.updated_at !== "string" ||
    !Number.isFinite(Date.parse(out.updated_at)) ||
    Date.parse(out.updated_at) < Date.parse(out.created_at)
  )
    return false;
  if (
    out.error !== undefined &&
    (typeof out.error !== "string" || out.error.length > 2048)
  )
    return false;
  if (
    (out.state === "succeeded" && out.error) ||
    (["failed", "needs-attention"].includes(out.state) && !out.error)
  )
    return false;
  const allowed =
    out.action === "ids-config"
      ? ["expected_revision", "network_interface", "home_networks"]
      : out.action === "ids-rules"
        ? ["expected_revision", "rule_profile"]
        : out.action === "ids-boot"
          ? ["expected_revision", "enabled"]
          : ["expected_revision"];
  if (
    Object.keys(out.input).length !== allowed.length ||
    !allowed.every((key) => Object.hasOwn(out.input, key))
  )
    return false;
  if (out.action === "ids-boot" && typeof out.input.enabled !== "boolean")
    return false;
  if (
    out.action === "ids-rules" &&
    !validIDSRuleProfile(out.input.rule_profile)
  )
    return false;
  if (
    out.action === "ids-config" &&
    (typeof out.input.network_interface !== "string" ||
      !/^[A-Za-z0-9][A-Za-z0-9_.:-]{0,14}$/.test(out.input.network_interface) ||
      out.input.network_interface === "any" ||
      !Array.isArray(out.input.home_networks) ||
      out.input.home_networks.length < 1 ||
      out.input.home_networks.length > 16 ||
      !out.input.home_networks.every(
        (value) => typeof value === "string" && value.length <= 64,
      ))
  )
    return false;
  return (
    Array.isArray(out.steps) &&
    out.steps.length <= 16 &&
    out.steps.every(
      (step) =>
        step &&
        typeof step.time === "string" &&
        Number.isFinite(Date.parse(step.time)) &&
        typeof step.message === "string" &&
        step.message.length > 0 &&
        step.message.length <= 2048,
    )
  );
}

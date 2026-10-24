const id = /^[a-f0-9]{32}$/;
export type WafApplyKind = "software_install" | "software_configure";
export interface WafApplyTaskOutcome {
  state: "pending" | "succeeded" | "failed" | "attention";
  detail: string;
}

// A healthy CURRENT configuration can belong to a subsequent administrator's
// request. Bind the UI success statement to this exact normalized preview and
// its one committed revision, not just to a healthy task from the same app.
export function wafCommittedConfiguration(requested: unknown, current: unknown): boolean {
  const object = (v: unknown): v is Record<string, unknown> => !!v && typeof v === "object" && !Array.isArray(v) && [Object.prototype, null].includes(Object.getPrototypeOf(v));
  if (!object(requested) || !object(current) || !object(requested.policy) || !object(current.policy)) return false;
  const revision = requested.policy.revision;
  if (typeof revision !== "number" || !Number.isSafeInteger(revision) || revision < 0 || revision >= Number.MAX_SAFE_INTEGER || current.policy.revision !== revision + 1) return false;
  const wanted: Record<string, unknown> = {...requested, policy: {...requested.policy, revision: revision + 1}};
  // Omission has the same preserve-independent-field meaning as the executor.
  // An explicit object must still match completely, including arrays and IDs.
  for (const field of ["body", "trusted_proxy", "body_log_rotation", "body_log_retention"]) {
    if (!Object.hasOwn(requested, field) && Object.hasOwn(current, field)) wanted[field] = current[field];
  }
  try {
    function canonical(value: unknown): string {
      let nodes = 0;
      function encode(v: unknown, depth: number): string {
        if (++nodes > 16000 || depth > 32) throw new Error("configuration structure too large");
        if (v === null || typeof v === "boolean" || typeof v === "string") return JSON.stringify(v);
        if (typeof v === "number" && Number.isFinite(v)) return JSON.stringify(v);
        if (Array.isArray(v)) {
          const values: string[] = [];
          for (let i = 0; i < v.length; i++) {
            if (!Object.hasOwn(v, i)) throw new Error("sparse configuration array");
            values.push(encode(v[i], depth + 1));
          }
          return `[${values.join(",")}]`;
        }
        if (object(v)) return `{${Object.keys(v).sort().map(key => `${JSON.stringify(key)}:${encode(v[key], depth + 1)}`).join(",")}}`;
        throw new Error("configuration is not JSON");
      }
      const wire = encode(value, 0);
      if (new TextEncoder().encode(wire).length > 128 * 1024) throw new Error("configuration too large");
      return wire;
    }
    return canonical(wanted) === canonical(current);
  } catch { return false; }
}

export function wafQueuedApplyID(value: unknown): string {
  const candidate = typeof value === "string" ? value :
    value && typeof value === "object" && !Array.isArray(value) ? (value as {job_id?: unknown}).job_id : undefined;
  if (typeof candidate !== "string" || !id.test(candidate)) throw new Error("未收到可核对的原任务标识，保留原请求；不要提交不同配置。");
  return candidate;
}

// A result for some other task is never this WAF's completed operation.
// needs_attention is an immediate visible uncertainty, not two minutes of
// ordinary polling and never a reason to submit another mutation.
export function wafApplyTaskOutcome(requested: string, engine: string, kind: WafApplyKind, value: unknown): WafApplyTaskOutcome {
  if (!id.test(requested) || !["nginx-waf", "apache-waf"].includes(engine) ||
      !["software_install", "software_configure"].includes(kind) || !value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("原防火墙任务响应无法核验；保留请求，未重新提交。");
  }
  if (![Object.prototype,null].includes(Object.getPrototypeOf(value)) || Object.keys(value).sort().join(",") !== "error,id,kind,state,target_id") throw new Error("原防火墙任务字段缺失或含未知内容；保留请求，未重新提交。");
  const job = value as {id?: unknown; target_id?: unknown; kind?: unknown; state?: unknown; error?: unknown};
  if (job.id !== requested || job.target_id !== engine || job.kind !== kind || typeof job.error !== "string" || new TextEncoder().encode(job.error).length > 32768) {
    throw new Error("原防火墙任务身份、类型或错误信息不一致；保留请求，未重新提交。");
  }
  switch (job.state) {
    case "queued": case "running": return {state:"pending", detail:""};
    case "succeeded": return {state:"succeeded", detail:""};
    case "failed": case "cancelled": return {state:"failed", detail:job.error || "配置任务失败；请核对操作记录和当前实际配置。"};
    case "needs_attention": return {state:"attention", detail:job.error || "原任务结果需要核对，未确认配置生效；保留原任务，不自动重新提交。"};
    default: throw new Error("原防火墙任务状态未知；保留请求，未宣称成功或重新提交。");
  }
}

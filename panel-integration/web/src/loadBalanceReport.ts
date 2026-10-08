type Row = Record<string, any>;

export function loadBalanceEntryFields(row: Row) {
  return {
    nodes: (row.nodes as Row[]).map(node=>({...node})),
    health_check: row.health_check ? {...row.health_check} : null,
  };
}
export function loadBalanceEntryRow(row: Row) {
  return {health_check:row.health_check || null, http_health_enabled:Boolean(row.health_check)};
}
export function loadBalanceNodeSummary(nodes: unknown[]) {
  return nodes.map(node=>{
    if (!node || typeof node!=="object") return "未知节点";
    const value=node as Row;
    return `${value.address || "未知地址"} ×${value.weight ?? 1}${value.backup ? "（备用）" : ""}`;
  }).join(", ");
}
export function loadBalanceTransitions(rows: Row[]) {
  const unique=new Map<string,Row>();
  for (const row of rows) {
    if (typeof row.domain!=="string" || !Array.isArray(row.transitions)) continue;
    for (const event of row.transitions) {
      if (!event || typeof event!=="object" || !Number.isSafeInteger(event.sequence)) continue;
      unique.set(`${row.domain}:${event.sequence}`,{...event,domain:row.domain});
    }
  }
  return [...unique.values()].sort((a,b)=>Date.parse(b.at)-Date.parse(a.at)).slice(0,200);
}

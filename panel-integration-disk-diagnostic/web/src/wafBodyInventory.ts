// An incomplete/failed read must never masquerade as an empty inventory.
export function bodyInventoryPresentation(known: boolean, count: number) {
  const verified = known && Number.isInteger(count) && count >= 0 && count <= 8;
  return {
    verified,
    label: verified ? `保留 ${count} / 8 份备份` : "备份库存待核对（不是零份）",
    empty: verified ? "没有元数据日志备份" : "完整备份库存暂不可核验，请核对恢复记录",
  };
}

// UI selectors only. These never grant access or replace Core/Root path checks.
export type DiskSelection = {path:string;drill:true};
export const diskAllocationBasis='st_blocks_512_inode_deduplicated';
const allocationKeys=new Set(['allocated_bytes','allocated_file_bytes','unique_logical_bytes','unique_files','hardlink_entries','sparse_candidates']);
const fsBytes=new Set(['filesystem_capacity_bytes','filesystem_used_bytes','filesystem_available_bytes','filesystem_reserved_bytes']);
const fsInodes=new Set(['filesystem_total_inodes','filesystem_free_inodes','filesystem_used_inodes']);
const counters=new Set(['total_bytes','bytes','files','link_count','ignored_links','ignored_special','foreign_filesystems_skipped','directory_cycles_skipped','entries_scanned','read_batch_size',...allocationKeys,...fsBytes,...fsInodes]);

export function diskPath(value:unknown,root=false):value is string {
  if(typeof value!=='string')return false;
  if(root&&(value===''||value==='.'))return true;
  if(!value||new TextEncoder().encode(value).length>1024||value.startsWith('/')||value.includes('\\'))return false;
  for(const part of value.split('/')){
    if(!part||part==='.'||part==='..'||part.startsWith('.panel-'))return false;
    for(const char of part){const point=char.codePointAt(0)!;if(point<32||point===127||point>=0xd800&&point<=0xdfff)return false;}
  }
  return true;
}
export function diskDirectorySelection(base:unknown,name:unknown):DiskSelection|undefined {
  if(!diskPath(base,true)||typeof name!=='string'||!name||!diskPath(name,true))return;
  const path=[base==='.'?'':base,name==='.'?'':name].filter(Boolean).join('/');
  if(diskPath(path,true))return {path,drill:true};
}
export function diskFileSelection(row:unknown):DiskSelection|undefined {
  if(!row||typeof row!=='object'||Array.isArray(row))return;
  const value=row as Record<string,unknown>;
  if(value.can_drill!==true||!diskPath(value.path)||!diskPath(value.directory,true))return;
  const parent=value.path.includes('/')?value.path.slice(0,value.path.lastIndexOf('/')):'.';
  if(value.directory!==parent)return;
  return {path:parent==='.'?'':parent,drill:true};
}
export function diskValueNotice(report:Record<string,unknown>,key:string,value:unknown):string|undefined {
  if(!counters.has(key))return;
  if(fsBytes.has(key)&&report.filesystem_available!==true||fsInodes.has(key)&&report.filesystem_inodes_available!==true)return '未知';
  if(allocationKeys.has(key)&&report.allocation_basis!==diskAllocationBasis)return '分配块计算方式未核对';
  if(typeof value!=='number'||!Number.isFinite(value)||value<0||!Number.isInteger(value))return '未知';
  if(!Number.isSafeInteger(value))return '超出精确显示范围';
  if((key==='filesystem_capacity_bytes'||key==='filesystem_total_inodes')&&value===0)return '未知';
}

export interface TaskSelection {readonly pid:number;readonly start_time:number}
const object=(v:unknown):v is Record<string,unknown>=>!!v&&typeof v==='object'&&!Array.isArray(v)&&[Object.prototype,null].includes(Object.getPrototypeOf(v));
export function taskSelection(value:unknown):TaskSelection|undefined {
  if(!object(value)||value.managed!==true||value.can_terminate!==true||!Number.isSafeInteger(value.pid)||typeof value.pid!=='number'||value.pid<2||value.pid>2147483647||!Number.isSafeInteger(value.start_time)||typeof value.start_time!=='number'||value.start_time<1)return undefined;
  return Object.freeze({pid:value.pid,start_time:value.start_time});
}
export function taskTerminationNotice(value:unknown,pid:unknown):string {
  if(!object(value)||Object.keys(value).sort().join(',')!=='exit_verified,pid,signal,signal_accepted'||value.pid!==pid||typeof pid!=='number'||!Number.isSafeInteger(pid)||pid<2||pid>2147483647||value.signal!=='SIGTERM'||value.signal_accepted!==true||value.exit_verified!==false)throw Error('原进程信号回执无法完整核对；可能已发送，请刷新实际状态，不自动重发或宣称退出。');
  return 'SIGTERM 已发送；请刷新核对实际状态，不能据此认定进程已退出或服务已停止。';
}

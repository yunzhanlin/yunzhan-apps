import {platformFleetView} from './platformHealthView.ts';

export type PlatformSnapshotContext = {generation:number; installationID:string};
const validContext=(v:PlatformSnapshotContext|undefined):v is PlatformSnapshotContext=>!!v
  &&Number.isSafeInteger(v.generation)&&v.generation>=0&&/^[a-f0-9]{32}$/.test(v.installationID);

// Component-memory only: no local/session storage and no credentials. A page
// reopen is not a new health check. Retain one complete, bounded snapshot only
// for the exact authorization generation and actual installation identity.
export class PlatformHealthSnapshot {
  private saved?:{generation:number; installationID:string; json:string};
  clear(){this.saved=undefined;}
  remember(value:unknown,context:PlatformSnapshotContext|undefined):boolean {
    if(!validContext(context)){this.clear();return false;}
    try {
      const json=JSON.stringify(value);
      if(!json||new TextEncoder().encode(json).length>256*1024)return false;
      // Validate both the original and the detached JSON representation; NaN,
      // Infinity or omitted fields must not normalize into a plausible report.
      if(!platformFleetView(value)||!platformFleetView(JSON.parse(json)))return false;
      this.saved={...context,json};return true;
    }catch{return false;}
  }
  restore(context:PlatformSnapshotContext|undefined):Record<string,unknown>|undefined {
    if(!validContext(context)||!this.saved||this.saved.generation!==context.generation
      ||this.saved.installationID!==context.installationID){this.clear();return;}
    return JSON.parse(this.saved.json);
  }
}

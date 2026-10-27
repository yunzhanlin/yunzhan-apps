import { readFile, writeFile, mkdir, lstat, realpath } from "node:fs/promises";
import { createPrivateKey, createPublicKey, sign } from "node:crypto";
import { fileURLToPath } from "node:url";
import path from "node:path";

const root = fileURLToPath(new URL("..", import.meta.url));
const args=process.argv.slice(2);if(args.length>1||args.length===1&&args[0]!=='--candidate-apps')throw new Error('unknown fixed catalogue signing mode');
const candidate=args.length===1,output=path.join(root,candidate?'candidate':'');
const keyPath = process.env.YUNZHAN_APP_SIGNING_KEY;
if (!keyPath) throw new Error("YUNZHAN_APP_SIGNING_KEY must point to the offline Ed25519 private key");
const stat=await lstat(keyPath);
if(!path.isAbsolute(keyPath)||await realpath(keyPath)!==keyPath||!stat.isFile()||stat.isSymbolicLink()||stat.nlink!==1||stat.uid!==process.getuid()||(stat.mode&0o077)!==0)throw new Error('signing requires the existing ordinary owner-only offline key');
const body = await readFile(path.join(output, "dist/catalog-v1.json"));
const key = createPrivateKey(await readFile(keyPath));
const published=await readFile(path.join(root,'signatures/catalog-v1.pub.pem'));
if(key.asymmetricKeyType!=='ed25519'||!createPublicKey(key).export({type:'spki',format:'der'}).equals(createPublicKey(published).export({type:'spki',format:'der'})))throw new Error('signer does not match the unchanged official application trust root');
const signature = sign(null, body, key).toString("base64");
const outStat=await lstat(output);if(!outStat.isDirectory()||outStat.isSymbolicLink()||await realpath(output)!==path.resolve(output))throw new Error('catalogue signing output root is not canonical and ordinary');
try{await mkdir(path.join(output,'signatures'),{mode:0o755});}catch(error){if(error.code!=='EEXIST')throw error;}
const sigStat=await lstat(path.join(output,'signatures'));if(!sigStat.isDirectory()||sigStat.isSymbolicLink()||(sigStat.mode&0o022)!==0)throw new Error('signature directory is not ordinary');
for(const name of ['catalog-v1.pub.pem','catalog-v1.sig','catalog-v1.bundle.json']){
  try{const s=await lstat(path.join(output,'signatures',name));if(!s.isFile()||s.isSymbolicLink()||s.nlink!==1||(s.mode&0o022)!==0)throw new Error('signature output member is not ordinary');}
  catch(error){if(error.code!=='ENOENT')throw error;}
}
if(candidate){
  try{const old=await readFile(path.join(output,'signatures/catalog-v1.pub.pem'));if(!old.equals(published))throw new Error('candidate trust root changed');}
  catch(error){if(error.code!=='ENOENT')throw error;await writeFile(path.join(output,'signatures/catalog-v1.pub.pem'),published,{flag:'wx',mode:0o644});}
}
await writeFile(path.join(output, "signatures/catalog-v1.sig"), `${signature}\n`);
await writeFile(path.join(output, "signatures/catalog-v1.bundle.json"), JSON.stringify({ catalog: body.toString("utf8"), signature }) + "\n");
console.log("signed dist/catalog-v1.json with the offline Ed25519 key");

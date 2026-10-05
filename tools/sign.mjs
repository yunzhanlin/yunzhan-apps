import { readFile, writeFile } from "node:fs/promises";
import { createPrivateKey, sign } from "node:crypto";
import { fileURLToPath } from "node:url";
import path from "node:path";

const root = fileURLToPath(new URL("..", import.meta.url));
const keyPath = process.env.YUNZHAN_APP_SIGNING_KEY;
if (!keyPath) throw new Error("YUNZHAN_APP_SIGNING_KEY must point to the offline Ed25519 private key");
const body = await readFile(path.join(root, "dist/catalog-v1.json"));
const key = createPrivateKey(await readFile(keyPath));
const signature = sign(null, body, key).toString("base64");
await writeFile(path.join(root, "signatures/catalog-v1.sig"), `${signature}\n`);
console.log("signed dist/catalog-v1.json with the offline Ed25519 key");


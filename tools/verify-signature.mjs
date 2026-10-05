import { readFile } from "node:fs/promises";
import { createPublicKey, verify } from "node:crypto";
import { fileURLToPath } from "node:url";
import path from "node:path";

const root = fileURLToPath(new URL("..", import.meta.url));
const body = await readFile(path.join(root, "dist/catalog-v1.json"));
const signature = Buffer.from((await readFile(path.join(root, "signatures/catalog-v1.sig"), "utf8")).trim(), "base64");
const key = createPublicKey(await readFile(path.join(root, "signatures/catalog-v1.pub.pem")));
if (!verify(null, body, key, signature)) throw new Error("catalog signature is invalid");
const bundle = JSON.parse(await readFile(path.join(root, "signatures/catalog-v1.bundle.json"), "utf8"));
if (bundle.catalog !== body.toString("utf8") || bundle.signature !== signature.toString("base64")) throw new Error("atomic catalog bundle does not match signed catalog");
console.log("verified catalog Ed25519 signature");

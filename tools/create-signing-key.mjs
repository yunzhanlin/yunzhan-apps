import { mkdir, open, writeFile } from "node:fs/promises";
import { generateKeyPairSync } from "node:crypto";
import { fileURLToPath } from "node:url";
import path from "node:path";

const root = fileURLToPath(new URL("..", import.meta.url));
const privatePath = path.join(root, ".local/yunzhan-apps-ed25519.pem");
const publicPath = path.join(root, "signatures/catalog-v1.pub.pem");
await mkdir(path.dirname(privatePath), { recursive: true });
await mkdir(path.dirname(publicPath), { recursive: true });
try {
  const existing = await open(privatePath, "wx", 0o600);
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  await existing.writeFile(privateKey.export({ type: "pkcs8", format: "pem" }));
  await existing.close();
  await writeFile(publicPath, publicKey.export({ type: "spki", format: "pem" }), { mode: 0o644 });
  console.log("created offline Ed25519 signing key and publishable public key");
} catch (error) {
  if (error?.code === "EEXIST") throw new Error(`refusing to overwrite existing key: ${privatePath}`);
  throw error;
}

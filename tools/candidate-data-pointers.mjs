import { createHash, createPublicKey, verify } from 'node:crypto';
import { lstat, readFile, realpath } from 'node:fs/promises';
import path from 'node:path';

const cityDirectory = 'data/geodata/dbip-city-lite-v1';
const etDirectory = 'dist/apps/network-threat-detection/rule-data/et-open-web-bsd-v1';
const etPointers = new Set(['catalog-v1.json', 'catalog-v1.sig', 'catalog-v1.bundle.json']);
const keyPin = '659ea4edcecaf23a586e2ff371616fde5f6ee7c219fb70fa978816e2b10acf75';
const sha = bytes => createHash('sha256').update(bytes).digest('hex');

async function readOrdinary(file, limit) {
  const info = await lstat(file);
  if (!info.isFile() || info.nlink !== 1 || info.size < 1 || info.size > limit || await realpath(file) !== file) {
    throw Error('signed data pointer file identity is invalid');
  }
  const bytes = await readFile(file);
  if (bytes.length !== info.size) throw Error('signed data pointer changed during read');
  return bytes;
}

async function verifiedPointer(directory, type, key) {
  const isCity = type === 'city';
  const file = isCity ? 'catalog.signed.json' : 'catalog-v1.bundle.json';
  const envelope = JSON.parse(await readOrdinary(path.join(directory,file), 64 << 10));
  const field = isCity ? 'manifest' : 'catalog';
  const message = envelope[field];
  const signature = envelope.signature;
  if (Object.keys(envelope).sort().join(',') !== [field,'signature'].join(',') ||
      typeof message !== 'string' || typeof signature !== 'string') {
    throw Error('signed data pointer format is invalid');
  }
  const signatureBytes = Buffer.from(signature,'base64');
  const domain = isCity ? 'yunzhan-geodata-city-v1\n' : 'yunzhan-rulefeed-channel-v1\n';
  if (signatureBytes.length !== 64 || signatureBytes.toString('base64') !== signature ||
      !verify(null, Buffer.from(domain + message), key, signatureBytes)) {
    throw Error('signed data pointer signature is invalid');
  }
  const document = JSON.parse(message);
  if (isCity) {
    const release = document.release;
    if (document.format !== 1 || document.channel !== 'dbip-city-lite-v1' ||
        typeof release !== 'string' || !/^20[2-9][0-9]-(0[1-9]|1[0-2])$/.test(release)) {
      throw Error('signed city data release identity is invalid');
    }
    const retained = path.join(directory,'releases',release + '-' + sha(message));
    if (!(await readOrdinary(path.join(retained,'manifest.json'),4096)).equals(Buffer.from(message)) ||
        (await readOrdinary(path.join(retained,'manifest.json.sig'),128)).toString('utf8').trim() !== signature) {
      throw Error('signed city data pointer differs from its immutable manifest');
    }
    return release;
  }
  if (document.schema_version !== 1 || document.channel !== 'et-open-web-bsd-v1' ||
      !Number.isSafeInteger(document.sequence) || document.sequence < 1 ||
      !(await readOrdinary(path.join(directory,'catalog-v1.json'),64 << 10)).equals(Buffer.from(message)) ||
      (await readOrdinary(path.join(directory,'catalog-v1.sig'),128)).toString('utf8').trim() !== signature) {
    throw Error('signed ET Open data pointer differs from its catalogue');
  }
  const feed = document.feed;
  if (!feed || !/^et-open-web-20[2-9][0-9]{5}$/.test(feed.id) ||
      typeof feed.manifest_sha256 !== 'string' || !/^[a-f0-9]{64}$/.test(feed.manifest_sha256)) {
    throw Error('signed ET Open feed identity is invalid');
  }
  const manifest = await readOrdinary(path.join(directory,'feeds',feed.id,feed.manifest_sha256,'manifest.json'),32 << 10);
  if (sha(manifest) !== feed.manifest_sha256) throw Error('signed ET Open feed manifest differs');
  return document.sequence;
}

// A newer independently signed data pointer in the candidate channel is kept.
// Application packages and individual data releases remain immutable.
export async function preserveCandidateDataPointer(root, relative) {
  const directory = path.posix.dirname(relative);
  const name = path.posix.basename(relative);
  let type;
  if (directory === cityDirectory && name === 'catalog.signed.json') type = 'city';
  else if (directory === etDirectory && etPointers.has(name)) type = 'et';
  else return false;
  const publicKey = await readOrdinary(path.join(root,'signatures/catalog-v1.pub.pem'),256);
  if (sha(publicKey) !== keyPin) throw Error('original pinned application signing key is required');
  const key = createPublicKey(publicKey);
  const stable = await verifiedPointer(path.join(root,directory),type,key);
  const candidate = await verifiedPointer(path.join(root,'candidate',directory),type,key);
  if (candidate <= stable) throw Error('candidate data pointer is not newer than the stable pointer');
  return true;
}

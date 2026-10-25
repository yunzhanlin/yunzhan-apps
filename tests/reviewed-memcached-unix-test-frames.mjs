// Remove only declared historical-input selectors and the missing fixture dependency.
// All prior assertion bytes remain pinned to the actual accepted merge tree.
import assert from'node:assert/strict';import{createHash}from'node:crypto';
export const reviewedMemcachedUnixReaders={
  "tests/geodata-admission-source.test.mjs": {
    "path": "tests/geodata-admission-source.test.mjs",
    "importLine": "import{historicalMemcachedUnixInput}from'./reviewed-memcached-unix-inputs.mjs';\n",
    "edits": [
      {
        "from": "read=n=>historicalMemcachedUnixInput(root,n)",
        "to": "read=n=>fs.readFileSync(root+n)",
        "count": 1
      }
    ],
    "before": "6f166025c79e541eeb5af377b79acfcf223ac591028b312e412b5b4edf95ddc3",
    "after": "1fde93057604924beb490fd156e93d89f5e621b3ca23547e4539d4af8e9d410d"
  },
  "tests/memcached-retirement-source.test.mjs": {
    "path": "tests/memcached-retirement-source.test.mjs",
    "importLine": "import{historicalMemcachedUnixInput}from'./reviewed-memcached-unix-inputs.mjs';\n",
    "edits": [
      {
        "from": "read=n=>historicalMemcachedUnixInput(root,n)",
        "to": "read=n=>fs.readFileSync(root+n)",
        "count": 1
      }
    ],
    "before": "0900762daa2faea2d4737a960d2fd56d0d7c40054a8e4532e1627e695aead205",
    "after": "5e50d4b3fe3eb14a41da6d64f5482d39d48d3a6e332f7a4b57105ba322884715"
  },
  "tests/memcached-review-source.test.mjs": {
    "path": "tests/memcached-review-source.test.mjs",
    "importLine": "import{historicalMemcachedUnixInput}from'./reviewed-memcached-unix-inputs.mjs';\n",
    "edits": [
      {
        "from": "read=n=>historicalMemcachedUnixInput(root,n)",
        "to": "read=n=>fs.readFileSync(root+n)",
        "count": 1
      }
    ],
    "before": "c6261294f91e13a48661b77260983f2b774fdf84c6f61cca09fd28ad395a6533",
    "after": "1b55d221e46cde79cffcf04c1f213e0839d55232edcb3e8911b3a69f73641cfb"
  },
  "tests/memcached-unix-source.test.mjs": {
    "path": "tests/memcached-unix-source.test.mjs",
    "importLine": "import{historicalMemcachedUnixInput}from'./reviewed-memcached-unix-inputs.mjs';\n",
    "edits": [
      {
        "from": "read=n=>historicalMemcachedUnixInput(root,n)",
        "to": "read=n=>fs.readFileSync(root+n)",
        "count": 1
      }
    ],
    "before": "a464c943ac6dfea22b3f1fba7dac58ffc7baf0a89d375845815bcc455936cd77",
    "after": "20281c55945282dd0b84175d6ed52b997e9e8847835acb1d368abdc9e8f751f2"
  },
  "tests/redis-privilege-source.test.mjs": {
    "path": "tests/redis-privilege-source.test.mjs",
    "importLine": "import{historicalMemcachedUnixInput}from'./reviewed-memcached-unix-inputs.mjs';\n",
    "edits": [
      {
        "from": "read=n=>historicalMemcachedUnixInput(root,n)",
        "to": "read=n=>fs.readFileSync(root+n)",
        "count": 1
      }
    ],
    "before": "578419159a18084a0d183ed167a294273c4b8a6b5bb4af0028b08bbd49b96134",
    "after": "aec3d59a12d815f177686d5f02430fc0c4d399a3277977cf4454f3d537c76957"
  },
  "tests/mobile-delivery-source.test.mjs": {
    "path": "tests/mobile-delivery-source.test.mjs",
    "importLine": "import{historicalMemcachedUnixInput}from'./reviewed-memcached-unix-inputs.mjs';\n",
    "edits": [
      {
        "from": "read=n=>historicalMemcachedUnixInput(base,n)",
        "to": "read=n=>fs.readFileSync(path.join(base,n))",
        "count": 1
      }
    ],
    "before": "ba491a827c93a920918cef569af2788dd6685bfa0f8b2f69254bcfadce8b3f06",
    "after": "2a57df13c7d7a1641405ec861a35587ceaa1d11cd174e3dad861b5bac138d702"
  },
  "tests/memcached-digest-contract.test.mjs": {
    "path": "tests/memcached-digest-contract.test.mjs",
    "importLine": "import{historicalMemcachedUnixSchemaURL}from'./reviewed-memcached-unix-inputs.mjs';\n",
    "edits": [
      {
        "from": "historicalMemcachedUnixSchemaURL(import.meta.url)",
        "to": "new URL('../schema/app.schema.json',import.meta.url)",
        "count": 1
      }
    ],
    "before": "3e2224b7bbd0b1d9b7e5a4b7ed60237d0844daf4f8491011223fc3fd63db4b19",
    "after": "646101627b9a2d0f8098045f843d1c7a9bc92704cfe9ea5fee844179afad1a50"
  },
  "tests/platform-maintenance-manifest.test.mjs": {
    "path": "tests/platform-maintenance-manifest.test.mjs",
    "importLine": "import{historicalMemcachedUnixSchemaURL}from'./reviewed-memcached-unix-inputs.mjs';\n",
    "edits": [
      {
        "from": "const schema=JSON.parse(await readFile(historicalMemcachedUnixSchemaURL(import.meta.url),'utf8'));",
        "to": "const schema=JSON.parse(await read('schema/app.schema.json'));",
        "count": 1
      }
    ],
    "before": "b60670f95360e2f39e636cba619278870a8481144868eafa0df7e0660d437b45",
    "after": "617a0b196f37e64e56537deac4e8e2a12cd7f45d61995b0faf7441ffa5613ff3"
  },
  "tests/php-bounded-contract.test.mjs": {
    "path": "tests/php-bounded-contract.test.mjs",
    "importLine": "import{historicalPHPBoundedCases}from'./reviewed-memcached-unix-inputs.mjs';\n",
    "edits": [
      {
        "from": "const cases=historicalPHPBoundedCases(root)",
        "to": "const cases=phpBoundedCases(root)",
        "count": 1
      }
    ],
    "before": "a999c2cb220d748727a4d0efe57fdd5526f87e73b5aeb018b4544d095f1c9514",
    "after": "46a8ea35364be91c551ccea132d2772991254a21a4cf61f179cc23d9f6f5bd8f"
  },
  "tests/geodata-channel-publisher.test.mjs": {
    "path": "tests/geodata-channel-publisher.test.mjs",
    "importLine": "",
    "edits": [
      {
        "from": "'tools/lib.mjs','tools/memcached-unix-contract.mjs','tools/php-security-contract.mjs'",
        "to": "'tools/lib.mjs','tools/php-security-contract.mjs'",
        "count": 1
      }
    ],
    "before": "de6432038e07003906b4af179d14eecd5cba1bcb90f33d816addf6ef4c491474",
    "after": "90c152464027dd184b79d57cef9a0a12cb50002a6c1fcc9aff98d95c00ae8784"
  },
  "tests/versioning.test.mjs": {
    "path": "tests/versioning.test.mjs",
    "importLine": "",
    "edits": [
      {
        "from": "'build.mjs','lib.mjs','memcached-unix-contract.mjs','php-security-contract.mjs'",
        "to": "'build.mjs','lib.mjs','php-security-contract.mjs'",
        "count": 1
      }
    ],
    "before": "e33d08b61a884b8e7323e0329de5a147a5da8de5a1d256e1274336a94fcfecf6",
    "after": "32e687b004e67d826b502216a1ccfe9bcca5f5af078ab67694654df26724ad0a"
  }
};
export function originalReviewedMemcachedUnixTest(path,bytes){
 const plan=reviewedMemcachedUnixReaders[path];if(!plan)return bytes;
 const sha=b=>createHash('sha256').update(b).digest('hex');if(sha(bytes)===plan.before)return bytes;
 assert.equal(sha(bytes),plan.after,'Unknown reader or assertion change is not an input qualification');
 let text=bytes.toString();
 if(plan.importLine){assert.equal(text.split(plan.importLine).length,2);text=text.replace(plan.importLine,()=> '');}
 for(const e of plan.edits){assert.equal(text.split(e.from).length-1,e.count);text=text.replaceAll(e.from,()=>e.to);}
 assert.equal(sha(text),plan.before,'Every original assertion and fixture remains byte-identical');return Buffer.from(text);
}

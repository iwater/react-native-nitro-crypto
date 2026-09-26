#!/usr/bin/env node
// 从 node 的 `require('crypto').constants` 生成 `src/impl/constants.ts`。
//
// 用法（在 `react-native-nitro-crypto/` 下）：
//     node scripts/gen-constants.mjs            # 写文件
//     node scripts/gen-constants.mjs --check    # 只比对不写（给 CI / 复核用）
//
// ⚠️ 必须用**参照 node** 跑（本仓口径 = Node.js，当前 v22.22.2）。
//    实测 v22.22.2 → v24.19.0：键集合 **56 个完全不变**，唯一会变的值是
//    `OPENSSL_VERSION_NUMBER`（810549328 → 810549360）⇒ 换参照 node 时重跑本脚本即可。
//
// 为什么是「镜像 node」而不是「回报原生库」：
//   本模块的原生侧是 原生层—— **纯 RustCrypto**
//   （rsa / p256 / p384 / p521 / k256 / ed25519 / x25519 / aes-gcm / chacha20poly1305 /
//   ocb3 / ml-kem / ml-dsa …），**不链接 OpenSSL**，`nm` 里 OpenSSL 符号 **0 个**，
//   源码里 `SSL_OP_*` / `OPENSSL_VERSION_NUMBER` **一个都没有**。
//   ⇒ 「让原生侧用编译期的 `SSL_OP_*` 填充」这条路**不存在**（硬要在 Rust 里再写一张同样的
//     表只是把硬编码搬个地方，白付一次跨 FFI 成本）。
//   而 `crypto.constants` 是 **Node API 契约**：用户拿它做特性检测（`'SSL_OP_NO_TLSv1_3' in …`）
//   与版本比较（`=== TLS1_2_VERSION`）。node 的值就是唯一真值 ⇒ **逐键对齐**。
import { createRequire } from 'node:module';
import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const require_ = createRequire(import.meta.url);
const HERE = dirname(fileURLToPath(import.meta.url));
const OUT = join(HERE, '..', 'src', 'impl', 'constants.ts');

const c = require_('crypto').constants;
// ⚠️ 保持 node 的**插入顺序**：`Object.keys()` 的键序本身也是可观测面
//    （`for...in` / `JSON.stringify` 都按它走），所以不排序。
const keys = Object.keys(c);

/** 分组用：取前两段下划线前缀（`SSL_OP_ALL` → `SSL_OP`），不足三段就用整个名字。 */
function groupOf(k) {
  const parts = k.split('_');
  return parts.length >= 3 ? parts.slice(0, 2).join('_') : k;
}

function literal(v) {
  return typeof v === 'string' ? JSON.stringify(v) : String(v);
}

const header = [
  '// ⚠️ 本文件是**生成物**，勿手改 —— 由 `scripts/gen-constants.mjs` 从 node 的',
  "//    `require('crypto').constants` 逐键生成（**保留 node 的键序**）。",
  '//',
  '//    生成 / 校验（在 `react-native-nitro-crypto/` 下）：',
  '//        node scripts/gen-constants.mjs            # 重新生成（= npm run gen-constants）',
  '//        node scripts/gen-constants.mjs --check    # 只比对不写（= npm run check-constants）',
  '//',
  '//    ⚠️ 生成之后必须跑 `tsc`（或 `npm run build`）才会更新运行期真正加载的 `lib/`。',
  '//    ⚠️ `--check` 必须用**参照 node** 跑：换 node 大版本时 `OPENSSL_VERSION_NUMBER`',
  '//       必然不同，那是预期的（脚本会单独提示），别为了消掉它重新生成。',
  '//',
  `//    目标运行时：${process.version} (${process.platform} ${process.arch})`,
  '//    —— 与 Node.js一致。',
  '//',
  '// ── 为什么是「镜像 node」而不是「回报原生库」 ────────────────────────────',
  '// 本模块的原生侧是 原生层：**纯 RustCrypto**',
  '// （rsa / p256 / p384 / p521 / k256 / ed25519 / x25519 / aes-gcm / ocb3 / ml-kem / ml-dsa…），',
  '// **不链接 OpenSSL**（`nm` 里 OpenSSL 符号 0 个），源码里连 `SSL_OP_*` 这个名字都没有',
  "// ⇒ 「让原生侧用编译期的 SSL_OP_* 填充」这条路不存在。",
  '// 而 `crypto.constants` 是 **Node API 契约**（特性检测 `\'X\' in constants`、版本比较',
  '// `=== TLS1_2_VERSION`），node 的值就是唯一真值 ⇒ 逐键对齐。',
  '//',
  '// ── 版本敏感性 ───────────────────────────────────────────────────────',
  '// 实测 node v22.22.2 → v24.19.0：**键集合 56 个完全不变**，唯一会变的值是',
  '// `OPENSSL_VERSION_NUMBER`（810549328 → 810549360，都是 OpenSSL 3.5.0 的不同 patch）。',
  '// 换参照 node 时重跑生成脚本即可 —— 这是本表唯一需要「刷新」的地方。',
  '//',
  '// ── 三个容易漏的可观测特征（已一并镜像） ───────────────────────────────',
  '// 1. node 的 `crypto.constants` 是 **null 原型**对象（`Object.getPrototypeOf === null`）',
  '//    ⇒ `\'toString\' in constants` 为 `false`。用 `Object.create(null)` 构造。',
  '// 2. 键序 = node 的插入顺序（生成时保留，不排序）。',
  '// 3. 属性形态：node 的 54 个数字键 + `defaultCoreCipherList` 是',
  '//    `writable:false, configurable:false`（绑定层只读常量），`defaultCipherList` 是',
  '//    `writable:true, configurable:true`。用 `Object.defineProperty` 逐个对齐。',
  '//    ⚠️ 未镜像的**瞬态**：node 在首次读 `defaultCipherList` **之前**它是 get/set 访问器',
  '//    （其 getter 首次求值时会把自己重定义成可写数据属性）—— 本文件对应 node 的**稳定态**。',
  '//',
  '// ── 锁定 ─────────────────────────────────────────────────────────────',
  '// 测试套件 把本表与 node **逐键逐值**比对',
  '// （两侧 stdout 必须逐字节相同）。表被改坏会立刻红。',
  '//',
  '// ⚠️ 本模块**自己只用** `RSA_*_PADDING`：`src/index.ts:345/368/387/402`、',
  '//    `src/impl/SubtleCrypto.ts:578/628`（共 6 处）。其余键纯粹是 API 契约面。',
  '',
  'const nodeConstants = {',
];

const body = [];
let lastGroup = null;
for (const k of keys) {
  const g = groupOf(k);
  if (g !== lastGroup) {
    if (lastGroup !== null) body.push('');
    body.push(`    // --- ${g} ---`);
    lastGroup = g;
  }
  body.push(`    ${k}: ${literal(c[k])},`);
}

const footer = [
  '}',
  '',
  '// 对齐 node 的**对象层**可观测特征（实测）：',
  '//   · null 原型（`Object.getPrototypeOf === null` ⇒ `\'toString\' in constants` 为 false）',
  '//   · 键序 = 上面书写的顺序（= node 的插入顺序；`Object.assign` 按 `Object.keys` 拷贝）',
  'export const constants: typeof nodeConstants = Object.assign(Object.create(null), nodeConstants);',
  '',
  '// · 属性形态：node 的 54 个数字键 + `defaultCoreCipherList` 是 `writable:false,',
  '//   configurable:false`（绑定层只读常量），`defaultCipherList` 是 `writable:true,',
  '//   configurable:true`。重定义时省略 `value` / `enumerable` ⇒ 只改这两个属性位。',
  '//   ⚠️ 未镜像的**瞬态**：node 在首次读 `defaultCipherList` **之前**它是 get/set 访问器',
  '//   （getter 首次求值时会把自己重定义成可写数据属性）；本文件对应 node 的**稳定态**。',
  'for (const k of Object.keys(constants)) {',
  "  if (k === 'defaultCipherList') continue;",
  '  Object.defineProperty(constants, k, { writable: false, configurable: false });',
  '}',
  '',
];

const out = header.concat(body, footer).join('\n');
const rel = 'src/impl/constants.ts';

if (process.argv.includes('--check')) {
  let cur = '';
  try { cur = readFileSync(OUT, 'utf8'); } catch { /* 不存在也算不一致 */ }
  if (cur === out) {
    console.log(`ok ${rel} 与 node ${process.version} 的 crypto.constants 一致（${keys.length} 键）`);
    process.exit(0);
  }
  // ⚠️ 唯一**允许**的差异是 `OPENSSL_VERSION_NUMBER`（值）与表头的「目标运行时」（版本号）
  //    —— 两者都随 node 内置的 OpenSSL / node 版本走
  //    （v22.22.2 → 810549328，v24.19.0 → 810549360）。这时**不要**重新生成：
  //    生成时的 Node.js 版本是**固定**的（见文件头），改了会让 与 Node.js 的对照测试变红。
  const a = cur.split('\n');
  const b = out.split('\n');
  const differing = [];
  for (let i = 0; i < Math.max(a.length, b.length); i++) {
    if (a[i] !== b[i]) differing.push(i);
  }
  const benign = (line) => {
    const t = (line || '').trim();
    return t.startsWith('OPENSSL_VERSION_NUMBER:') || t.startsWith('//    目标运行时：');
  };
  const onlyVersionDependent = differing.length > 0 &&
    differing.every((i) => benign(a[i]) && benign(b[i]));
  if (onlyVersionDependent) {
    console.error(`FAIL ${rel} 与 node ${process.version} 的唯一差异是**随 node 版本走的两行**：`);
    for (const i of differing) {
      console.error(`     文件里   ${(a[i] || '').trim()}`);
      console.error(`     本次 node ${(b[i] || '').trim()}`);
    }
    console.error('     ⇒ 这是**预期**的（`OPENSSL_VERSION_NUMBER` 随 node 内置的 OpenSSL 版本走）。');
    console.error('       **不要**为了消掉它重新生成 —— 本仓的参照 node 固定在文件头写明的版本，');
    console.error('       改了会让 与 Node.js 的对照测试变红。');
    process.exit(1);
  }
  console.error(`FAIL ${rel} 与 node ${process.version} 的 crypto.constants **不一致**（${differing.length} 行不同）——`);
  console.error('     跑 `node scripts/gen-constants.mjs` 重新生成（用参照 node）。');
  process.exit(1);
}

writeFileSync(OUT, out);
console.log(`已生成 ${rel}：${keys.length} 键（来自 node ${process.version}）`);

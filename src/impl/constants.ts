// ⚠️ 本文件是**生成物**，勿手改 —— 由 `scripts/gen-constants.mjs` 从 node 的
//    `require('crypto').constants` 逐键生成（**保留 node 的键序**）。
//
//    生成 / 校验（在 `react-native-nitro-crypto/` 下）：
//        node scripts/gen-constants.mjs            # 重新生成（= npm run gen-constants）
//        node scripts/gen-constants.mjs --check    # 只比对不写（= npm run check-constants）
//
//    ⚠️ 生成之后必须跑 `tsc`（或 `npm run build`）才会更新运行期真正加载的 `lib/`。
//    ⚠️ `--check` 必须用**参照 node** 跑：换 node 大版本时 `OPENSSL_VERSION_NUMBER`
//       必然不同，那是预期的（脚本会单独提示），别为了消掉它重新生成。
//
//    目标运行时：v22.22.2 (darwin arm64)
//    —— 与 Node.js一致。
//
// ── 为什么是「镜像 node」而不是「回报原生库」 ────────────────────────────
// 本模块的原生侧是 原生层：**纯 RustCrypto**
// （rsa / p256 / p384 / p521 / k256 / ed25519 / x25519 / aes-gcm / ocb3 / ml-kem / ml-dsa…），
// **不链接 OpenSSL**（`nm` 里 OpenSSL 符号 0 个），源码里连 `SSL_OP_*` 这个名字都没有
// ⇒ 「让原生侧用编译期的 SSL_OP_* 填充」这条路不存在。
// 而 `crypto.constants` 是 **Node API 契约**（特性检测 `'X' in constants`、版本比较
// `=== TLS1_2_VERSION`），node 的值就是唯一真值 ⇒ 逐键对齐。
//
// ── 版本敏感性 ───────────────────────────────────────────────────────
// 实测 node v22.22.2 → v24.19.0：**键集合 56 个完全不变**，唯一会变的值是
// `OPENSSL_VERSION_NUMBER`（810549328 → 810549360，都是 OpenSSL 3.5.0 的不同 patch）。
// 换参照 node 时重跑生成脚本即可 —— 这是本表唯一需要「刷新」的地方。
//
// ── 三个容易漏的可观测特征（已一并镜像） ───────────────────────────────
// 1. node 的 `crypto.constants` 是 **null 原型**对象（`Object.getPrototypeOf === null`）
//    ⇒ `'toString' in constants` 为 `false`。用 `Object.create(null)` 构造。
// 2. 键序 = node 的插入顺序（生成时保留，不排序）。
// 3. 属性形态：node 的 54 个数字键 + `defaultCoreCipherList` 是
//    `writable:false, configurable:false`（绑定层只读常量），`defaultCipherList` 是
//    `writable:true, configurable:true`。用 `Object.defineProperty` 逐个对齐。
//    ⚠️ 未镜像的**瞬态**：node 在首次读 `defaultCipherList` **之前**它是 get/set 访问器
//    （其 getter 首次求值时会把自己重定义成可写数据属性）—— 本文件对应 node 的**稳定态**。
//
// ── 锁定 ─────────────────────────────────────────────────────────────
// 测试套件 把本表与 node **逐键逐值**比对
// （两侧 stdout 必须逐字节相同）。表被改坏会立刻红。
//
// ⚠️ 本模块**自己只用** `RSA_*_PADDING`：`src/index.ts:345/368/387/402`、
//    `src/impl/SubtleCrypto.ts:578/628`（共 6 处）。其余键纯粹是 API 契约面。

const nodeConstants = {
    // --- OPENSSL_VERSION ---
    OPENSSL_VERSION_NUMBER: 810549328,

    // --- SSL_OP ---
    SSL_OP_ALL: 2147485776,
    SSL_OP_ALLOW_NO_DHE_KEX: 1024,
    SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION: 262144,
    SSL_OP_CIPHER_SERVER_PREFERENCE: 4194304,
    SSL_OP_CISCO_ANYCONNECT: 32768,
    SSL_OP_COOKIE_EXCHANGE: 8192,
    SSL_OP_CRYPTOPRO_TLSEXT_BUG: 2147483648,
    SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS: 2048,
    SSL_OP_LEGACY_SERVER_CONNECT: 4,
    SSL_OP_NO_COMPRESSION: 131072,
    SSL_OP_NO_ENCRYPT_THEN_MAC: 524288,
    SSL_OP_NO_QUERY_MTU: 4096,
    SSL_OP_NO_RENEGOTIATION: 1073741824,
    SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION: 65536,
    SSL_OP_NO_SSLv2: 0,
    SSL_OP_NO_SSLv3: 33554432,
    SSL_OP_NO_TICKET: 16384,
    SSL_OP_NO_TLSv1: 67108864,
    SSL_OP_NO_TLSv1_1: 268435456,
    SSL_OP_NO_TLSv1_2: 134217728,
    SSL_OP_NO_TLSv1_3: 536870912,
    SSL_OP_PRIORITIZE_CHACHA: 2097152,
    SSL_OP_TLS_ROLLBACK_BUG: 8388608,

    // --- ENGINE_METHOD ---
    ENGINE_METHOD_RSA: 1,
    ENGINE_METHOD_DSA: 2,
    ENGINE_METHOD_DH: 4,
    ENGINE_METHOD_RAND: 8,
    ENGINE_METHOD_EC: 2048,
    ENGINE_METHOD_CIPHERS: 64,
    ENGINE_METHOD_DIGESTS: 128,
    ENGINE_METHOD_PKEY_METHS: 512,
    ENGINE_METHOD_PKEY_ASN1_METHS: 1024,
    ENGINE_METHOD_ALL: 65535,
    ENGINE_METHOD_NONE: 0,

    // --- DH_CHECK ---
    DH_CHECK_P_NOT_SAFE_PRIME: 2,
    DH_CHECK_P_NOT_PRIME: 1,

    // --- DH_UNABLE ---
    DH_UNABLE_TO_CHECK_GENERATOR: 4,

    // --- DH_NOT ---
    DH_NOT_SUITABLE_GENERATOR: 8,

    // --- RSA_PKCS1 ---
    RSA_PKCS1_PADDING: 1,

    // --- RSA_NO ---
    RSA_NO_PADDING: 3,

    // --- RSA_PKCS1 ---
    RSA_PKCS1_OAEP_PADDING: 4,

    // --- RSA_X931 ---
    RSA_X931_PADDING: 5,

    // --- RSA_PKCS1 ---
    RSA_PKCS1_PSS_PADDING: 6,

    // --- RSA_PSS ---
    RSA_PSS_SALTLEN_DIGEST: -1,
    RSA_PSS_SALTLEN_MAX_SIGN: -2,
    RSA_PSS_SALTLEN_AUTO: -2,

    // --- defaultCoreCipherList ---
    defaultCoreCipherList: "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA256:ECDHE-RSA-AES256-SHA384:DHE-RSA-AES256-SHA384:ECDHE-RSA-AES256-SHA256:DHE-RSA-AES256-SHA256:HIGH:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!SRP:!CAMELLIA",

    // --- TLS1_VERSION ---
    TLS1_VERSION: 769,

    // --- TLS1_1 ---
    TLS1_1_VERSION: 770,

    // --- TLS1_2 ---
    TLS1_2_VERSION: 771,

    // --- TLS1_3 ---
    TLS1_3_VERSION: 772,

    // --- POINT_CONVERSION ---
    POINT_CONVERSION_COMPRESSED: 2,
    POINT_CONVERSION_UNCOMPRESSED: 4,
    POINT_CONVERSION_HYBRID: 6,

    // --- defaultCipherList ---
    defaultCipherList: "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA256:ECDHE-RSA-AES256-SHA384:DHE-RSA-AES256-SHA384:ECDHE-RSA-AES256-SHA256:DHE-RSA-AES256-SHA256:HIGH:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!SRP:!CAMELLIA",
}

// 对齐 node 的**对象层**可观测特征（实测）：
//   · null 原型（`Object.getPrototypeOf === null` ⇒ `'toString' in constants` 为 false）
//   · 键序 = 上面书写的顺序（= node 的插入顺序；`Object.assign` 按 `Object.keys` 拷贝）
export const constants: typeof nodeConstants = Object.assign(Object.create(null), nodeConstants);

// · 属性形态：node 的 54 个数字键 + `defaultCoreCipherList` 是 `writable:false,
//   configurable:false`（绑定层只读常量），`defaultCipherList` 是 `writable:true,
//   configurable:true`。重定义时省略 `value` / `enumerable` ⇒ 只改这两个属性位。
//   ⚠️ 未镜像的**瞬态**：node 在首次读 `defaultCipherList` **之前**它是 get/set 访问器
//   （getter 首次求值时会把自己重定义成可写数据属性）；本文件对应 node 的**稳定态**。
for (const k of Object.keys(constants)) {
  if (k === 'defaultCipherList') continue;
  Object.defineProperty(constants, k, { writable: false, configurable: false });
}

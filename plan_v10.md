# Plan v10: 后端钱包逻辑解耦 — 按 UR 类型重构

## 1. 问题分析

当前 connect wallet 的架构是**按钱包名划分后端逻辑**，导致同一个 UR 类型在多个钱包模块中重复实现。

### 1.1 钱包逻辑渗透深度

| 层级 | 文件 | 钱包专属代码 | 说明 |
|---|---|---|---|
| **C 层** | `gui_wallet.c` | ~15 个 `GuiGetXxxData()` 函数 | 每个钱包一个函数，调用对应的 Rust FFI |
| **C 层** | `gui_connect_wallet_widgets.c` | ~30 个钱包的 UI + 路由 | 已在 Phase 5 删除 |
| **Rust FFI** | `rust_c/src/wallet/multi_coins_wallet/*.rs` | ~13 个文件 | 每个钱包一个 FFI 函数，调用 `app_wallets` |
| **Rust App** | `rust/apps/wallets/src/*.rs` | ~13 个模块 | 每个钱包一个模块，构造 UR 数据结构 |

### 1.2 重复分析

`ur:crypto-multi-accounts` 被 18+ 个钱包使用，但每个钱包在 `app_wallets` 中都有自己的 `generate_crypto_multi_accounts()` 实现：

```
rust/apps/wallets/src/backpack.rs        → generate_crypto_multi_accounts()
rust/apps/wallets/src/bitget.rs          → generate_crypto_multi_accounts()
rust/apps/wallets/src/core_wallet.rs     → generate_crypto_multi_accounts()
rust/apps/wallets/src/keystone_connect.rs → generate_crypto_multi_accounts()
rust/apps/wallets/src/okx.rs             → generate_crypto_multi_accounts()
rust/apps/wallets/src/thor_wallet.rs     → generate_crypto_multi_accounts()
```

这些函数的核心逻辑完全相同：遍历 `ExtendedPublicKey[]`，根据路径判断密钥类型（ed25519/secp256k1），构造 `CryptoHDKey`，最后组装 `CryptoMultiAccounts`。唯一差异是：
- 个别钱包对特定路径有特殊处理（如 Backpack 的 ETH LedgerLive 子派生）
- 个别钱包添加了 `note` 字段（如 "account.standard"）

但这些差异**不应该存在于后端**。

### 1.3 核心问题

1. **后端关心了前端语义**：后端知道"MetaMask"、"Backpack"等钱包名，违反 opaque bytes 原则
2. **代码重复**：同一 UR 类型的构造逻辑在 6+ 个文件中重复
3. **扩展性差**：新增一个用 `ur:crypto-multi-accounts` 的钱包，需要改 3 层代码
4. **耦合风险**：MetaMask 改 UR 类型，后端要跟着改

## 2. 目标架构

```
┌─────────────────────────────────────────────────────────────┐
│ 前端（C 层）                                                 │
│                                                             │
│  用户选择钱包/币种/路径                                       │
│    → 前端查表确定 UR 类型 + 组装密钥参数                       │
│    → 调用后端 UR 生成 API（按 UR 类型）                       │
└──────────────────────────┬──────────────────────────────────┘
                           │
┌──────────────────────────▼──────────────────────────────────┐
│ 后端 API（按 UR 类型，不关心钱包名）                          │
│                                                             │
│  generate_ur_crypto_account(mfp, keys)         → ur:crypto-account       │
│  generate_ur_crypto_hd_key(mfp, key, path)     → ur:crypto-hd-key        │
│  generate_ur_crypto_multi_accounts(mfp, keys)  → ur:crypto-multi-accounts │
│  generate_ur_bytes(data, tag)                  → ur:bytes                 │
│  generate_ur_arweave_account(mfp, key)         → ur:arweave-crypto-account│
│  generate_ur_zcash_accounts(sfp, keys)         → ur:zcash-accounts        │
│  generate_ur_xmr_json(spend_key, view_key)     → JSON text               │
└─────────────────────────────────────────────────────────────┘
```

### 2.1 后端职责

后端只做两件事：
1. **构造 UR 数据结构**：将密钥 + 路径 + 指纹组装为 `ur_registry` 类型
2. **编码为 UR 字符串**：调用 `ur_parse_lib::probe_encode()` 输出 UR

后端**不关心**：
- 这是给哪个钱包用的
- 用户在前端选了什么钱包名
- 钱包期望什么格式（这是前端的查表逻辑）

### 2.2 前端职责

前端负责：
1. **钱包→UR 类型映射表**：`MetaMask → ur:crypto-hd-key`、`Solfare → ur:crypto-multi-accounts` 等
2. **组装密钥参数**：根据用户选择的币种/路径，取出对应的公钥和派生路径
3. **调用后端 API**：传入 `(mfp, keys[])` 等通用参数

## 3. 实现计划

### Phase 1: 定义后端 UR 生成 API（Rust 层）

**目标**：在 `rust/rust_c/src/wallet/` 中创建通用 UR 生成模块，替代所有钱包专属 FFI 函数。

新增 `rust/rust_c/src/wallet/ur_generators.rs`：

```rust
// 通用 UR 生成 API — 不关心钱包名，只关心 UR 类型

// ur:crypto-account（BTC 专用）
pub fn generate_ur_crypto_account(mfp, keys) → UREncodeResult

// ur:crypto-hd-key（单 HD 密钥）
pub fn generate_ur_crypto_hd_key(mfp, key, path, key_name) → UREncodeResult

// ur:crypto-multi-accounts（多账户多路径）
pub fn generate_ur_crypto_multi_accounts(mfp, keys, device_name) → UREncodeResult

// ur:bytes（原始字节，如 XRP）
pub fn generate_ur_bytes(data, tag) → UREncodeResult

// ur:arweave-crypto-account（AR RSA 密钥）
pub fn generate_ur_arweave_account(mfp, rsa_pubkey) → UREncodeResult

// ur:zcash-accounts（Zcash UFVK）
pub fn generate_ur_zcash_accounts(sfp, ufvk_keys) → UREncodeResult

// JSON text（XMR）
pub fn generate_ur_xmr_json(pub_spend_key, priv_view_key) → UREncodeResult
```

**关键**：这些函数复用已有的 `ur_registry` 类型构造逻辑，但去掉钱包名参数。`generate_ur_crypto_multi_accounts` 内部统一处理 ed25519/secp256k1 路径判断（这部分逻辑在 `backpack.rs` 等文件中重复了 6 次）。

### Phase 2: 统一密钥类型判断逻辑

**问题**：当前每个 `app_wallets` 模块都自己判断密钥类型（ed25519 vs secp256k1），逻辑重复。

**方案**：提取通用的密钥类型判断 + `CryptoHDKey` 构造函数到 `app_wallets/src/common.rs`：

```rust
// 根据路径和密钥长度自动判断类型，构造 CryptoHDKey
pub fn make_crypto_hd_key(mfp, path, key_bytes, key_name) → URResult<CryptoHDKey>

// 判断密钥类型
fn detect_key_type(path, key_bytes) → KeyType  // Ed25519 | Secp256k1 | Secp256k1Xpub
```

这样所有 `generate_crypto_multi_accounts` 实现都可以统一为：
```rust
for key in keys {
    hd_keys.push(make_crypto_hd_key(mfp, key.path, key.key, "Keystone")?);
}
Ok(CryptoMultiAccounts::new(mfp, hd_keys, ...))
```

### Phase 3: 清理 Rust FFI 层

**目标**：删除 `rust_c/src/wallet/multi_coins_wallet/` 下所有钱包专属文件，替换为 Phase 1 的通用 API。

删除：
- `backpack.rs`、`bitget.rs`、`core_wallet.rs`、`keplr.rs`、`keystone_connect.rs`
- `okx.rs`、`thor_wallet.rs`、`tonkeeper.rs`、`xrp_toolkit.rs`
- `arconnect.rs`

保留：
- `mod.rs`（MetaMask 的 ETH 特殊处理暂保留，见 Phase 5）
- `utils.rs`（通用工具函数）
- `structs.rs`（通用结构体）

新增：
- `ur_generators.rs`（Phase 1 的通用 API）

### Phase 4: 清理 app_wallets 层

**目标**：删除 `rust/apps/wallets/src/` 下所有钱包专属模块。

删除：
- `backpack.rs`、`bitget.rs`、`blue_wallet.rs`、`core_wallet.rs`
- `keplr/`、`keystone_connect.rs`、`okx.rs`、`thor_wallet.rs`
- `tonkeeper.rs`、`xrp_toolkit.rs`、`zcash.rs`

保留：
- `common.rs`（通用工具）
- `utils.rs`（`generate_crypto_multi_accounts_sync_ur` 等通用函数）
- `metamask.rs`（ETH 特殊处理，见 Phase 5）

新增：
- `ur_constructors.rs`（统一的 UR 数据结构构造逻辑）

### Phase 5: ETH 特殊处理

**问题**：MetaMask 的 ETH 有三种账户类型（Bip44Standard、LedgerLive、LedgerLegacy），LedgerLive 需要从 master xpub 派生 10 个子账户。

**分析**：这是**密钥派生**逻辑，不是**UR 编码**逻辑。在 Export View Keys 场景下，用户选的是已派生好的密钥，不需要后端做派生。

**方案**：
- Export View Keys：前端直接传入已派生的密钥，后端只做 UR 编码
- Connect Wallet（如未来恢复）：前端负责派生逻辑，或提供 `derive_eth_ledger_live_keys(master_xpub)` 专用 API

**暂不处理**：Phase 5 的 ETH 派生逻辑保留在 `metamask.rs` 中，作为 Export View Keys 不需要的遗留代码。后续如需恢复 connect wallet 功能再清理。

### Phase 6: 清理 C 层 gui_wallet.c

**目标**：删除所有 `GuiGetXxxData()` 函数，前端直接调用通用 UR 生成 API。

删除：
- `GuiGetStandardBtcData()`、`GuiGetCakeData()`、`GuiGetMetamaskData()`
- `GuiGetImTokenData()`、`GuiGetNaboxData()`、`GuiGetCoreWalletData()`
- `GuiGetSolflareData()`、`GuiGetHeliumData()`、`GuiGetXBullData()`
- `GuiGetBackpackData()`、`GuiGetThorWalletData()`
- `GuiGetKeystoneConnectWalletDataBip39()`、`GuiGetKeystoneConnectWalletDataSlip39()`
- `GuiGetFewchaDataByCoin()`、`GuiGetPetraData()`
- `GuiGetIotaWalletData()`、`GuiGetWalletDataByCoin()`
- `GuiGetADADataByIndex()`、`GuiGetKeplrDataByIndex()`
- `GuiGetXrpToolkitDataByIndex()`、`GuiGetBitgetWalletData()`、`GuiGetOkxWalletData()`

保留：
- `BuildChainPaths()`、`BuildSOLAccountKeys()` 等通用工具函数
- `GetMasterFingerPrint()`、`GetCurrentAccountPublicKey()` 等密钥获取函数

### Phase 7: 更新 Export View Keys 前端

**目标**：`gui_export_xpub_widgets.c` 中的 `GenerateExportViewKeys()` 直接调用通用 UR API。

```c
static UREncodeResult *GenerateExportViewKeys(void)
{
    KosmoChainType chain = g_chainList[g_selectedChain].chain;
    uint8_t mfp[4] = {0};
    GetMasterFingerPrint(mfp);

    // 前端根据链类型决定用哪个 UR 生成 API
    switch (chain) {
    case KOSMO_CHAIN_BTC_NATIVE_SEGWIT:
        return generate_ur_crypto_account(mfp, btc_keys);
    case KOSMO_CHAIN_XMR:
        return generate_ur_xmr_json(spend_key, view_key);
    default:
        return generate_ur_crypto_multi_accounts(mfp, keys, "Kosmo");
    }
}
```

## 4. 影响评估

### 4.1 可删除的代码量

| 层级 | 文件 | 预估行数 |
|---|---|---|
| Rust App | `apps/wallets/src/*.rs`（10 个文件） | ~800 行 |
| Rust FFI | `multi_coins_wallet/*.rs`（10 个文件） | ~250 行 |
| C 层 | `gui_wallet.c` 中的 `GuiGetXxxData()` 函数 | ~600 行 |
| **合计** | | **~1,650 行** |

### 4.2 新增的代码量

| 层级 | 文件 | 预估行数 |
|---|---|---|
| Rust App | `ur_constructors.rs`（统一 UR 构造） | ~200 行 |
| Rust FFI | `ur_generators.rs`（通用 FFI API） | ~150 行 |
| C 层 | `gui_ur_api.c/h`（通用 C 包装） | ~100 行 |
| **合计** | | **~450 行** |

**净减少 ~1,200 行代码**。

### 4.3 不受影响的部分

- `gui_animating_qrcode.c` — QR 动画引擎不变
- `kosmo_api.c` — UR 分发逻辑不变（`KOSMO_REQ_UR_GENERATE_QR` 等）
- `ur_parse_lib` — 编解码库不变
- `ur_registry` — UR 类型定义不变
- 签名流程 — 完全不涉及

### 4.4 风险

- **MetaMask LedgerLive 派生**：当前在 `app_wallets` 中做，解耦后需要前端或单独 API 处理。Export View Keys 不需要此功能，暂不处理。
- **Keplr 多链密钥**：Keplr 一次导出 8 条 Cosmos 链的密钥，需要前端组装多密钥参数。不影响后端，但前端需要更多逻辑。
- **Keystone self-connect**：打包 14+ 条链的密钥，需要前端组装大数组。不影响后端。

## 5. 验证标准

1. ARM 编译通过
2. 模拟器编译通过
3. Export View Keys 功能在模拟器中正常工作：
   - BTC → `ur:crypto-account`（动画 QR）
   - ETH → `ur:crypto-hd-key`（动画 QR）
   - SOL → `ur:crypto-multi-accounts`（动画 QR）
   - XMR → JSON text（静态 QR）
4. 签名流程不受影响（签名 UR 编码不在此 plan 范围内）
5. 无钱包名出现在后端代码中（grep 验证）

## 6. 后续工作（不在本 plan 范围内）

- 签名 UR 的解耦（`EthSignRequest`、`SolSignRequest` 等按链划分，已有 Feature Flag，不需要额外解耦）
- MetaMask LedgerLive 派生逻辑的前端迁移
- Connect Wallet 通用版的恢复（基于新的 UR API）

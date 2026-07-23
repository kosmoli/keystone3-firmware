# Plan v11: 签名流程简化重构

## 1. 问题分析

### 1.1 当前签名流程的数据流

```
钱包扫码 → QR 字节
  → ur-parse-lib（后端）解码 UR 类型和数据
  → 前端保存 UR 指针（GuiSetXrpUrData）
  → 前端调用 Rust FFI 解析链特定交易（GuiGetXrpData → xrp_parse_tx）
  → 前端提取 UI 字段（GetXrpDetail、GetAdaFee 等）
  → 前端显示给用户
  → 用户确认
  → 前端构造 KosmoRequest，传回 UR 指针
  → kosmo_api.c 异步执行 ModelSignXrpTx
  → 后端签名
  → 后端 UR 编码
  → 返回签名 UR 给前端
```

**数据在前后端之间来回 5 次**，但其中只有 2 次是必要的（解析展示、签名）。

### 1.2 代码膨胀

| 层 | 文件 | 行数 | 说明 |
|---|---|---|---|
| 前端 | `gui_chain/gui_*.c` | **9,615** | 18 个链特定文件，每条链 7-10 个函数 |
| 中层 | `kosmo_api.c` 签名部分 | **~700** | 31 个 KOSMO_REQ_SIGN case + 37 个 ModelSign 函数 |
| 中层 | `gui_chain.c` 路由 | **184** | 58 个路由条目 |
| 中层 | `gui_analyze_chains.h` UI 布局 | **~5,000** | 硬编码 JSON 定义每个链的 UI |
| **合计** | | **~15,500** | |

### 1.3 每条链的样板代码

以 XRP 为例（167 行），需要实现的函数：

| 函数 | 用途 | 行数 |
|---|---|---|
| `GuiGetXrpPath` | 生成派生路径 | 5 |
| `GuiGetXrpAddressByIndex` | 根据索引生成地址 | 15 |
| `GuiSetXrpUrData` | 保存 UR 指针 | 6 |
| `GuiGetXrpData` | 调用 Rust 解析交易 | 17 |
| `GuiGetXrpCheckResult` | 调用 Rust 检查交易 | 52 |
| `GetXrpDetail` | 提取 UI 字段 | 5 |
| `GetXrpDetailLen` | 字段长度 | 4 |
| `FreeXrpMemory` | 释放内存 | 7 |
| `GuiGetXrpSignQrCodeData` | 触发签名 | 14 |

**9 个函数，167 行代码，其中只有 3 个是真正链特定的**（地址生成、交易解析、签名）。其余 6 个是样板代码（保存 UR 指针、检查、提取字段、释放内存等）。

ADA 为例（1,053 行），函数更多：

| 函数 | 用途 |
|---|---|
| `GuiGetAdaData` | 解析交易 |
| `GuiGetAdaCatalyst` | 解析 Catalyst 投票 |
| `GuiGetAdaSignTxHashData` | 解析 SignTxHash |
| `GuiGetAdaSignDataData` | 解析 SignData |
| `GuiGetAdaCheckResult` | 检查交易 |
| `GuiGetAdaCatalystCheckResult` | 检查 Catalyst |
| `GuiGetAdaSignDataCheckResult` | 检查 SignData |
| `GuiGetAdaSignTxHashCheckResult` | 检查 SignTxHash |
| `GetAdaNetwork/TotalInput/TotalOutput/Fee/...` | 20+ 个 UI 字段提取函数 |
| `GetAdaInputDetail/OutputDetail/...` | 表格数据提取 |
| `FreeAdaMemory/FreeAdaSignDataMemory/...` | 4 个释放函数 |
| `GuiGetAdaSignQrCodeData/...` | 5 个签名触发函数 |
| `GetAdaXPubType/...` | 派生路径管理 |

**50+ 个函数，1,053 行代码**。其中 UI 字段提取函数（`GetAdaNetwork`、`GetAdaFee` 等）应该是通用的，不应该和签名逻辑混在一起。

### 1.4 kosmo_api.c 中的签名样板

```c
// 每个链都重复这个模式：
static int32_t ModelSignXxx(const void *inData, uint32_t inDataLen)
{
    void *urData = *(void **)inData;
    uint8_t seed[SEED_LEN] = {0};
    uint32_t seedLen = 0;
    int32_t ret = KosmoApi_GetSeed(seed, &seedLen);
    if (ret != KOSMO_OK) {
        KosmoApi_NotifyResult(KOSMO_REQ_SIGN_XXX, KOSMO_ERR_GENERAL, NULL, 0);
        return ret;
    }
    int len = KosmoApi_GetMnemonicType() == KOSMO_MNEMONIC_BIP39
              ? sizeof(seed) : KosmoApi_GetEntropyLen();
    UREncodeResult *result = xxx_sign(urData, seed, len);
    memset_s(seed, sizeof(seed), 0, sizeof(seed));
    ClearSecretCache();
    KosmoApi_NotifySignResult(KOSMO_REQ_SIGN_XXX, result);
    return KOSMO_OK;
}
```

31 个签名请求类型，每个一个 case + 一个 ModelSign 函数。虽然有 `ModelSignGeneric` 辅助函数，但仍需 31 个 wrapper。

## 2. 目标架构

### 2.1 简化后的数据流

```
钱包扫码 → QR 字节
  → 前端调用后端 sign_ur_parse(ur_data)
  → 后端内部完成：UR 解析 + 链特定解析 + 生成展示数据
  → 返回 SignDisplayData 给前端
  → 前端显示给用户
  → 用户确认
  → 前端调用后端 sign_ur_execute(ur_data)
  → 后端内部完成：UR 解析 + 签名 + UR 编码
  → 返回签名 UR 给前端
```

**数据在前后端之间只来回 2 次**。

### 2.2 新 API 定义

```c
// ── 展示数据结构 ─────────────────────────────────────

typedef struct {
    char *title;            // "Sign Transaction" / "Sign Message"
    char *chain;            // "XRP" / "ADA" / "ETH" / ...
    char *network;          // "mainnet" / "testnet"
    char *from_address;     // 发送地址
    char *to_address;       // 接收地址
    char *amount;           // 金额
    char *fee;              // 手续费
    char *raw_data;         // 原始数据（JSON 或 hex）
    char *detail;           // 链特定详情（JSON）
    char *warning;          // 警告信息
    uint8_t detail_type;    // 详情类型（0=none, 1=table, 2=raw, 3=custom）
} SignDisplayData;

// ── 后端 API ──────────────────────────────────────────

/**
 * 解析 UR，返回展示数据。
 * @param ur_data     QR 码扫描的原始字节
 * @param ur_len      字节长度
 * @return            展示数据，调用者负责释放
 */
SignDisplayData *sign_ur_parse(const uint8_t *ur_data, uint32_t ur_len);

/**
 * 签名，返回签名 UR。
 * @param ur_data     QR 码扫描的原始字节（需要重新解析）
 * @param ur_len      字节长度
 * @return            签名 UR 编码结果
 */
UREncodeResult *sign_ur_execute(const uint8_t *ur_data, uint32_t ur_len);

/**
 * 释放展示数据。
 */
void sign_display_data_free(SignDisplayData *data);
```

### 2.3 前端简化

```c
// 旧：每条链 7-10 个函数，18 个文件
GuiSetXrpUrData(urResult, urMultiResult, isMulti);
void *data = GuiGetXrpData();
TransactionCheckResult *check = GuiGetXrpCheckResult();
GetXrpDetail(indata, data, maxLen);
GuiGetXrpSignQrCodeData();

// 新：每条链 2 个函数调用
SignDisplayData *display = sign_ur_parse(urData, urLen);
// ... 展示 display->amount, display->fee, display->from_address ...
UREncodeResult *result = sign_ur_execute(urData, urLen);
sign_display_data_free(display);
```

### 2.4 gui_chain.c 路由表简化

```c
// 旧：58 个路由条目
static const ViewHandlerEntry g_viewHandlerMap[] = {
    {BtcNativeSegwitTx, GuiGetBtcSignQrCodeData, GuiGetBtcSignUrDataUnlimited, GuiGetPsbtCheckResult, CHAIN_BTC, REMAPVIEW_BTC},
    // ... 58 条 ...
};

// 新：后端根据 UR 类型自动路由，前端不需要路由表
// 前端只需要：
void GuiSignTransaction(void)
{
    uint8_t *urData = GetScannedUrData();
    uint32_t urLen = GetScannedUrLen();
    SignDisplayData *display = sign_ur_parse(urData, urLen);
    ShowSignConfirmation(display);
    // 用户确认后
    UREncodeResult *result = sign_ur_execute(urData, urLen);
    ShowSignatureQrCode(result);
    sign_display_data_free(display);
}
```

## 3. 实现计划

### Phase 1: 后端 sign_ur_parse/sign_ur_execute 实现

**目标**：在 Rust 层实现统一的签名 API，内部路由到链特定解析。

新增 `rust/rust_c/src/wallet/sign_ur.rs`：

```rust
/// 解析 UR，返回展示数据
#[no_mangle]
pub extern "C" fn sign_ur_parse(
    ur_data: *const u8,
    ur_len: u32,
) -> *mut SignDisplayData {
    let data = unsafe { std::slice::from_raw_parts(ur_data, ur_len as usize) };
    let (ur_type, decoded) = ur_parse_lib::decode(data);
    match ur_type {
        "eth-sign-request" => eth_parse_display(decoded),
        "sol-sign-request" => sol_parse_display(decoded),
        "xrp-sign-request" => xrp_parse_display(decoded),
        // ... 所有链 ...
        _ => error_display("Unsupported UR type"),
    }
}

/// 签名，返回签名 UR
#[no_mangle]
pub extern "C" fn sign_ur_execute(
    ur_data: *const u8,
    ur_len: u32,
    seed: *const u8,
    seed_len: u32,
) -> *mut UREncodeResult {
    let data = unsafe { std::slice::from_raw_parts(ur_data, ur_len as usize) };
    let seed_bytes = unsafe { std::slice::from_raw_parts(seed, seed_len as usize) };
    let (ur_type, decoded) = ur_parse_lib::decode(data);
    match ur_type {
        "eth-sign-request" => eth_sign(decoded, seed_bytes),
        "sol-sign-request" => sol_sign(decoded, seed_bytes),
        "xrp-sign-request" => xrp_sign(decoded, seed_bytes),
        // ... 所有链 ...
        _ => error_result("Unsupported UR type"),
    }
}
```

**关键**：内部复用已有的 `app_wallets` 解析和签名函数，但统一接口。

### Phase 2: kosmo_api.c 简化

**目标**：删除 31 个 KOSMO_REQ_SIGN case 和 37 个 ModelSign 函数，替换为 2 个通用函数。

```c
// 新：ModelSignParse + ModelSignExecute
static int32_t ModelSignParse(const void *inData, uint32_t inDataLen)
{
    SignParseParams *params = (SignParseParams *)inData;
    SignDisplayData *result = sign_ur_parse(params->urData, params->urLen);
    KosmoApi_NotifyResult(KOSMO_REQ_SIGN_PARSE, KOSMO_OK, result, sizeof(*result));
    return KOSMO_OK;
}

static int32_t ModelSignExecute(const void *inData, uint32_t inDataLen)
{
    SignExecuteParams *params = (SignExecuteParams *)inData;
    uint8_t seed[SEED_LEN] = {0};
    uint32_t seedLen = 0;
    int32_t ret = KosmoApi_GetSeed(seed, &seedLen);
    if (ret != KOSMO_OK) {
        KosmoApi_NotifyResult(KOSMO_REQ_SIGN_EXECUTE, KOSMO_ERR_GENERAL, NULL, 0);
        return ret;
    }
    UREncodeResult *result = sign_ur_execute(params->urData, params->urLen, seed, seedLen);
    memset_s(seed, sizeof(seed), 0, sizeof(seed));
    ClearSecretCache();
    KosmoApi_NotifySignResult(KOSMO_REQ_SIGN_EXECUTE, result);
    return KOSMO_OK;
}
```

**删除**：
- 31 个 `case KOSMO_REQ_SIGN_XXX`（约 200 行）
- 37 个 `ModelSignXxx` 函数（约 500 行）
- `ModelSignGeneric` 辅助函数（约 20 行）

**保留**：签名相关的特殊处理（如 BTC multisig、ETH Batch、XMR keyimage 等）需要在 `sign_ur_execute` 内部处理，不暴露给前端。

### Phase 3: 前端 GuiXxx 层删除

**目标**：删除 `gui_chain/gui_*.c` 中所有链特定文件，替换为通用签名调用。

**删除**：
- `gui_xrp.c` (167 行)
- `gui_ada.c` (1,053 行)
- `gui_eth.c` (1,744 行)
- `gui_sol.c` (1,319 行)
- `gui_btc.c` (1,322 行)
- `gui_cosmos.c` (639 行)
- `gui_trx.c` (417 行)
- `gui_ar.c` (363 行)
- `gui_monero.c` (386 行)
- `gui_ton.c` (422 行)
- `gui_avax.c` (242 行)
- `gui_sui.c` (284 行)
- `gui_aptos.c` (107 行)
- `gui_iota.c` (199 行)
- `gui_zcash.c` (324 行)
- `gui_stellar.c` (129 行)

**保留**：
- `gui_chain.c` — 路由表（简化为 2 条：parse、execute）
- `gui_chain_components.c` — 通用 UI 组件

**总计删除：~9,000 行**

### Phase 4: gui_analyze_chains.h UI 布局重构

**目标**：将硬编码 JSON UI 布局改为通用模板，由 `SignDisplayData` 驱动。

```c
// 旧：每个链一个 JSON 布局
"{\"type\":\"container\",\"children\":[
    {\"type\":\"label\",\"text\":\"Network\",\"text_func\":\"GetAdaNetwork\"},
    {\"type\":\"label\",\"text\":\"Fee\",\"text_func\":\"GetAdaFee\"}
]}"

// 新：通用布局，从 SignDisplayData 读取字段
"{\"type\":\"container\",\"children\":[
    {\"type\":\"label\",\"text\":\"Network\",\"field\":\"network\"},
    {\"type\":\"label\",\"text\":\"Amount\",\"field\":\"amount\"},
    {\"type\":\"label\",\"text\":\"Fee\",\"field\":\"fee\"},
    {\"type\":\"label\",\"text\":\"From\",\"field\":\"from_address\"},
    {\"type\":\"label\",\"text\":\"To\",\"field\":\"to_address\"}
]}"
```

**关键**：通用布局 + 链特定 detail JSON，前端渲染引擎解析 `SignDisplayData` 字段。

### Phase 5: 测试与验证

**验证标准**：
1. ARM 编译通过
2. 模拟器编译通过
3. 所有支持的链签名功能正常：
   - BTC (PSBT, Keystone, Unlimited)
   - ETH (Tx, Message, TypedData, Batch, Bytes)
   - SOL (Tx, Message)
   - ADA (Tx, SignData, SignTxHash, Catalyst)
   - XRP (Native, Keystone Bytes)
   - TRX (Tx, Message, Swap)
   - COSMOS (Tx, EvmTx)
   - SUI (Tx, Hash)
   - IOTA (Tx, Hash)
   - APTOS (Tx)
   - AVAX (Tx)
   - ARWEAVE (Tx, Message, DataItem)
   - STELLAR (Tx, Hash)
   - TON (Tx, Proof)
   - ZCASH (Tx)
   - MONERO (Keyimage, Tx)
4. UI 展示正确（金额、地址、手续费等）
5. 签名 QR 码生成正确

## 4. 影响评估

### 4.1 可删除的代码量

| 层 | 文件 | 行数 |
|---|---|---|
| 前端 | `gui_chain/gui_*.c` (16 个文件) | ~9,000 |
| 中层 | `kosmo_api.c` 签名部分 | ~700 |
| 中层 | `gui_analyze_chains.h` JSON 布局 | ~5,000 |
| **合计** | | **~14,700** |

### 4.2 新增的代码量

| 层 | 文件 | 行数 |
|---|---|---|
| Rust | `sign_ur.rs`（统一签名 API） | ~300 |
| C | `gui_sign.c`（通用签名流程） | ~100 |
| C | 通用 UI 布局模板 | ~200 |
| **合计** | | **~600** |

**净减少 ~14,100 行代码**（比 Plan v10 的 2,414 行减少 5.8 倍）。

### 4.3 不受影响的部分

- `ur-parse-lib` — UR 解码库不变
- `app_wallets` — 链特定签名逻辑不变（但会被 `sign_ur.rs` 内部调用）
- `gui_animating_qrcode.c` — QR 动画引擎不变
- `gui_views/` — 页面路由不变
- 签名请求的 Rust FFI 函数 — 保留，但前端不再直接调用

### 4.4 风险

- **UI 布局灵活性**：通用布局可能无法满足所有链的特殊展示需求（如 ADA 的 Withdrawals/Certificates 表格、BTC 的 UTXO 详情）。解决方案：保留 `detail` JSON 字段，特殊布局由前端解析 `detail` 后渲染。
- **解析性能**：`sign_ur_parse` 需要解码 UR + 解析交易，可能比当前的"延迟解析"模式慢。但硬件钱包的 QR 码扫描是瓶颈，解析时间可忽略。
- **复杂链的特殊处理**：某些链有多种签名模式（如 ETH 有 5 种签名变体）。解决方案：`sign_ur_execute` 内部根据 UR 类型自动选择正确的签名函数，不需要前端知道。

## 5. 执行策略

### 5.1 分阶段执行

```
Phase 1: 后端 sign_ur_parse/sign_ur       ← 新增，不影响现有代码
Phase 2: kosmo_api.c 简化                 ← 重构，删除样板
Phase 3: 前端 GuiXxx 层删除               ← 删除，最大代码减少
Phase 4: UI 布局重构                      ← 重构，影响 UI 展示
Phase 5: 测试验证                        ← 功能验证
```

**关键**：Phase 1 新增代码，不影响现有功能；Phase 2-4 删除/重构，需要测试验证。

### 5.2 向后兼容

Plan v11 是破坏性重构，不保持向后兼容。所有签名流程都会改变。

### 5.3 与 Plan v10 的关系

Plan v10 解耦了 Connect Wallet 的后端（按钱包名→按 UR 类型）。Plan v11 解耦了签名流程的前后端（统一签名 API）。两者独立，可以分别执行。

## 6. 预期收益

| 指标 | Plan v10 | Plan v11 |
|---|---|---|
| 删除行数 | 3,484 | ~14,700 |
| 新增行数 | 1,070 | ~600 |
| 净减少 | 2,414 | **~14,100** |
| 文件删除数 | 24 | 16+ |
| 前后端交互次数 | 5→2 | 5→2 |

Plan v11 完成后，整个签名流程将从 ~15,500 行代码简化为 ~600 行，净减少 **14,100 行**（91%）。

## 7. 后续工作（不在本 plan 范围内）

- Connect Wallet 通用版恢复（基于新的签名 API）
- UI 布局引擎优化（从 JSON 布局改为声明式 UI）
- 签名请求的 Rust FFI 函数整合（合并重复的签名变体）
- 测试框架建立（自动化签名测试）

# KOSMO 固件重构 — Plan v5：KosmoApi 统一收编

> 基于 v4 完成状态（Phase 1-5 去耦合完成），目标：**KosmoApi.h 成为 LVGL 开发者与后端之间的唯一接口。**

## 一、最终架构（已完成）

```
LVGL 开发者的世界（唯一允许的依赖：kosmo_api.h + kosmo_types.h + LVGL）
├── View 层（gui_views/）
│   ├── 调度视图切换
│   ├── 处理 view-to-view 信号（GUI_EVENT_REFRESH 等）
│   └── 不 include 任何后端头文件 ✅
│
├── Widget 层（gui_widgets/ + gui_components/）
│   ├── 纯 UI 渲染 + 用户交互
│   ├── 通过 KosmoApi_*() 获取数据、发起请求
│   ├── 通过 callback 接收异步结果
│   └── 后端 include: 0（完全消除） ✅
│
├── KosmoApi.h（唯一接口，89 个函数）
│   ├── 账户/链信息：GetAccountInfo / GetChainList / IsMoneroSupported ...
│   ├── BIP39 + 公钥/地址 + Seed/Entropy：GetBip39Word / GetPublicKey / GetSeed ...
│   ├── 公钥/地址：GetPublicKey / GetPublicKeyByPath / GetPath ...
│   ├── 链操作：ViewTypeToChainTypeSwitch / GetUrGenerator / SignTransaction ...
│   ├── ConnectWallet：GetConnectWalletPathIndex / GetWalletName / GetKeplrData ...
│   ├── SecretCache：CacheGetPassword / CacheSetMnemonic / CacheCleanSecretCache ...
│   └── 通用：GetBip39Word / GetHomeCoinList ...
│
└── KosmoTypes.h（共享类型）
    ├── GuiChainCoinType 枚举（链类型）
    ├── KosmoAccountInfo 结构体
    ├── KosmoMnemonicType 枚举
    ├── KosmoPasswordVerifyResult_t 结构体
    ├── Slip39Data_t / Bip39Data_t / TonData_t / WalletDesc_t 结构体
    ├── ReturnVoidPointerFunc 函数指针类型
    └── 常量宏（KOSMO_BIP39_MAX_WORD_LEN, ADDRESS_MAX_LEN, PATH_ITEM_MAX_LEN, PASSWORD_MAX_LEN 等）

后端世界（对 LVGL 开发者完全不可见）
├── gui_model.c（异步分发 + 15 个 view 级信号路由）
├── gui_chain/（链适配器 + gui_ur_macros.h 工具宏）
├── gui_wallet/（钱包数据）
├── crypto/（密钥推导 + SecretCache）
├── managers/（账户管理 + keystore）
├── account_public_info.c（公钥存储）
└── Rust FFI（链实现）
```

### 依赖关系图

```
                ┌─────────────────────────────────┐
                │         LVGL (UI 框架)            │
                └──────────┬──────────────────────┘
                           │
                ┌──────────▼──────────────────────┐
                │     View 层 (gui_views/)          │
                │  · 调度视图切换                     │
                │  · 处理 view-to-view 信号           │
                │  · 依赖: LVGL + gui_views.h        │
                └──────────┬──────────────────────┘
                           │ 信号 (SIG_*)
                ┌──────────▼──────────────────────┐
                │   Widget 层 (gui_widgets/ +       │
                │              gui_components/)     │
                │  · 纯 UI 渲染 + 用户交互            │
                │  · 依赖: kosmo_api.h +             │
                │    kosmo_types.h + LVGL           │
                │  · 后端 include: 0 (完全消除)     │
                └──────┬───────────────┬──────────┘
                       │               │
          KosmoApi_*() │               │ GuiEmitSignal
                       │               │ (view-to-view)
                ┌──────▼───────────────▼──────────┐
                │         KosmoApi (api/)           │
                │  · 89 个函数                      │
                │  · 同步查询 + 异步请求              │
                │  · SecretCache + Rust FFI 包装     │
                └──────────┬──────────────────────┘
                           │
        ┌──────────────────┼──────────────────────┐
        │                  │                      │
┌───────▼──────┐  ┌───────▼──────┐  ┌────────────▼────┐
│ gui_model.c   │  │ gui_chain/    │  │ managers/        │
│ (异步分发)     │  │ (链适配器)     │  │ (账户+keystore)   │
│ 15 个 view    │  │ UR 编码       │  │ SecretCache      │
│ 级信号路由    │  │ 地址生成       │  │ 密码/助记词缓存   │
└──────────────┘  └───────┬──────┘  └─────────────────┘
                          │
                ┌─────────▼────────────┐
                │   Rust FFI (rust.h)    │
                │   · 链签名              │
                │   · UR 编解码           │
                │   · 密钥推导            │
                └──────────────────────┘
```

### KosmoApi 接口分类（89 个函数）

| 类别 | 数量 | 函数 |
|---|---|---|
| 基础设施 | 3 | `Init`, `Request`, `NotifyResult` |
| 账户/链信息 | 4 | `GetAccountInfo`, `GetChainList`, `IsMoneroSupported`, `IsZcashSupported` |
| BIP39 | 3 | `GetBip39Word`, `ValidateWord`, `Bip39MnemonicFromBytes` |
| 公钥/地址 | 4 | `GetPublicKey`, `GetPublicKeyByPath`, `GetPublicKeyRaw`, `GetPath` |
| Seed/Entropy | 5 | `GetSeed`, `GetMnemonicType`, `GetSeedLen`, `GetEntropyLen`, `GetPassphrase` |
| 账户管理 | 5 | `GetCurrentAccountIndex`, `GetAccountCount`, `GetExistAccountNum`, `GetIsTempAccount`, `GetPassphraseQuickAccess` |
| 链索引管理 | 6 | `GetAccountReceiveIndex/Set`, `GetAccountReceivePath/Set`, `GetAccountIndex/Set` |
| 链操作/UR | 7 | `ViewTypeToChainTypeSwitch`, `GetUrGenerator`, `GetSingleUrGenerator`, `IsMessageType`, `IsTonSignProof`, `IsCatalystVotingRegistration`, `GetAdaXPubType` |
| ConnectWallet | 15 | `GetConnectWalletPathIndex/Set`, `GetConnectWalletAccountIndex/Set`, `GetConnectWalletNetwork/Set`, `GetWalletName`, `GetWalletNameByIndex`, `GetXrpAddressByIndex`, `GetAdaBaseAddressByXPub`, `GetKeplrData`, `GetAdaData`, `GetXrpToolkitData`, `GetTonkeeperWalletUr`, `GetFewchaData` |
| SecretCache | 17 | `CacheGetPassword/Set`, `CacheGetMnemonic/Set`, `CacheSetPassphrase`, `CacheGetChecksum`, `CacheSetWalletIndex/Name`, `CacheGetNewPassword/Set`, `CacheGetDiceRollsLen`, `CacheSetEntropy`, `CacheCleanSecretCache`, `CacheSetSlip39Mnemonic/Get`, `CacheSetDiceRollHash`, `CacheSetDiceRollsLen` |
| Rust FFI 包装 | 8 | `EthSignBatchTx`, `FreeSimpleResponseCChar`, `FreeUrEncodeResult`, `FreeUrParseMultiResult`, `FreeUrParseResult`, `ParseDeriveContextHash`, `ParseQrHardwareCall`, `CardanoGetAddress` |
| 状态/杂项 | 7 | `GetAccountSeed`, `GetAccountEntropy`, `GetFirstReceive/Set`, `AccountPublicHomeCoinGet`, `CheckSolPathSupport`, `GetHomeCoinList`, `GetZcashSFP`, `GetZcashUFVK` |
| **宏** | **3** | `KOSMO_API_REQUEST_WALLET`, `KOSMO_API_REQUEST_DEVICE`, `KOSMO_API_REQUEST_ACCOUNT` |
| **总计** | **89+3** | |

---

## 二、原始泄漏审计（v5 开始时）

### 2.1 Widget 层泄漏（完整审计）

| 泄漏类型 | 文件数 | 调用次数 | 来源头文件 |
|---|---|---|---|
| `GetCurrentAccountIndex()` | 19 | **118** | account_manager.h |
| `GetCoinCardByIndex()` | 8 | ~30 | account_public_info.h |
| ConnectWallet 状态管理 | 1 | ~50 | gui_chain.h |
| `GetConnectWalletPathIndex` | 3 | ~25 | gui_chain.h |
| `GetAdaXPubType*` | 2 | ~20 | gui_chain.h |
| `GetMnemonicType()` | 10 | 15+ | keystore.h（经 gui_model.h） |
| `bip39_mnemonic_validate()` | 6 | ~20 | bip39.h |
| `GetAccountSeed/Entropy/Passphrase` | 2 | ~10 | account_manager.h |
| 地址生成函数 | 3 | ~12 | gui_chain.h |
| `GetCurrentAccountEntropyLen()` | 3 | 3 | keystore.h |
| `GetAccountIndex()` / `SetAccountIndex()` | 1 | 3 | account_manager.h |
| `GuiChainCoinType` 类型 | 8 | ~15 | gui_chain.h |
| `rust.h` FFI 直接 include | 4 | — | rust_c/rust.h |
| `gui_model.h` include | 22 | — | gui_model.h |
| 死 include（include 但未使用） | ~15 | 0 | 各种 |

---

## 三、执行记录

### Phase 6：清理死 include ✅

**已完成**：
- gui_lock_view.c：删除 `keystore.h` + `account_manager.h`（死 include）
- 3 个文件添加 `kosmo_api.h`（gui_seed_check_widgets.c、gui_fingerprint_widgets.c、gui_init_view.c）

---

### Phase 7：KosmoApi 扩展 — Account + Wallet 层包装 ✅

**已完成**：

**7.1 新增 KosmoApi getter（8 个）**
- `KosmoApi_GetAccountReceiveIndex/SetAccountReceiveIndex`
- `KosmoApi_GetAccountReceivePath/SetAccountReceivePath`
- `KosmoApi_GetAccountIndex/SetAccountIndex`（链名参数版本）
- `KosmoApi_GetAccountSeed/GetAccountEntropy/GetPassphrase`

**7.2 GetCurrentAccountIndex 迁移**
- 94 处替换，19 个 widget 文件 + 1 个 view 文件
- 添加 `kosmo_api.h` 到 3 个缺少的文件

**7.3 GetMnemonicType 迁移**
- `GetMnemonicType()` → `KosmoApi_GetMnemonicType()`（9 文件）
- `MNEMONIC_TYPE_*` → `KOSMO_MNEMONIC_*`（全局替换）
- `MnemonicType` → `KosmoMnemonicType`（3 文件）
- `GetCurrentAccountEntropyLen()` → `KosmoApi_GetEntropyLen()`（3 文件）

**7.4 后端函数迁移**
- `GetAccountSeed` → `KosmoApi_GetAccountSeed`（3 文件）
- `GetAccountEntropy` → `KosmoApi_GetAccountEntropy`（1 文件）
- `GetPassphrase` → `KosmoApi_GetPassphrase`（1 文件）
- `GetAccountIndex/SetAccountIndex` → `KosmoApi_*`（1 文件）
- `GetAccountReceiveIndex/Path` → `KosmoApi_*`（4 文件）

---

### Phase 8：KosmoApi 扩展 — ConnectWallet 状态管理 ✅

**已完成**：

**8.1 新增 KosmoApi ConnectWallet 接口（15 个函数）**
- `KosmoApi_GetConnectWalletPathIndex/SetConnectWalletPathIndex`
- `KosmoApi_GetConnectWalletAccountIndex/SetConnectWalletAccountIndex`
- `KosmoApi_GetConnectWalletNetwork/SetConnectWalletNetwork`
- `KosmoApi_GetWalletName/GetWalletNameByIndex`
- `KosmoApi_GetXrpAddressByIndex/GetAdaBaseAddressByXPub/GetKeplrDataByIndex/GetAdaDataByIndex/GetXrpToolkitDataByIndex`
- `KosmoApi_GetTonkeeperWalletUr/GetFewchaData`

**8.2 Widget 迁移**
- 53 个后端调用 → `KosmoApi_*`
- `gui_chain.h` → `kosmo_api.h`
- `GuiChainCoinType` 依赖消除（Fewcha 改用 `bool isSui`）
- 5 个死 include 清理（gui_general_home_widgets.c 等）

---

### Phase 9：KosmoApi 扩展 — 链操作包装 ✅

**已完成**：

**9.1 GuiChainCoinType 迁移**
- 枚举从 `gui_chain.h` 迁移到 `kosmo_types.h`
- `gui_chain.h` 新增 `#include "kosmo_types.h"`（向后兼容）

**9.2 新增 KosmoApi 链操作函数（7 个）**
- `KosmoApi_ViewTypeToChainTypeSwitch`
- `KosmoApi_GetUrGenerator / GetSingleUrGenerator`
- `KosmoApi_IsMessageType / IsTonSignProof / IsCatalystVotingRegistration`
- `KosmoApi_GetAdaXPubType`

**9.3 Widget 迁移**
- 7 个文件 `gui_chain.h` → `kosmo_api.h`
- gui_status_bar.c/h: `gui_chain.h` → `kosmo_types.h`

---

### Phase 10：BIP39 完全归零 ✅

**已完成**：
- `bip39_mnemonic_validate` → `KosmoApi_Bip39MnemonicValidate`（6 个 widget 文件）
- `BIP39_MAX_WORD_LEN` → `KOSMO_BIP39_MAX_WORD_LEN`（2 个文件）
- `bip39.h` 在 widget 层归零

---

### Phase 11：Model 层信号残留 ✅

**结论**：gui_model.c 中的 21 个信号全部是 **view 级 UI 路由信号**（密码验证路由、RSA 进度、Passphrase 流程、公钥检查），不携带后端数据，全部保留。

---

### Phase 12：Widget 层 GuiEmitSignal ✅

**结论**：widget 中的 10 个 `GuiEmitSignal` 全部是 **view-to-view 或 widget-to-view 通信**，不是后端泄漏。全部保留。

---

### Phase 13：最终验证 + 死 include 清理 ✅

**已完成**：编译零 error，模拟器启动正常。死 include 清理完成。

---

### Phase 14：SecretCache + 小函数包装 ✅

**已完成**：

**14.1 SecretCache 包装（17 个函数）**
- `KosmoApi_CacheGetPassword/SetPassword/GetMnemonic/SetMnemonic/SetPassphrase`
- `KosmoApi_CacheGetChecksum/SetWalletIndex/SetWalletName/GetNewPassword/SetNewPassword`
- `KosmoApi_CacheGetDiceRollsLen`
- `KosmoApi_CacheSetEntropy/CleanSecretCache`
- `KosmoApi_CacheSetSlip39Mnemonic/GetSlip39Mnemonic`
- `KosmoApi_CacheSetDiceRollHash/SetDiceRollsLen`

**14.2 小函数包装（6 个）**
- `KosmoApi_GetExistAccountNum/GetPassphraseQuickAccess`
- `KosmoApi_GetIsTempAccount/GetFirstReceive/SetFirstReceive/AccountPublicHomeCoinGet`

**14.3 Widget 迁移**
- SecretCache*: ~50 处 → 0（widget 层完全清零）
- 其他小函数: ~15 处 → 0
- 死 include 清理: 21 个文件

---

### Phase 15：gui_model.h 类型迁移 ✅

**已完成**：
- `PasswordVerifyResult_t` → `KosmoPasswordVerifyResult_t`（已在 `kosmo_types.h` 中）
- `gui_keyboard_hintbox.c/.h`：删除死 include `gui_model.h`
- `gui_model.h` 在 widget 层归零

---

### Phase 16：gui_chain.h + gui_model.h 最终归零 ✅

**已完成**：
- `gui_keyboard_hintbox.c/.h`：删除死 include `gui_model.h`（`KosmoPasswordVerifyResult_t` 已在 `kosmo_types.h`）
- 创建 `gui_ur_macros.h`：从 `gui_chain.h` 提取 `CHECK_CHAIN_BREAK`/`CHECK_CHAIN_RETURN`/`CHECK_FREE_UR_RESULT` 宏
- 3 个 widget 文件 `gui_chain.h` → `gui_ur_macros.h`
- `gui_chain.h` 在 widget 层归零

---

### Phase 17：Rust FFI 包装 ✅

**已完成**：
- 新增 7 个 KosmoApi 包装函数：`EthSignBatchTx`, `FreeSimpleResponseCChar`, `FreeUrEncodeResult`, `FreeUrParseMultiResult`, `FreeUrParseResult`, `ParseDeriveContextHash`, `ParseQrHardwareCall`
- `gui_eth_batch_tx_widgets.c/.h`：删除 `rust.h`，14 处 Rust 调用 → KosmoApi
- `gui_animating_qrcode.h`：改用前向声明 `UREncodeResult` 替代 `#include "rust.h"`
- Widget+Component 层 rust.h: **3→0（完全清零）**

---

### Phase 18：构建修复 + 类型迁移 ✅

**背景**：Phase 15-16 的类型迁移过程中，`gui_model.h` 被过度清理导致全量构建失败。

**修复内容**：
- `gui_model.h`：恢复 37 个 `GuiModel*`/`GuiMode*` 函数声明（被误删）
- `gui_model.h`：补上缺失的 `#endif` 守卫 + 添加 `#include "rust.h"`
- `kosmo_types.h`：删除第 299 行多余的 `#endif`（导致迁移的类型在守卫外）
- `kosmo_types.h`：添加 `MAX_LOGIN_PASSWORD_ERROR_COUNT`
- `gui_model.c`：添加 `ModelGetPassphraseQuickAccess` 和 `RsaGenerateKeyPair` 前向声明
- `gui_scan_widgets.h`：修复 `GuiTransactionCheckFailed` 类型不匹配
- Simulator 构建：**0 error，二进制正常生成**

---

### Phase 19：Cardano 地址包装 + 最终清理 ✅

**已完成**：
- 新增 `KosmoApi_CardanoGetAddress()`：包装 `cardano_get_*_address`，隐藏 `SimpleResponse_c_char`
- `gui_change_path_type_widgets.c`：删除 `#include "rust.h"`，`ModelGetADAAddress` 改用 KosmoApi 包装
- `ADDRESS_MAX_LEN` / `PATH_ITEM_MAX_LEN` 宏从 `rust.h` 迁移到 `kosmo_types.h`
- Widget+Component 层后端 include：**确认 0**（全文搜索验证）
- KosmoApi 函数总数：**89 个**

---

## 四、最终状态

| 指标 | v5 开始 | 最终 | 变化 |
|---|---|---|---|
| **Widget 后端 include 总数** | **153** | **0** | **-100%** |
| `account_manager.h` | 21 | **0** ✅ | 完全消除 |
| `keystore.h` | 26 | **0** ✅ | 完全消除 |
| `secret_cache.h` | 26 | **0** ✅ | 完全消除 |
| `gui_model.h` | 22 | **0** ✅ | 完全消除 |
| `gui_chain.h` | 16 | **0** ✅ | 完全消除 |
| `account_public_info.h` | 11 | **0** ✅ | 完全消除 |
| `bip39.h` | 6 | **0** ✅ | 完全消除 |
| `rust.h` | 5 | **0** ✅ | 完全消除 |
| KosmoApi 函数总数 | 39 | **89** | +50 |
| LVGL 开发者需要知道的后端概念 | chain/wallet/keystore/account/rust | **0** | |

### kosmo_types.h 最终内容

从 `gui_model.h` / `rust.h` 迁移的类型和宏，使 widget 层无需任何后端头文件：
- 结构体：`Slip39Data_t`, `Bip39Data_t`, `TonData_t`, `WalletDesc_t`
- 函数指针：`ReturnVoidPointerFunc`
- 宏：`ADDRESS_MAX_LEN`, `PATH_ITEM_MAX_LEN`, `PASSWORD_MAX_LEN`, `MAX_LOGIN_PASSWORD_ERROR_COUNT`, `WALLET_NAME_MAX_LEN`

---

## 五、预估工时

| Phase | 预估 | 实际 | 备注 |
|---|---|---|---|
| 6 | 0.5h | ✅ 0.5h | 死 include 清理 |
| 7 | 2h | ✅ 2h | Account/Wallet 层包装（130+ 处迁移） |
| 8 | 2-3h | ✅ 2h | ConnectWallet 重构（53 个调用迁移，15 个新函数） |
| 9 | 1-2h | ✅ 1h | 链操作包装 + GuiChainCoinType 迁移 |
| 10 | 1h | ✅ 0.5h | BIP39 完全归零 |
| 11 | 0.5h | ✅ 0.1h | 全部保留为 view 信号 |
| 12 | 0h | ✅ 0h | 全部保留 |
| 13 | 0.5h | ✅ 0.5h | 最终验证 + 死 include 清理 |
| 14 | 1.5h | ✅ 2h | SecretCache 全面包装（17 个函数） |
| 15 | 0.5h | ✅ 0.5h | gui_model.h 类型迁移 |
| 16 | — | ✅ 0.5h | gui_chain.h + gui_model.h 最终归零 |
| 17 | — | ✅ 1h | Rust FFI 包装（7 函数，rust.h 完全清零） |
| 18 | — | ✅ 1.5h | 构建修复（类型迁移善后，37 函数声明恢复） |
| 19 | — | ✅ 0.5h | Cardano 地址包装 + 宏迁移 |
| **总计** | **10-14h** | **~15h** | **全部完成** |

---

## 六、风险评估

| Phase | 风险 | 缓解措施 |
|---|---|---|
| 6（死 include） | 极低 | 编译验证即可 |
| 7（Wallet 包装） | 低 | 纯包装，不改逻辑 |
| 8（ConnectWallet） | **中高** | 最复杂的单文件，~50 个调用需逐个替换 |
| 9（链操作） | 中 | 地址生成函数签名差异大 |
| 10（BIP39） | 低 | 单文件，逻辑简单 |
| 11（信号残留） | 无 | 全部保留 |
| 14（SecretCache） | 低 | 敏感操作，但包装不改变安全属性 |
| 16（宏提取） | 低 | 宏是纯文本替换，移到新头文件即可 |
| 17（Rust FFI） | 低 | 纯包装，前向声明替代 include |
| 18（构建修复） | **中** | 类型迁移级联影响，需逐个修复编译错误 |
| 19（Cardano） | 低 | 单函数包装，逻辑简单 |

---

## 七、执行顺序（回顾）

```
Phase 6 ✅（死 include 清理）
  ↓
Phase 7 ✅（Account/Wallet 层包装 — 最大面泄漏已解决）
  ↓
Phase 8 ✅（ConnectWallet 重构 — 最难的单点，53 个调用迁移）
  ↓
Phase 9 ✅（链操作包装 — gui_chain.h: 16→3）
  ↓
Phase 10 ✅（BIP39 完全归零）
  ↓
Phase 11 ✅（信号残留 — 全部保留为 view 信号）
Phase 12 ✅（Widget 信号 — 全部保留）
Phase 13 ✅（最终验证 + 死 include 清理）
  ↓
Phase 14 ✅（SecretCache 全面包装 — 17 个函数）
  ↓
Phase 15 ✅（gui_model.h 类型迁移）
  ↓
Phase 16 ✅（gui_chain.h 归零 — 153→3）
  ↓
Phase 17 ✅（Rust FFI 包装 — rust.h 完全清零）
  ↓
Phase 18 ✅（构建修复 — 类型迁移善后）
  ↓
Phase 19 ✅（Cardano 包装 — 最后一个 rust.h 残留消除）
  ↓ 完成
```

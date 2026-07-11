# KOSMO 固件重构 — Plan v5：KosmoApi 统一收编

> 基于 v4 完成状态（Phase 1-5 去耦合完成），目标：**KosmoApi.h 成为 LVGL 开发者与后端之间的唯一接口。**

## 一、目标架构

```
LVGL 开发者的世界（唯一允许的依赖：kosmo_api.h + kosmo_types.h + LVGL）
├── View 层（gui_views/）
│   ├── 调度视图切换
│   ├── 处理 view-to-view 信号（GUI_EVENT_REFRESH 等）
│   └── 不 include 任何后端头文件
│
├── Widget 层（gui_widgets/）
│   ├── 纯 UI 渲染 + 用户交互
│   ├── 通过 KosmoApi_*() 获取数据、发起请求
│   ├── 通过 callback 接收异步结果
│   └── 不 include 任何后端头文件
│
└── KosmoApi.h（唯一接口）
    ├── 同步查询：GetAccountInfo / GetPublicKey / GetSeed / GetMnemonicType ...
    ├── 异步请求：Request(enum, data, callback) → 39+ 种请求类型
    └── 链操作：GetAddress / GetPath / EncodeUR / DecodeUR ...

后端世界（对 LVGL 开发者完全不可见）
├── gui_model.c（异步分发）
├── gui_chain/（链适配器）
├── gui_wallet/（钱包数据）
├── crypto/（密钥推导）
├── managers/（账户管理）
├── account_public_info.c（公钥存储）
└── Rust FFI（链实现）
```

## 二、当前泄漏审计

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

### 2.2 View 层泄漏

| 文件 | include | 实际使用 |
|---|---|---|
| gui_lock_view.c | keystore.h + account_manager.h | **未使用（死 include）** |
| gui_init_view.c | account_manager.h | **未使用（死 include）** |
| gui_transaction_detail_view.c | gui_chain.h | **未使用（死 include）** |

### 2.3 Model 层泄漏

| 泄漏 | 数量 | 说明 |
|---|---|---|
| `GuiApiEmitSignal` 残留 | 15 | 密码验证路由(8) + RSA(5) + 杂项(2) |

### 2.4 泄漏分类总结

| 类别 | 文件数 | 说明 |
|---|---|---|
| **A. 死 include（直接删除）** | ~17 | include 了但没用到 |
| **B. 需要 KosmoApi 包装的函数** | ~15 | GetMnemonicType、ConnectWallet 状态、地址生成等 |
| **C. 需要重构的重泄漏** | 1 | gui_connect_wallet_widgets.c（~50 个后端调用） |
| **D. Model 层信号残留** | 15 个信号 | 需要转为 NotifyResult 或保留为 view 信号 |

## 三、执行计划

### Phase 6：清理死 include（低风险，快速收益）

**目标**：删除所有未使用的后端 include，缩小泄漏范围。

**6.1 Widget 层死 include 清理**

以下 widget 文件 include 了 `account_public_info.h` 但未使用任何符号：
- gui_general_home_widgets.c
- gui_export_pubkey_widgets.c
- gui_derive_context_hash_request_widgets.c
- gui_multi_path_coin_receive_widgets.c
- gui_standard_receive_widgets.c
- gui_key_derivation_request_widgets.c
- gui_change_path_type_widgets.c
- gui_multi_accounts_receive_widgets.c
- gui_select_address_widgets.c
- gui_utxo_receive_widgets.c
- gui_connect_wallet_widgets.c（需确认，可能有间接依赖）

以下 widget 文件 include 了 `gui_model.h` 但仅用类型定义（应改为 include kosmo_types.h 或在 kosmo_api.h 中暴露类型）：
- 需逐个确认，约 8-12 个文件

**6.2 View 层死 include 清理**

直接删除：
- gui_lock_view.c: 删除 `#include "keystore.h"` + `#include "account_manager.h"`
- gui_init_view.c: 删除 `#include "account_manager.h"`
- gui_transaction_detail_view.c: 删除 `#include "gui_chain.h"`

**6.3 验证**：编译零 error，模拟器启动。

---

### Phase 7：KosmoApi 扩展 — Account + Wallet 层包装

**目标**：将 account_manager.h / keystore.h / account_public_info.h 中 widget 需要的函数收编到 KosmoApi。

这是**最大的面泄漏**——`GetCurrentAccountIndex()` 有 118 个引用分布在 19 个 widget 文件中。

**7.1 新增 KosmoApi getter 函数**

```c
// kosmo_api.h 新增

// === 账户索引（最高优先级，118 个引用）===
uint32_t KosmoApi_GetCurrentAccountIndex(void);

// === 链卡片数据（~30 个引用）===
const CoinCard_t *KosmoApi_GetCoinCardByIndex(uint32_t index);

// === 账户接收路径（多文件使用）===
const char *KosmoApi_GetAccountReceivePath(KosmoChainType chain);
uint32_t KosmoApi_GetAccountReceiveIndex(KosmoChainType chain);
void KosmoApi_SetAccountReceivePath(KosmoChainType chain, const char *path);
void KosmoApi_SetAccountReceiveIndex(KosmoChainType chain, uint32_t index);

// === 种子/熵/密码（gui_key_derivation + gui_derive_context_hash）===
const uint8_t *KosmoApi_GetAccountSeed(void);
const uint8_t *KosmoApi_GetAccountEntropy(void);
uint32_t KosmoApi_GetAccountEntropyLen(void);
const char *KosmoApi_GetPassphrase(void);

// === 助记词类型===
MnemonicType KosmoApi_GetMnemonicType(void);
bool KosmoApi_IsSlip39(void);
bool KosmoApi_IsTonMnemonic(void);

// === 账户信息===
uint32_t KosmoApi_GetAccountIndex(KosmoChainType chain);
uint32_t KosmoApi_GetAccountCount(void);

// === 钱包状态===
bool KosmoApi_IsWalletCreated(void);

// === Zcash 特定===
const char *KosmoApi_GetZcashUFVK(void);
```

实现：在 `kosmo_api.c` 中包装对应的 keystore/account_manager/account_public_info 函数。

**7.2 Widget 迁移（按引用数排序）**

| 优先级 | 函数 | 引用数 | 文件数 | 迁移方式 |
|---|---|---|---|---|
| P0 | `GetCurrentAccountIndex()` | 118 | 19 | 全局替换为 `KosmoApi_GetCurrentAccountIndex()` |
| P1 | `GetCoinCardByIndex()` | ~30 | 8 | 全局替换为 `KosmoApi_GetCoinCardByIndex()` |
| P2 | `GetMnemonicType()` | 15+ | 10 | 全局替换为 `KosmoApi_GetMnemonicType()` |
| P3 | `GetAccountSeed/Entropy/Passphrase` | ~10 | 2 | 逐个替换 |
| P4 | `GetCurrentAccountEntropyLen()` | 3 | 3 | 逐个替换 |
| P5 | `GetAccountIndex/SetAccountIndex` | 3 | 1 | 逐个替换 |

移除这些文件对 `keystore.h`、`account_manager.h`、`account_public_info.h` 的 include。

**7.3 验证**：编译零 error，模拟器启动。

---

### Phase 8：KosmoApi 扩展 — ConnectWallet 状态管理

**目标**：将 `gui_connect_wallet_widgets.c` 的 ~50 个后端调用收编到 KosmoApi。

这是最复杂的单文件迁移。`gui_connect_wallet_widgets.c` 直接调用了：
- `GetConnectWalletPathIndex()` / `SetConnectWalletPathIndex()`
- `GetConnectWalletAccountIndex()` / `SetConnectWalletAccountIndex()`
- `GetConnectWalletNetwork()` / `SetConnectWalletNetwork()`
- `GetWalletNameByIndex()`
- `GetAdaXPubTypeByIndexAndDerivationType()`
- `GetConnectWalletAccountIndex()`
- `GuiGetXrpAddressByIndex()`
- `GuiGetADABaseAddressByXPub()`
- `GuiGetKeplrDataByIndex()`
- `GuiGetADADataByIndex()`
- `get_tonkeeper_wallet_ur()`
- `GetWalletName()`
- `GetMnemonicType()`

**8.1 新增 KosmoApi ConnectWallet 接口**

```c
// kosmo_api.h 新增

// ConnectWallet 状态（读写）
uint8_t KosmoApi_GetConnectWalletPathIndex(const char *walletName);
void KosmoApi_SetConnectWalletPathIndex(const char *walletName, uint8_t index);
uint8_t KosmoApi_GetConnectWalletAccountIndex(const char *walletName);
void KosmoApi_SetConnectWalletAccountIndex(const char *walletName, uint8_t index);
uint8_t KosmoApi_GetConnectWalletNetwork(const char *walletName);
void KosmoApi_SetConnectWalletNetwork(const char *walletName, uint8_t network);

// 钱包名称
const char *KosmoApi_GetWalletName(void);
const char *KosmoApi_GetWalletNameByIndex(uint8_t index);

// 链特定地址生成（同步，用于显示）
const char *KosmoApi_GetXrpAddressByIndex(uint8_t index);
const char *KosmoApi_GetAdaBaseAddressByXPub(const char *xpub);

// UR 编码（同步，用于 QR 码显示）
UREncodeResult *KosmoApi_GetKeplrDataByIndex(uint8_t accountIndex);
UREncodeResult *KosmoApi_GetAdaDataByIndex(const char *walletName);
UREncodeResult *KosmoApi_GetTonkeeperWalletUr(...);

// ADA 特定
AdaXPubType KosmoApi_GetAdaXPubTypeByIndexAndDerivationType(uint8_t pathIndex, uint8_t derivationType);
```

**8.2 Widget 迁移**

`gui_connect_wallet_widgets.c`：将所有后端调用替换为 `KosmoApi_*` 调用。
移除对 `gui_chain.h`、`account_public_info.h`、`gui_wallet.h` 的 include。

**8.3 验证**：编译零 error，模拟器启动。

---

### Phase 9：KosmoApi 扩展 — 链操作包装

**目标**：将 gui_chain.h 中 widget 需要的地址生成函数收编到 KosmoApi。

**9.1 地址生成包装**

```c
// kosmo_api.h 新增

// 通用地址生成
bool KosmoApi_GetAddress(KosmoChainType chain, uint32_t index, char *out, size_t outLen);

// 链特定（保留，因为不同链的地址格式差异大）
const char *KosmoApi_GetXrpAddressByIndex(uint8_t index);
const char *KosmoApi_GetAdaBaseAddressByXPub(const char *xpub);
const char *KosmoApi_GetUtxoAddress(uint32_t pathType, uint32_t index);
```

**9.2 Widget 迁移**

3 个文件的地址生成调用 → `KosmoApi_*` 调用：
- gui_select_address_widgets.c
- gui_connect_wallet_widgets.c（Phase 8 已处理部分）
- gui_export_pubkey_widgets.c

**9.3 验证**：编译零 error，模拟器启动。

---

### Phase 10：BIP39 词表 + AsyncExecute + Rust FFI 清理

**10.1 BIP39 词表包装**

6 个 widget 文件直接调用 `bip39_mnemonic_validate()`：
- gui_import_phrase_widgets.c
- gui_forget_pass_widgets.c
- gui_single_phrase_widgets.c（13 处引用）
- gui_namewallet_widgets.c
- gui_passphrase_setting_widgets.c
- gui_key_derivation_request_widgets.c（`bip39_mnemonic_from_bytes()`）

方案：在 `kosmo_api.h` 中新增：
```c
bool KosmoApi_ValidateBip39Mnemonic(const char *mnemonic);
int KosmoApi_Bip39MnemonicFromBytes(const uint8_t *bytes, int bytesLen, char *mnemonic, int mnemonicLen);
```

**10.2 AsyncExecute 清理**

`gui_lock_widgets.c` 中 1 处直接 `AsyncExecute()` 调用 → 改为 `KosmoApi_Request()`。

**10.3 Rust FFI 清理**

4 个 widget 文件直接 include `rust.h`：
- gui_scan_widgets.h
- gui_eth_batch_tx_widgets.h/.c
- gui_connect_wallet_widgets.c

方案：将这些 widget 需要的 Rust 函数包装到 KosmoApi 中，移除对 `rust.h` 的直接 include。

**10.4 验证**：编译零 error，模拟器启动。

---

### Phase 11：Model 层信号残留处理

**目标**：处理 gui_model.c 中剩余的 15 个 `GuiApiEmitSignal` 调用。

**11.1 分类**

| 类别 | 数量 | 信号 | 处理方案 |
|---|---|---|---|
| 密码验证路由 | 8 | SIG_VERIFY_PASSWORD_PASS 等 | **保留为 view 信号**（view 级 UI 路由，不是后端事件） |
| RSA 进度 | 5 | SIG_SETUP_RSA_* | **保留为 view 信号**（RSA 是 UI-only 特性） |
| Passphrase | 1 | SIG_SETTING_WRITE_PASSPHRASE_* | **转为 NotifyResult callback** |
| 公钥不匹配 | 1 | SIG_EXTENDED_PUBLIC_KEY_NOT_MATCH | **转为 NotifyResult callback** |

**11.2 Passphrase + 公钥不匹配迁移**

将 passphrase 写入和公钥检查的信号转为 `KosmoApi_NotifyResult` callback。

**11.3 保留的 13 个 view 信号**

密码验证路由(8) + RSA(5) = 13 个信号是 **view 级 UI 路由事件**，不是后端泄漏。它们的特征：
- 由 view 层的 switch/case 消费
- 控制 UI 状态切换（显示密码键盘、显示 RSA 进度条）
- 不携带后端数据，只携带 UI 路由参数

这些信号**保留在 gui_views.h** 中，标记为 `// View-level UI routing signals`。

**11.4 验证**：编译零 error，模拟器启动。

---

### Phase 12：Widget 层 GuiEmitSignal 清理

**目标**：处理 widget 中的 10 个 `GuiEmitSignal` 调用。

**12.1 分类**

| 信号 | 文件 | 说明 | 处理方案 |
|---|---|---|---|
| `SIG_SETUP_VIEW_TILE_NEXT` | gui_create_share_widgets.c | 导航到下一个 tile | **保留**（view-to-view 通信） |
| `SIG_CREATE_SHARE_VIEW_NEXT_SLICE` | gui_create_share_widgets.c | SLIP39 切片进度 | **保留**（widget-to-view 通信） |
| `SIG_LOCK_VIEW_SCREEN_ON_VERIFY` | gui_lock_device_widgets.c | 触发密码验证 | **保留**（widget-to-view 通信） |
| `GUI_EVENT_REFRESH` | gui_general_home_widgets.c, gui_lock_widgets.c | 刷新 UI | **保留**（通用 UI 事件） |
| `SIG_SHOW_TRANSACTION_LOADING` | gui_eth_batch_tx_widgets.c | 显示加载动画 | **保留**（widget-to-view 通信） |

**12.2 结论**

这 10 个信号全部是 **view-to-view 或 widget-to-view 通信**，不是后端泄漏。它们控制 UI 状态切换，是信号系统的正常用途。全部保留。

---

### Phase 13：最终验证 + 文档更新

**13.1 最终泄漏检查**

运行全面审计，确认：
- Widget 层：0 个后端 include（仅 `kosmo_api.h` + `kosmo_types.h` + LVGL）
- View 层：0 个后端 include（仅信号系统 + LVGL）
- gui_model.c：≤13 个 `GuiApiEmitSignal`（全部 view 级信号）

**13.2 文档更新**

- 更新 `KOSMO固件前后端去耦合-plan.md`：记录 Phase 6-13 完成状态
- 更新 `Keystone固件原理.md`：架构图反映最终状态
- 新增 `KosmoApi 接口文档`：完整的 API 参考

**13.3 编译 + 模拟器验证**

零 error，模拟器启动正常。

---

## 四、预期最终状态

| 指标 | 当前 | 目标 |
|---|---|---|
| Widget 后端 include | ~50 个文件 | **0** |
| View 后端 include | 4 个文件 | **0** |
| `GuiApiEmitSignal`（gui_model.c） | 15 | **≤13**（view 级信号） |
| Widget `GuiEmitSignal` | 10 | **10**（view-to-view，保留） |
| KosmoApi getter 函数 | 14 | **~40** |
| KosmoApi 请求类型 | 39 | **39**（不变） |
| LVGL 开发者需要知道的后端概念 | chain/wallet/keystore/account/rust | **0** |

## 五、风险评估

| Phase | 风险 | 缓解措施 |
|---|---|---|
| 6（死 include） | 极低 | 编译验证即可 |
| 7（Wallet 包装） | 低 | 纯包装，不改逻辑 |
| 8（ConnectWallet） | **中高** | 最复杂的单文件，~50 个调用需逐个替换 |
| 9（链操作） | 中 | 地址生成函数签名差异大 |
| 10（BIP39） | 低 | 单文件，逻辑简单 |
| 11（信号残留） | 低 | 仅 2 个信号需迁移 |
| 12（Widget 信号） | 无 | 全部保留 |
| 13（验证） | 无 | 编译 + 模拟器 |

## 六、预估工时

| Phase | 预估 | 备注 |
|---|---|---|
| 6 | 0.5h | 机械删除 + 编译验证 |
| 7 | **2-3h** | ~20 个新 getter + 迁移 19 个文件（118 处 GetCurrentAccountIndex） |
| 8 | 2-3h | 最复杂，gui_connect_wallet_widgets.c 重构 |
| 9 | 1-2h | 地址生成包装 + 3 个文件迁移 |
| 10 | 1h | BIP39(6 文件) + AsyncExecute + Rust FFI(4 文件) |
| 11 | 0.5h | 2 个信号迁移 |
| 12 | 0h | 全部保留 |
| 13 | 0.5h | 验证 + 文档 |
| **总计** | **8-11h** | |

## 七、执行顺序建议

```
Phase 6（死 include 清理）
  ↓ 快速收益，缩小泄漏范围
Phase 7（Wallet 层包装）
  ↓ 解决最大面泄漏（GetMnemonicType 10 文件）
Phase 8（ConnectWallet 重构）
  ↓ 最难的单点，集中精力攻克
Phase 9（链操作包装）
  ↓ 收尾地址生成
Phase 10（BIP39 + AsyncExecute）
  ↓ 小修补
Phase 11（信号残留）
  ↓ 最后 2 个信号
Phase 13（验证 + 文档）
  ↓ 收官
```

Phase 6 和 Phase 7 可以合并执行（都是低风险的清理 + 包装工作）。
Phase 8 是最大的风险点，建议单独执行，每步编译验证。

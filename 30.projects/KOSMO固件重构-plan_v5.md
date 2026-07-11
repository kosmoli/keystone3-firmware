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

**剩余后端 include（widget + component 层，82 → 37）**：

| Header | v5 开始 | Phase 15 后 | Phase 8 后 | 处理方案 |
|---|---|---|---|---|
| `gui_chain.h` | 16 | 16 | **10** | Phase 8 ✅ -6, Phase 9 剩余 10 |
| `bip39.h` | 6 | 6 | **6** | Phase 10 |
| `rust.h` | 5 | 5 | **5** | Phase 10 |
| `secret_cache.h` | 26 | 11 | **5** | Slip39/DiceRolls/keyboard（暂保留） |
| `gui_model.h` | 22 | 22 | **3** | Phase 15 ✅ |
| `account_public_info.h` | 11 | 7 | **1** | 1 处死 include |
| `keystore.h` | 26 | 13 | **1** | 1 处死 include |
| `account_manager.h` | 21 | 17 | **0** | Phase 7 + 14 ✅ |

---

### Phase 8：KosmoApi 扩展 — ConnectWallet 状态管理 ✅

**目标**：将 `gui_connect_wallet_widgets.c` 的 ~50 个后端调用收编到 KosmoApi。

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

**8.3 结果**
- `gui_chain.h`: 16 → **10** 文件
- gui_connect_wallet_widgets.c 零后端 include（仅 `kosmo_api.h`）

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

**9.4 结果**
- `gui_chain.h`: 10 → **3** 文件（仅剩 CHECK_CHAIN 宏使用者）
- 总后端 include: 31 → **25**

---

### Phase 10：BIP39 + AsyncExecute + Rust FFI 清理

**10.1 BIP39 包装**
- `bip39_mnemonic_from_bytes`（1 处）→ KosmoApi 包装

**10.2 AsyncExecute 清理**
- `gui_lock_widgets.c` 中 1 处直接 `AsyncExecute()` → `KosmoApi_Request()`

**10.3 Rust FFI 清理**
- 4 个 widget 文件直接 include `rust.h` → 包装到 KosmoApi

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

## 四、预期最终状态（更新于 Phase 15 后）

| 指标 | v5 开始 | 当前 | 目标 |
|---|---|---|---|
| Widget 后端 include 总数 | **153** | **25**（-84%） | **0** |
| `account_manager.h` | 21 | **0** ✅ | 0 |
| `keystore.h` | 26 | **1** | 0 |
| `secret_cache.h` | 26 | **5** | 0 |
| `gui_model.h` | 22 | **3** | 0 |
| `gui_chain.h` | 16 | **3** | 0 |
| `account_public_info.h` | 11 | **1** | 0 |
| `bip39.h` | 6 | **6** | 0 |
| `rust.h` | 5 | **5** | 0 |
| `GuiApiEmitSignal`（gui_model.c） | 15 | 15 | **≤13**（view 级信号） |
| Widget `GuiEmitSignal` | 10 | 10 | **10**（view-to-view，保留） |
| KosmoApi 函数总数 | 39 | **~78** | ~80 |
| LVGL 开发者需要知道的后端概念 | chain/wallet/keystore/account/rust | **大幅减少** | **0** |

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

## 六、预估工时（更新于 Phase 15 后）

| Phase | 预估 | 实际 | 备注 |
|---|---|---|---|
| 6 | 0.5h | ✅ 0.5h | 死 include 清理 |
| 7 | 2h | ✅ 2h | Account/Wallet 层包装（130+ 处迁移） |
| 8 | 2-3h | ✅ 2h | ConnectWallet 重构（53 个调用迁移，15 个新函数） |
| 9 | 1-2h | ✅ 1h | 链操作包装 + GuiChainCoinType 迁移 |
| 10 | 1h | ⬜ | BIP39 + AsyncExecute + Rust FFI |
| 11 | 0.5h | ⬜ | 2 个信号迁移 |
| 12 | 0h | ✅ 0h | 全部保留 |
| 13 | 0.5h | ⬜ | 验证 + 文档 |
| 14 | 1.5h | ✅ 1.5h | SecretCache + 小函数包装 + 死 include 清理 |
| 15 | 0.5h | ✅ 0.5h | gui_model.h: 22→3 |
| **总计** | **10-14h** | **已完成 ~8h** | **剩余 ~2-6h** |

## 七、执行顺序建议

```
Phase 6 ✅（死 include 清理）
  ↓
Phase 7 ✅（Account/Wallet 层包装 — 最大面泄漏已解决）
  ↓
Phase 14 ✅（SecretCache + 小函数包装 — account_manager.h 归零）
  ↓
Phase 15 ✅（gui_model.h 类型迁移 — 22→3）
  ↓
Phase 8 ✅（ConnectWallet 重构 — 最难的单点，53 个调用迁移）
  ↓
Phase 9 ✅（链操作包装 — gui_chain.h: 16→3）
  ↓
Phase 10 ⬜（BIP39 + AsyncExecute + Rust FFI）
  ↓
Phase 11 ⬜（信号残留 — 2 个信号迁移）
Phase 13 ⬜（验证 + 文档）
  ↓ 收官
```

## 八、Phase 14：SecretCache + 小函数包装 ✅

**已完成**：

**14.1 SecretCache 包装（12 个函数）**
- `KosmoApi_CacheGetPassword/SetPassword/GetMnemonic/SetMnemonic/SetPassphrase`
- `KosmoApi_CacheGetChecksum/SetWalletIndex/SetWalletName/GetNewPassword/SetNewPassword/GetDiceRollsLen`

**14.2 小函数包装（6 个）**
- `KosmoApi_GetExistAccountNum/GetPassphraseQuickAccess`
- `KosmoApi_GetIsTempAccount/GetFirstReceive/SetFirstReceive/AccountPublicHomeCoinGet`

**14.3 Widget 迁移**
- SecretCache*: ~40 处 → 0
- 其他小函数: ~15 处 → 0
- 死 include 清理: 21 个文件

**14.4 死 include 清理**
- `account_manager.h`: 21 → **0** ✅（Phase 7 迁移 + Phase 14 清理）
- `keystore.h`: 26 → **1**（仅 gui_keyboard_hintbox.h）
- `secret_cache.h`: 26 → **5**（Slip39/DiceRolls/keyboard 保留）
- `account_public_info.h`: 11 → **1**（1 处死 include）
- `gui_model.h`: 22 → **3**（Phase 15 迁移，keyboard_hintbox 保留）

## 九、新增 Phase 15：gui_model.h 类型迁移

**目标**：将 widget 层对 `gui_model.h` 的 include 替换为 `kosmo_api.h`。

22 个 widget 文件 include `gui_model.h`，主要用于：
- 类型定义（`WalletDesc_t`、`Entropy_t` 等）
- `AsyncExecute` 宏（1 处）

方案：
1. 将 widget 需要的类型定义迁移到 `kosmo_types.h`
2. 将 `AsyncExecute` 调用改为 `KosmoApi_Request()`
3. 移除 widget 对 `gui_model.h` 的 include

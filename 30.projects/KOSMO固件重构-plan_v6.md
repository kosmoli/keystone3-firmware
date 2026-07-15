# KOSMO 固件重构 plan v6

> 日期: 2026-07-06
> 分支: feature/frontend-backend-decoupling
> 前置: plan_v5 Phase 20 完成（gui_model.c 中所有 EmitSignal → KosmoApi_NotifyResult）

---

## 一、目标

**消除 gui_model.c，将所有执行逻辑移入 KosmoApi。**

当前架构（三层）：
```
Widget → GuiModelXxx() → AsyncExecute(ModelXxx) → ui_common_* → KosmoApi_NotifyResult → callback
```

目标架构（两层）：
```
Widget → KosmoApi_Xxx(cb) → AsyncExecute → ui_common_* → KosmoApi_NotifyResult → callback
```

gui_model.c 是纯粹的中间层：1704 行代码，70 个 KosmoApi_NotifyResult 调用（已迁移），0 个 GuiApiEmitSignal（已干净）。它的唯一职责是 AsyncExecute 包装 + 路由。这个职责可以直接由 KosmoApi 承担。

---

## 二、现状分析

### gui_model.c 结构

| 层 | 数量 | 说明 |
|---|---|---|
| 公开函数（GuiModelXxx / GuiModeXxx） | 37 | Widget 调用入口 |
| 执行函数（ModelXxx / ModeXxx） | 27 | static，包含实际逻辑 |
| AsyncExecute 调用 | 38 | 异步执行包装 |
| KosmoApi_NotifyResult | 70 | 结果通知（已迁移） |
| GuiApiEmitSignal | 0 | 已清零 |

### 外部依赖

20 个文件 include `gui_model.h`：

- gui_views/: init, home, lock, scan, setting, system_setting, forget_pass, firmware_update, eth_batch_tx, transaction_detail, transaction_signature, usb_transport, standard_receive
- gui_widgets/: init_widgets
- gui_connect_wallet/: (间接)
- gui_frame/: gui_framework.c
- gui_chain/: gui_eth.c

### gui_model 函数分类

**A 类 — 简单包装（直接迁移）**
调用 AsyncExecute → ModelXxx → ui_common_* → KosmoApi_NotifyResult，无额外逻辑。

| 公开函数 | 执行函数 | KosmoApi 目标函数 |
|---|---|---|
| GuiModelSettingSaveWalletDesc | ModelSaveWalletDesc | KosmoApi_SaveWalletDesc |
| GuiModelSettingDelWalletDesc | ModelDelWallet | KosmoApi_DelWalletDesc |
| GuiModelLockedDeviceDelAllWalletDesc | ModelDelAllWallet | KosmoApi_DelAllWalletDesc |
| GuiModelSettingWritePassphrase | ModelWritePassphrase | KosmoApi_WritePassphrase |
| GuiModelChangeAccountPassWord | ModelChangeAccountPass | KosmoApi_ChangePassword |
| GuiModelVerifyAccountPassWord | ModelVerifyAccountPass | KosmoApi_VerifyAccountPassword |
| GuiModelWriteLastLockDeviceTime | ModelWriteLastLockDeviceTime | KosmoApi_WriteLockTime |
| GuiModelCopySdCardOta | ModelCopySdCardOta | KosmoApi_CopySdCardOta |
| GuiModelRsaGenerateKeyPair | ModelRsaGenerateKeyPair | KosmoApi_RsaGenerateKeyPair |
| GuiModelWriteSe | ModelWriteEntropyAndSeed | KosmoApi_WriteEntropyAndSeed |
| GuiModelBip39CalWriteSe | ModelBip39CalWriteEntropyAndSeed | KosmoApi_Bip39CalWriteSe |
| GuiModelBip39RecoveryCheck | ModelBip39VerifyMnemonic | KosmoApi_Bip39VerifyMnemonic |
| GuiModelBip39ForgetPassword | ModelBip39ForgetPass | KosmoApi_Bip39ForgetPassword |
| GuiModelSlip39WriteSe | ModelSlip39WriteEntropy | KosmoApi_Slip39WriteSe |
| GuiModelSlip39CalWriteSe | ModelSlip39CalWriteEntropyAndSeed | KosmoApi_Slip39CalWriteSe |
| GuiModelSlip39ForgetPassword | ModelSlip39ForgetPass | KosmoApi_Slip39ForgetPassword |
| GuiModelCalculateCheckSum | ModelCalculateCheckSum | KosmoApi_CalculateCheckSum |
| GuiModelCalculateBinSha256 | ModelCalculateBinSha256 | KosmoApi_CalculateBinSha256 |
| GuiModelCalculateWebAuthCode | ModelCalculateWebAuthCode | KosmoApi_CalculateWebAuthCode |
| GuiModeGetAccount | ModeGetAccount | KosmoApi_GetAccount |
| GuiModelFormatMicroSd | ModelFormatMicroSd | KosmoApi_FormatMicroSd |
| GuiModelParseTransactionRawData | ModelParseTransactionRawData | KosmoApi_ParseTransactionRawData |
| GuiModelTransactionParseRawDataDelay | ModelParseTransactionRawDataDelay | KosmoApi_ParseTransactionRawDataDelay |

**B 类 — 带额外 UI 逻辑（需要拆分）**
执行函数内部除了 ui_common_* 还有 UI 状态更新（如 GuiFramework_SetStatusBar）。

| 公开函数 | 额外逻辑 | 处理方式 |
|---|---|---|
| GuiModelSettingDelWalletDesc | ModelDelWallet 调用 GuiFramework_SetStatusBar | UI 逻辑移到 Widget 层的 callback 中 |
| GuiModelBip39UpdateMnemonic | 调用 ModelGenerateEntropy + ModelWriteEntropyAndSeed | 拆成两个 KosmoApi 调用，Widget 层编排 |
| GuiModelBip39UpdateMnemonicWithDiceRolls | 同上 | 同上 |
| GuiModelSlip39UpdateMnemonic | 调用 ModelGenerateSlip39Entropy + ModelSlip39WriteEntropy | 同上 |
| GuiModelSlip39UpdateMnemonicWithDiceRolls | 同上 | 同上 |

**C 类 — 复杂逻辑（需要仔细迁移）**
执行函数内部有多步逻辑、条件分支、内存管理。

| 公开函数 | 复杂度 | 说明 |
|---|---|---|
| ModelWriteEntropyAndSeed | 中 | 包含 ModelComparePubkey（260 行），需要保留 |
| ModelBip39CalWriteEntropyAndSeed | 中 | 包含 ModelComparePubkey |
| ModelSlip39CalWriteEntropyAndSeed | 中 | 包含 ModelComparePubkey |
| ModelSlip39WriteEntropy | 中 | 包含 ModelComparePubkey |
| ModelVerifyAccountPass | 高 | 包含 RSA 签名 + 多步验证 |
| ModelDelWallet | 高 | 包含钱包删除 + 安全擦除 + UI 状态更新 |
| ModeGetAccount | 中 | 包含账户初始化逻辑 |
| ModelURGenerateQRCode | 中 | 有 BackgroundAsyncRunnable 参数 |
| ModelURUpdate | 中 | UR 编码更新 |

**D 类 — 内部辅助函数（不迁移，保留在 KosmoApi 内部）**

| 函数 | 说明 |
|---|---|
| ModelComparePubkey | 260 行，被多个 ModelXxx 调用，作为 KosmoApi 内部 static 函数 |

---

## 三、执行计划

### Phase 21.0 — 准备：理解 AsyncExecute 机制

确认 gui_model.c 中 AsyncExecute 的实现方式：
- 是 FreeRTOS task？还是同步调用？
- 栈大小配置？
- 与 KosmoApi_Request 的关系？

**决策点**：如果 AsyncExecute 本身就是同步的（和当前 KosmoApi_Request 一样），可以直接内联到 KosmoApi 函数中。如果是异步的，需要保留异步机制。

### Phase 21.1 — 迁移 A 类函数（23 个）

机械性迁移：
1. 在 `kosmo_api.h` 中声明 `KosmoApi_Xxx()` 函数
2. 在 `kosmo_api.c` 中实现：
   - 从 `gui_model.c` 复制执行函数逻辑
   - 包装在 AsyncExecute 中（或直接内联，取决于 21.0 的决策）
   - 保留原有的 KosmoApi_NotifyResult 调用
3. 更新 Widget 调用点：`GuiModelXxx()` → `KosmoApi_Xxx(cb)`

每个函数迁移后编译验证。

### Phase 21.2 — 迁移 B 类函数（5 个）

拆分执行函数中的 UI 逻辑：
1. UI 逻辑（如 GuiFramework_SetStatusBar）移到 Widget 层的 callback 中
2. 执行逻辑移到 KosmoApi 函数中
3. Widget 通过 callback 接收结果后再执行 UI 更新

### Phase 21.3 — 迁移 C 类函数（9 个）

仔细迁移复杂函数：
1. ModelComparePubkey → `static` 函数保留在 `kosmo_api.c` 内部
2. ModelVerifyAccountPass → KosmoApi_VerifyAccountPassword
3. ModelDelWallet → KosmoApi_DelWalletDesc
4. 其他 C 类函数逐一迁移

### Phase 21.4 — 清理

1. 删除 `gui_model.c`（1704 行 → 0）
2. 删除 `gui_model.h`
3. 删除 `CMakeLists.txt` 中的 gui_model 引用
4. 清除所有外部文件的 `#include "gui_model.h"`
5. 编译验证
6. 模拟器验证

### Phase 21.5 — 更新笔记

更新"KOSMO前后端交互原理"笔记，记录新架构。

---

## 四、预期结果

| 指标 | 之前 | 之后 |
|---|---|---|
| gui_model.c | 1704 行 | 0（删除） |
| gui_model.h | 存在 | 0（删除） |
| 外部 include gui_model.h | 20 个文件 | 0 |
| KosmoApi 函数总数 | 64 | ~87（+23 A类 + 5 B类 + 9 C类 - 已有的 5 个） |
| 架构层数 | 3（Widget → gui_model → KosmoApi → ui_common） | 2（Widget → KosmoApi → ui_common） |
| Widget 需要知道的头文件 | gui_model.h + kosmo_api.h | 仅 kosmo_api.h |

---

## 五、风险与注意事项

1. **ModelComparePubkey 复用**：这个 260 行的函数被 4 个 ModelXxx 调用。迁移后作为 `kosmo_api.c` 内部 `static` 函数，不暴露给前端。

2. **AsyncExecute 机制**：如果 gui_model 的 AsyncExecute 使用了独立的 FreeRTOS task + 栈，需要确认 KosmoApi 层是否有等效机制。当前 KosmoApi_Request 是同步的。

3. **UI 逻辑拆分**：B 类函数中的 GuiFramework_SetStatusBar 等 UI 调用需要移到 Widget 层的 callback 中。这改变了执行顺序（先执行 → 后更新 UI），需要验证时序是否正确。

4. **g_modeData 全局变量**：gui_model.c 使用的全局数据（如 g_walletDesc, g_mnemonicNum 等）需要迁移到 KosmoApi 的 g_requestCache 或新的内部状态。

5. **编译顺序**：删除 gui_model 后，CMakeLists.txt 需要更新。确保 kosmo_api.c 在编译顺序上能访问所有 ui_common_* 函数。

---

## 六、时间估算

| Phase | 估算工时 | 难度 |
|---|---|---|
| 21.0 准备 | 0.5h | 低 |
| 21.1 A 类（23 个） | 3-4h | 低（机械性） |
| 21.2 B 类（5 个） | 1-2h | 中 |
| 21.3 C 类（9 个） | 3-4h | 中-高 |
| 21.4 清理 | 1h | 低 |
| 21.5 笔记 | 0.5h | 低 |
| **总计** | **9-12h** | |

---

## 七、与之前 Phase 的关系

| Phase | 状态 | 成果 |
|---|---|---|
| v5 Phase 18 | ✅ 完成 | Widget → KosmoApi 迁移 |
| v5 Phase 19 | ✅ 完成 | Component → KosmoApi 迁移 |
| v5 Phase 20 | ✅ 完成 | gui_model.c EmitSignal → KosmoApi_NotifyResult |
| **v6 Phase 21** | **⬜ 待执行** | **消除 gui_model.c** |

Phase 21 完成后，前端对后端的依赖将完全收敛到 `kosmo_api.h` 一个头文件，架构层数从 3 层压缩到 2 层。

---

## 执行记录（2026-07-15）

| Phase | 状态 | 关键变化 |
|---|---|---|
| 21.0 | ✅ | AsyncExecute 机制：模拟器同步、硬件 FreeRTOS 异步 |
| 21.1 | ✅ | KosmoApi_Request → Model* + AsyncExecute；33 个 GuiModel* 包装删除 |
| 21.2 | ✅ | 19 个文件 gui_model.h include 移除；3 个文件添加显式 include |
| 21.3 | ✅ | 全部 Model*/Mode* 搬入 kosmo_api.c（992→2492 行）；gui_model/ 目录删除 |
| 21.4 | ✅ | gui_model.c/h/internal.h 删除；CMakeLists 清理 |
| 21.5 | ✅ | 笔记更新 |

**最终编译**：0 error，模拟器二进制 build/simulator/simulator (44.5MB)

**架构变化**：
- 层数：3 层 → 2 层
- 后端头文件：Widget 层只需 kosmo_api.h
- net 代码行数：-230 行（删除的冗余大于新增的整合）

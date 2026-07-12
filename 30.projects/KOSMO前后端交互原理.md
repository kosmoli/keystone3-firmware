# KOSMO 前后端交互原理

> Phase 20 完成后的架构文档。描述 Widget → KosmoApi → Model → KosmoApi → Widget Callback → 信号 → View 栈的完整链路。

---

## 一、总览

```
┌──────────────┐     KosmoApi_Request      ┌──────────────┐
│   Widget 层   │ ──────────────────────►  │   KosmoApi   │
│ (gui_*_widgets)│                         │  (kosmo_api.c)│
│               │ ◄──────────────────────  │              │
│  verifyCallback│     KosmoResult         │              │
└──────────────┘                           └──────┬───────┘
       │ GuiEmitSignal                            │ 分发
       ▼                                          ▼
┌──────────────┐                           ┌──────────────┐
│  View 栈派发  │                           │  Model 层    │
│(gui_framework)│                           │(gui_model.c) │
└──────────────┘                           └──────────────┘
```

**核心原则**：
- 前端→后端：只通过 `KosmoApi_Request()`
- 后端→前端：只通过 `KosmoApi_NotifyResult()` → Widget callback
- 信号系统：仅限前端内部 View 栈路由

---

## 二、请求发起（前端→后端）

### 入口函数

```c
int32_t KosmoApi_Request(const KosmoRequest *request, KosmoCallback cb);
```

Widget 层构造 `KosmoRequest`，传入请求类型和 callback：

```c
KosmoRequest req = {
    .type = KOSMO_REQ_VERIFY_PASSWORD,
    .verify_password = { .errorCount = signalId }
};
KosmoApi_Request(&req, widget->verifyCallback);
```

### 内部流程

```
KosmoApi_Request()
    │
    ├── 1. 存储 callback
    │   g_pendingCallbacks[request->type] = cb;
    │   g_persistentCallbacks[request->type] = request->persistent;
    │
    └── 2. 分发到 Model 函数
        switch (request->type) {
            case KOSMO_REQ_VERIFY_PASSWORD:
                → GuiModelVerifyAccountPassWord(&param);
            case KOSMO_REQ_RSA_GENERATE_KEYPAIR:
                → GuiModelRsaGenerateKeyPair();
            case KOSMO_REQ_BIP39_GENERATE_ENTROPY:
                → GuiModelBip39UpdateMnemonic(wordCnt);
            // ... 共 ~30 种请求类型
        }
```

### 异步 vs 同步

| 环境 | 行为 |
|---|---|
| 模拟器 | `AsyncExecute` 同步执行，callback 在 `KosmoApi_Request` 返回前触发 |
| 真机 | 投递到 `FetchSensitiveDataTask` 队列，callback 在后端线程触发 |

### cb=NULL 语义

当 Widget 不关心结果时传 `NULL`。此时**保留已有 callback**（不清除），Model 函数正常执行，`KosmoApi_NotifyResult` 会调用之前注册的 callback（如果有的话）。

---

## 三、后端执行（Model 层）

Model 函数在后端上下文执行，完成实际业务逻辑后通过 `KosmoApi_NotifyResult` 返回结果。

### 请求类型 → Model 函数映射

| 请求类型 | Model 函数 | 说明 |
|---|---|---|
| `KOSMO_REQ_VERIFY_PASSWORD` | `ModelVerifyAccountPass` | 密码验证（最复杂） |
| `KOSMO_REQ_RSA_GENERATE_KEYPAIR` | `RsaGenerateKeyPair` | RSA 密钥生成（多阶段） |
| `KOSMO_REQ_GET_ACCOUNT` | `ModeGetAccount` | 获取账户列表 |
| `KOSMO_REQ_BIP39_*` | `ModelBip39*` | 助记词操作 |
| `KOSMO_REQ_WRITE_PASSPHRASE` | `ModelSettingWritePassphrase` | Passphrase 写入 |
| `KOSMO_REQ_CHECK_TRANSACTION` | `ModelCheckTransaction` | 交易检查 |
| ... | ... | 共 ~30 种 |

### ModelVerifyAccountPass 详细流程

```
ModelVerifyAccountPass(inData, inDataLen)
    │
    ├── 1. 验证密码
    │   ├── 锁屏场景（SIG_LOCK_VIEW_VERIFY_PIN）：
    │   │   → VerifyPasswordAndLogin(&accountIndex, password)
    │   │   → 特殊错误：ERR_KEYSTORE_EXTEND_PUBLIC_KEY_NOT_MATCH
    │   │     → KosmoApi_NotifyResult(VERIFY_PASSWORD, ret, NULL, 0)
    │   │     → return（不经过 ModelVerifyPassSuccess/Failed）
    │   │   → 成功后：ModeGetWalletDesc() 获取钱包描述
    │   └── 其他场景：
    │       → VerifyCurrentAccountPassword(password)
    │
    ├── 2. Passphrase 快速访问
    │   if (首次验证 && passphraseQuickAccess)
    │       → 修改 param = SIG_LOCK_VIEW_SCREEN_ON_VERIFY_PASSPHRASE
    │
    ├── 3. SecretCache 清理（后端逻辑，保留在 Model 层）
    │   某些场景不需要清除：密码修改、Passphrase 写入、签名等
    │
    ├── 4. 调用 ModelVerifyPassSuccess/Failed
    │   → 返回 resultSignal（告诉 Widget 该 emit 什么信号）
    │   → 同时执行后端操作（SetPassphrase、Vibrate、ClearSecretCache 等）
    │
    └── 5. KosmoApi_NotifyResult(VERIFY_PASSWORD, ret, data, dataLen)
        data = { resultSignal:u16, originalParam:u16, errorCount:u16 }
```

### ModelVerifyPassSuccess 返回的 resultSignal

| 原始 param | resultSignal | 含义 |
|---|---|---|
| `DEVICE_SETTING_ADD_WALLET` (钱包数<3) | `SIG_VERIFY_PASSWORD_PASS` | 通用成功 |
| `DEVICE_SETTING_ADD_WALLET` (钱包数=3) | `SIG_SETTING_ADD_WALLET_AMOUNT_LIMIT` | 钱包上限 |
| `SIG_SETTING_WRITE_PASSPHRASE` (成功) | `SIG_SETTING_WRITE_PASSPHRASE_PASS` | Passphrase 写入成功 |
| `SIG_SETTING_WRITE_PASSPHRASE` (失败) | `SIG_SETTING_WRITE_PASSPHRASE_FAIL` | Passphrase 写入失败 |
| `SIG_LOCK_VIEW_SCREEN_ON_VERIFY_PASSPHRASE` | `SIG_LOCK_VIEW_SCREEN_ON_PASSPHRASE_PASS` | Passphrase 快速访问 |
| `SIG_SETUP_RSA_PRIVATE_KEY_WITH_PASSWORD` | `SIG_SETUP_RSA_PRIVATE_KEY_RSA_VERIFY_PASSWORD_PASS` | RSA 密码验证成功 |
| 其他（default） | `SIG_VERIFY_PASSWORD_PASS` | 通用成功 |

### ModelVerifyPassFailed 返回的 resultSignal

| 原始 param | resultSignal |
|---|---|
| `SIG_LOCK_VIEW_VERIFY_PIN` / `SIG_LOCK_VIEW_SCREEN_GO_HOME_PASS` | `SIG_VERIFY_PASSWORD_FAIL` |
| `SIG_SETUP_RSA_PRIVATE_KEY_WITH_PASSWORD` | `SIG_SETUP_RSA_PRIVATE_KEY_RSA_VERIFY_PASSWORD_FAIL` |
| 其他（default） | `SIG_VERIFY_PASSWORD_FAIL` |

---

## 四、结果通知（后端→前端）

### KosmoApi_NotifyResult

```c
void KosmoApi_NotifyResult(KosmoRequestType type, int32_t errorCode,
                           void *data, uint32_t dataLen);
```

内部流程：

```
KosmoApi_NotifyResult(type, errorCode, data, dataLen)
    │
    ├── cb = g_pendingCallbacks[type]
    ├── if (!persistent) → g_pendingCallbacks[type] = NULL  // 一次性清除
    ├── 构造 KosmoResult { requestType, errorCode, data, dataLen }
    └── cb(&result)   // 调用 Widget 注册的 callback
```

### 持久 vs 一次性

| 模式 | 行为 | 使用场景 |
|---|---|---|
| 一次性（`persistent=false`） | NotifyResult 后清除 callback | 密码验证、账户查询等单次操作 |
| 持久（`persistent=true``） | NotifyResult 后保留 callback | RSA 多阶段进度、UR 流式更新 |

---

## 五、Widget Callback（结果翻译）

### 当前实现：KOSMO_DEFAULT_VERIFY_CALLBACK

定义在 `gui_keyboard_hintbox.c`，是向后兼容的默认 callback。

```
DefaultVerifyCallback(result)
    │
    ├── 从 result->data 读取 { resultSignal, originalParam, errorCount }
    │
    ├── 成功路径（errorCode == SUCCESS_CODE）：
    │   → s_defaultVerifyOriginalParam = originalParam
    │   → GuiEmitSignal(resultSignal, &s_defaultVerifyOriginalParam, sizeof)
    │
    └── 失败路径：
        → 构造 KosmoPasswordVerifyResult_t { errorCount, signal指向originalParam }
        → GuiEmitSignal(resultSignal, &pwdResult, sizeof)
```

### Widget 自定义 callback

任何 Widget 可以通过以下方式提供自己的 callback，替代默认行为：

```c
// 方式 1：通过 keyboard widget 设置
SetKeyboardWidgetCallback(keyboardWidget, myCustomCallback);

// 方式 2：通过 passcode widget 设置
GuiSetEnterPasscodeCallback(passcodeItem, myCustomCallback);
```

自定义 callback 收到 `KosmoResult` 后可以：
- 直接处理 UI 更新（不经过信号系统）
- 发起下一个 KosmoApi 请求（链式调用）
- 或仍然 emit 信号给 View 栈

---

## 六、信号派发（前端内部）

### GuiEmitSignal 机制

```c
int32_t GuiEmitSignal(uint16_t usEvent, void *param, uint16_t usLen);
```

**不是发布-订阅**，而是 View 栈遍历：

```
GuiEmitSignal(signal, param, len)
    │
    ├── 锁屏特殊路由
    │   if (GuiLockScreenIsTop()) {
    │       SIG_VERIFY_PASSWORD_FAIL + 锁屏验证 → 直接给 lockView
    │       param 指向 SIG_LOCK_VIEW_VERIFY_PIN → 直接给 lockView
    │   }
    │
    └── 栈遍历
        pView = g_workingView (栈顶)
        do {
            ret = pView->pEvtHandler(pView, signal, param, len)
            if (ret != ERR_GUI_UNHANDLED) → 已处理，停止
            pView = pView->previous → 继续往下找
        } while (pView != NULL)
```

### 信号分类

| 类别 | 发出方 | 消费方 | 说明 |
|---|---|---|---|
| 前端路由信号 | Widget/View | View | Widget 点击 → 页面切换（如 `SIG_INIT_USB_CONNECTION`） |
| 结果通知信号 | Widget callback | View | 后端结果翻译后的信号（如 `SIG_VERIFY_PASSWORD_PASS`） |

两类信号使用同一个派发机制，但来源不同：
- 前端路由信号：Widget 直接 emit
- 结果通知信号：Widget callback 从 KosmoApi 翻译后 emit

---

## 七、RSA 密钥生成（多阶段示例）

RSA 是 persistent callback 的典型场景，4 个阶段共用一个 callback：

```
gui_general_home_widgets.c:
    KosmoRequest req = { .type = KOSMO_REQ_RSA_GENERATE_KEYPAIR, .persistent = true };
    KosmoApi_Request(&req, callback);

RsaGenerateKeyPair():
    │
    ├── Stage 1: KosmoApi_NotifyResult(RSA, OK, stage=START)
    │   → callback → GuiEmitSignal(SIG_SETUP_RSA_PRIVATE_KEY_WITH_PASSWORD_START)
    │
    ├── Stage 2: KosmoApi_NotifyResult(RSA, OK, stage=GENERATE_ADDRESS)
    │   → callback → GuiEmitSignal(SIG_SETUP_RSA_PRIVATE_KEY_GENERATE_ADDRESS)
    │
    ├── Stage 3: KosmoApi_NotifyResult(RSA, ret, stage=PASS/FAIL)
    │   → callback → GuiEmitSignal(SIG_SETUP_RSA_PRIVATE_KEY_WITH_PASSWORD_PASS/FAIL)
    │
    └── Stage 4: KosmoApi_NotifyResult(RSA, OK, stage=HIDE_LOADING)
        → callback → GuiEmitSignal(SIG_SETUP_RSA_PRIVATE_KEY_HIDE_LOADING)
```

persistent callback 不会在每次 NotifyResult 后被清除，4 次通知走同一个 callback。

---

## 八、数据格式约定

### KosmoApi_NotifyResult 的 data 参数

| 请求类型 | data 布局 | 说明 |
|---|---|---|
| `VERIFY_PASSWORD` | `{ resultSignal:u16, originalParam:u16, errorCount:u16 }` | 6 字节 |
| `RSA_GENERATE_KEYPAIR` | `{ stage:u16 }` | 2 字节，stage 是信号 ID |
| `GET_ACCOUNT` | `uint8_t walletAmount` | 1 字节 |
| `EXTENDED_PUBLIC_KEY_NOT_MATCH` | `NULL, dataLen=0` | 特殊：errorCode != OK + data=NULL |

### KosmoPasswordVerifyResult_t（View 层期望的格式）

```c
typedef struct {
    void *signal;       // 指向 originalParam（哪个场景发起的验证）
    uint16_t errorCount; // 密码错误次数
} KosmoPasswordVerifyResult_t;
```

---

## 九、已知遗留问题

### Issue 1：KosmoApi_Request 住在 keyboard/passcode 组件里 ✅ 已解决

**问题**：`KeyboardConfirmHandler` 和 `GuiEnterPasscodeVerifyHandler` 直接调 `KosmoApi_Request`，组件层不应知道后端交互细节。

**解决方案**：给 `KeyboardWidget_t` 和 `GuiEnterPasscodeItem_t` 增加 `onConfirm(self, cb)` 回调。组件只负责收集输入和缓存密码，确认后调用 `onConfirm`，由父 Widget 决定做什么。

```
KeyboardConfirmHandler():
    KosmoApi_CacheSetPassword(密码)
    keyboardWidget->onConfirm(keyboardWidget, NULL)   ← 委托给父 Widget
```

默认实现 `DefaultKeyboardVerifyConfirm` / `DefaultPasscodeVerifyConfirm` 保留了原有的密码验证行为（注册信号转发 callback + 触发 KosmoApi），向后兼容。

父 Widget 通过 `SetKeyboardWidgetOnConfirm` / `GuiSetEnterPasscodeOnConfirm` 提供自定义实现。

**效果**：组件层完全不持有 callback，不直接调 KosmoApi_Request。回调的所有权归父 Widget。

### Issue 2：各 Widget 应提供自定义 callback 替代默认信号转发 ⬜ 渐进式

**问题**：当前所有 Widget 使用 `KOSMO_DEFAULT_VERIFY_CALLBACK`，它只是把 KosmoApi 结果翻译成信号再 emit 给 View 栈——本质上还是信号在做前后端交互。

**目标**：每个 Widget 的 callback 直接处理结果（UI 更新、页面跳转等），不经过信号系统。

**当前状态**：
- `KOSMO_DEFAULT_VERIFY_CALLBACK` 保证向后兼容，所有现有流程正常工作
- Widget 可以通过 `SetKeyboardWidgetCallback` / `GuiSetEnterPasscodeCallback` 提供自定义 callback
- 尚无 Widget 实际使用自定义 callback

**迁移路径**（逐个 Widget 推进）：
1. 锁屏验证（gui_lock_widgets.c）→ `LockScreenVerifyCallback`：直接处理解锁/错误显示
2. 交易签名（gui_transaction_detail_widgets.c）→ `TxSignVerifyCallback`：直接处理签名流程
3. 批量签名（gui_eth_batch_tx_widgets.c）→ `BatchTxVerifyCallback`
4. 设置页密码（gui_setting_widgets.c）→ `SettingVerifyCallback`
5. RSA 密码验证（gui_connect_wallet_widgets.c）→ `RsaVerifyCallback`
6. 其他调用点...

每个 Widget 迁移后，对应的 View 层信号 handler 可以删除。

### Issue 3：verify_password.errorCount 字段被滥用 ✅ 已解决

**问题**：`KosmoRequest.verify_password.errorCount` 实际传递的是原始信号 ID（如 `SIG_SETTING_CHANGE_PASSWORD`），不是密码错误次数。

**解决方案**：重命名为 `verify_password.signalId`，语义准确。

```c
// 之前（误导性命名）
struct { uint16_t errorCount; } verify_password;

// 之后（准确命名）
struct { uint16_t signalId; } verify_password;  /* original signal identifying the caller context */
```

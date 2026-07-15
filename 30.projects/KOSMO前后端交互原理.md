
---

## 十、Phase 21 — gui_model.c 消除（2026-07-15 ✅ 已完成）

### 背景

gui_model.c 曾是 Widget 层与 C 后端之间的"中继层"，包含：
- 33 个 `GuiModel*` 包装函数（如 `GuiModelWriteSe()`）
- 27 个 `Model*` 执行函数（如 `ModelWriteEntropyAndSeed()`）
- 1704 行代码

架构问题：每个 Widget 调用经历 **3 层**：
```
Widget → GuiModelXxx() → AsyncExecute(ModelXxx) → ModelXxx()
```

### 执行

Phase 21 分 5 步消除 gui_model.c：

1. **21.0** — 分析 AsyncExecute 机制（模拟器同步、硬件 FreeRTOS 异步）
2. **21.1** — `KosmoApi_Request` switch 直接调用 `Model*` + `AsyncExecute`，删除 33 个 `GuiModel*` 包装函数
3. **21.2** — 移除 19 个外部文件的 `#include "gui_model.h"`
4. **21.3** — 将所有 `Model*`/`Mode*` 执行函数物理搬入 `kosmo_api.c`（+1500 行）
5. **21.4** — 删除 `gui_model.c`/`gui_model.h`/`gui_model_internal.h`，移除 CMakeLists.txt 引用

### 结果

| 指标 | Phase 21 前 | Phase 21 后 |
|---|---|---|
| 架构层数 | 3（Widget → gui_model → KosmoApi → ui_common） | 2（Widget → KosmoApi → ui_common） |
| gui_model.c | 1704 行 | 0（已删除） |
| gui_model.h | 89 行 | 0（已删除） |
| kosmo_api.c | 992 行 | 2492 行 |
| 外部 gui_model.h include | 20 个文件 | 0 |
| 编译 | ✅ 0 error | ✅ 0 error |

### 当前架构

```
Widget → kosmo_api.h（唯一接口头文件）
         │
         ▼
KosmoApi_Request(type, cb)
    → 注册 callback
    → AsyncExecute(ModelXxx)
        → ModelXxx() [在 kosmo_api.c 内部]
            → ui_common_*() / Rust FFI
            → KosmoApi_NotifyResult(type, result)
                → Widget callback 被调用
```

### 遗留

- Issue 2（Widget 自定义 callback）仍待渐进式推进
- kosmo_api.c 后续可拆分（model 函数太多），但不是当前优先事项

#ifndef UI_ASYNC_H
#define UI_ASYNC_H

#include <stdint.h>
#include <stdbool.h>

/*
 * ui_async — 后端→前端异步事件投递机制
 *
 * 后端代码通过 ui_post_rpc_callback() 或 ui_post_notification() 将事件
 * 投递到 g_ui_async_mailbox 队列，UI 线程在主循环中消费并执行。
 *
 * 替代后端直接调用 GuiApiEmitSignal() 的跨线程越界调用。
 */

/* 事件类型 */
typedef enum {
    UI_EVENT_RPC_CALLBACK_READY,   /* 后端请求 UI 线程执行 RPC callback */
    UI_EVENT_NOTIFICATION,         /* 后端主动通知（电量/USB/SD卡/指纹等） */
} ui_event_type_t;

/* 异步事件帧 */
typedef struct {
    ui_event_type_t type;
    union {
        struct {
            void (*callback)(void *data);
            void *data;
        } rpc;
        struct {
            uint16_t signal;       /* 复用现有 signal ID */
            uint32_t value;        /* 数据值（≤4 字节，值拷贝） */
        } notify;
    };
} ui_async_event_t;

/*
 * 初始化 UI 异步邮箱队列。
 * 在 UI 任务启动时调用一次。
 */
void ui_async_mailbox_init(void);

/*
 * 投递 RPC callback 到 UI 线程执行。
 * 后端 Model* 函数完成工作后调用此函数，替代直接调用 callback。
 * callback 将在 UI 线程上下文中执行，可安全调用 LVGL 函数。
 */
void ui_post_rpc_callback(void (*cb)(void *data), void *data);

/*
 * 投递硬件事件通知到 UI 线程。
 * 替代后端直接调用 GuiApiEmitSignalWithValue(signal, value)。
 * signal 复用现有 signal ID，前端视图栈遍历分发不变。
 */
void ui_post_notification(uint16_t signal, uint32_t value);

/*
 * === 后端可读的前端状态变量 ===
 *
 * 注意：大部分 UI 状态变量已在 Phase 1/2 重构中移除。
 * 后端应使用自身的业务状态（GetCurrentAccountIndex、GetExistAccountNum 等）
 * 而非读取前端 UI 状态。
 *
 * 以下变量是 Phase 2 清理后的残留，待后续 Phase 进一步消除。
 */

/* 指纹识别是否被需要（依赖前端错误计数，Phase 2 暂保留） */
extern volatile bool g_ui_need_fp_recognize;

/* 创建钱包视图是否已打开（kosmo_api.c 仍在读取，Phase 2 暂保留） */
extern volatile bool g_ui_create_wallet_view_opened;

/* Passphrase 快速访问状态（kosmo_api.c 仍在读取，Phase 2 暂保留） */
extern volatile bool g_ui_passphrase_quick_access;


/*
 * 前端状态同步：在 UI 线程主循环中调用，将前端内部状态
 * 同步到上述全局变量，供后端安全读取。
 * Phase 2 清理后仅更新 3 个仍被使用的变量。
 */
void ui_state_sync(void);

#endif /* UI_ASYNC_H */

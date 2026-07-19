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
 * 这些 volatile 变量由前端在状态变化时更新，后端直接读取（无锁）。
 * 替代后端直接调用 GuiIsSetup() / GuiLockScreenIsTop() 等查询函数。
 *
 * 规则：前端只写，后端只读。
 */

/* 设备是否处于 Setup 流程 */
extern volatile bool g_ui_is_setup;

/* 锁屏界面是否在栈顶 */
extern volatile bool g_ui_lock_screen_is_top;

/* 锁屏验证加载动画是否显示中 */
extern volatile bool g_ui_lock_screen_verify_loading;

/* 首页是否在栈顶 */
extern volatile bool g_ui_home_page_is_top;

/* USB 传输视图是否在栈顶 */
extern volatile bool g_ui_usb_transport_view_is_top;

/* 密钥派生请求视图是否在栈顶 */
extern volatile bool g_ui_key_derivation_request_view_is_top;

/* 创建钱包视图是否已打开 */
extern volatile bool g_ui_create_wallet_view_opened;

/* 指纹识别是否被需要 */
extern volatile bool g_ui_need_fp_recognize;

/* 字母键盘状态是否有错误 */
extern volatile bool g_ui_letter_kb_status_error;

/* Passphrase 快速访问状态 */
extern volatile bool g_ui_passphrase_quick_access;

/*
 * 后端→前端数据传递：用于跨线程传递需要前端处理的数据指针。
 * 后端存储指针后通过 PubValueMsg 通知前端，前端在 UI 线程中取出并处理。
 * 当前用于 KeyDerivationRequest 的 UR 数据传递。
 */
extern volatile void *g_ui_pending_ur_result;

/*
 * 前端状态同步：在 UI 线程主循环中调用，将前端内部状态
 * 同步到上述全局变量，供后端安全读取。
 */
void ui_state_sync(void);

#endif /* UI_ASYNC_H */

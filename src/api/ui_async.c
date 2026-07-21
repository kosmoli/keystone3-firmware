#include "ui_async.h"
#include <stdio.h>

/* 后端→前端数据传递指针 */

#ifdef COMPILE_SIMULATOR
/*
 * 模拟器：同步执行（与 AsyncExecute 行为一致）
 * 不使用 FreeRTOS Queue，直接调用 callback 或 GuiEmitSignal。
 */
#include "gui_framework.h"

void ui_async_mailbox_init(void)
{
    /* 模拟器无需初始化队列 */
}

void ui_post_rpc_callback(void (*cb)(void *data), void *data)
{
    if (cb != NULL) {
        cb(data);
    }
}

void ui_post_notification(uint16_t signal, uint32_t value)
{
    /* 模拟器直接调用 GuiEmitSignal（同步，同线程） */
    static uint32_t s_value;
    s_value = value;
    GuiEmitSignal(signal, &s_value, sizeof(s_value));
}

void ui_async_mailbox_poll(void)
{
    /* 模拟器无需轮询，所有操作同步完成 */
}

#else /* 真机 FreeRTOS */

#include "FreeRTOS.h"
#include "queue.h"

#define UI_ASYNC_MAILBOX_DEPTH  16

static QueueHandle_t g_ui_async_mailbox = NULL;

void ui_async_mailbox_init(void)
{
    g_ui_async_mailbox = xQueueCreate(UI_ASYNC_MAILBOX_DEPTH, sizeof(ui_async_event_t));
    configASSERT(g_ui_async_mailbox != NULL);
}

void ui_post_rpc_callback(void (*cb)(void *data), void *data)
{
    if (g_ui_async_mailbox == NULL || cb == NULL) return;

    ui_async_event_t evt = {
        .type = UI_EVENT_RPC_CALLBACK_READY,
        .rpc.callback = cb,
        .rpc.data = data,
    };
    xQueueSend(g_ui_async_mailbox, &evt, 0);
}

void ui_post_notification(uint16_t signal, uint32_t value)
{
    if (g_ui_async_mailbox == NULL) return;

    ui_async_event_t evt = {
        .type = UI_EVENT_NOTIFICATION,
        .notify.signal = signal,
        .notify.value = value,
    };
    xQueueSend(g_ui_async_mailbox, &evt, 0);
}

/*
 * UI 线程调用：消费邮箱中的所有事件。
 * 在 lv_timer_handler() 之前调用。
 */
void ui_async_mailbox_poll(void)
{
    if (g_ui_async_mailbox == NULL) return;

    ui_async_event_t evt;
    while (xQueueReceive(g_ui_async_mailbox, &evt, 0) == pdTRUE) {
        switch (evt.type) {
        case UI_EVENT_RPC_CALLBACK_READY:
            evt.rpc.callback(evt.rpc.data);
            break;
        case UI_EVENT_NOTIFICATION: {
            extern int32_t GuiEmitSignal(uint16_t usEvent, void *param, uint16_t usLen);
            static uint32_t s_value;
            s_value = evt.notify.value;
            GuiEmitSignal(evt.notify.signal, &s_value, sizeof(s_value));
            break;
        }
        }
    }
}

#endif /* COMPILE_SIMULATOR */

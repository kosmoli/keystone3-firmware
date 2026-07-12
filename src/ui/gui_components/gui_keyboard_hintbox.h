#include "kosmo_api.h"
#ifndef _GUI_KEYBOARD_HINTBOX_H
#define _GUI_KEYBOARD_HINTBOX_H

#include "gui.h"
#include "gui_keyboard.h"

enum {
    KEYBOARD_HINTBOX_PIN = 0,
    KEYBOARD_HINTBOX_PASSWORD = 1,
};

typedef struct KeyboardWidget {
    lv_obj_t *keyboardHintBox;
    KeyBoard_t *kb;
    lv_obj_t *led[6];
    lv_obj_t *btnm;
    lv_obj_t *errLabel;
    lv_obj_t *eyeImg;
    lv_obj_t *switchLabel;
    uint8_t currentNum;
    uint16_t *sig;
    KosmoCallback verifyCallback;   /* Phase 20: Widget-owned callback for verify result */
    lv_timer_t *countDownTimer;
    uint8_t *timerCounter;
    lv_obj_t *errHintBox;
    lv_obj_t *errHintBoxBtn;
    struct KeyboardWidget **self;
} KeyboardWidget_t;

KeyboardWidget_t *GuiCreateKeyboardWidget(lv_obj_t *parent);
KeyboardWidget_t *GuiCreateKeyboardWidgetView(lv_obj_t *parent, lv_event_cb_t buttonCb, uint16_t *signal);
/* Default verify callback — forwards KosmoApi result as signal to view stack.
 * Any Widget can use this, or provide its own custom callback. */
extern const KosmoCallback KOSMO_DEFAULT_VERIFY_CALLBACK;

void SetKeyboardWidgetSig(KeyboardWidget_t *keyboardWidget, uint16_t *sig);
void SetKeyboardWidgetCallback(KeyboardWidget_t *keyboardWidget, KosmoCallback cb);
void SetKeyboardWidgetSelf(KeyboardWidget_t *keyboardWidget, KeyboardWidget_t **self);
void SetKeyboardWidgetMode(uint8_t mode);
uint8_t GetKeyboardWidgetMode(void);
void PassWordPinHintRefresh(KeyboardWidget_t *keyboardWidget);

void GuiDeleteKeyboardWidget(KeyboardWidget_t *keyboardWidget);
const char *GuiGetKeyboardInput(KeyboardWidget_t *keyboardWidget);
void GuiClearKeyboardInput(KeyboardWidget_t *keyboardWidget);
void GuiSetErrorLabel(KeyboardWidget_t *keyboardWidget, char *errorMessage);
void GuiShowErrorLabel(KeyboardWidget_t *keyboardWidget);
void GuiHideErrorLabel(KeyboardWidget_t *keyboardWidget);
void GuiShowErrorNumber(KeyboardWidget_t *keyboardWidget, KosmoPasswordVerifyResult_t *passwordVerifyResult);

#endif
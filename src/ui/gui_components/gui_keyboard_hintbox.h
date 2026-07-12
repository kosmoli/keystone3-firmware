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
    void (*onConfirm)(struct KeyboardWidget *self, KosmoCallback cb);  /* Phase 20: parent controls confirm behavior */
    lv_timer_t *countDownTimer;
    uint8_t *timerCounter;
    lv_obj_t *errHintBox;
    lv_obj_t *errHintBoxBtn;
    struct KeyboardWidget **self;
} KeyboardWidget_t;

KeyboardWidget_t *GuiCreateKeyboardWidget(lv_obj_t *parent);
KeyboardWidget_t *GuiCreateKeyboardWidgetView(lv_obj_t *parent, lv_event_cb_t buttonCb, uint16_t *signal);
/*
 * Default onConfirm handler: registers a signal-forwarding callback with
 * KosmoApi and triggers VERIFY_PASSWORD. Any Widget can use this as a
 * drop-in onConfirm, or provide its own custom handler.
 */
void DefaultKeyboardVerifyConfirm(KeyboardWidget_t *self, KosmoCallback cb);

void SetKeyboardWidgetSig(KeyboardWidget_t *keyboardWidget, uint16_t *sig);
void SetKeyboardWidgetOnConfirm(KeyboardWidget_t *keyboardWidget,
                                void (*onConfirm)(struct KeyboardWidget *self, KosmoCallback cb));
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
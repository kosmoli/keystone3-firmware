#include "gui.h"
#include "gui_obj.h"
#include "gui_views.h"
#include "gui_export_xpub_widgets.h"
#include "gui_animating_qrcode.h"

int32_t GuiExportXpubViewEventProcess(void *self, uint16_t usEvent, void *param, uint16_t usLen)
{
    switch (usEvent) {
    case GUI_EVENT_OBJ_INIT:
        GuiExportXpubInit();
        break;
    case GUI_EVENT_REFRESH:
        break;
    case GUI_EVENT_OBJ_DEINIT:
        GuiExportXpubDeInit();
        break;
    case SIG_BACKGROUND_UR_GENERATE_SUCCESS:
        GuiAnimantingQRCodeFirstUpdate((char *)param, usLen);
        break;
    case SIG_BACKGROUND_UR_UPDATE:
        GuiAnimatingQRCodeUpdate((char *)param, usLen);
        break;
    default:
        return ERR_GUI_UNHANDLED;
    }
    return SUCCESS_CODE;
}

GUI_VIEW g_exportXpubView = {
    .id = SCREEN_EXPORT_XPUB,
    .previous = NULL,
    .isActive = false,
    .optimization = false,
    .pEvtHandler = GuiExportXpubViewEventProcess,
};

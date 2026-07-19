#include "gui.h"
#include "kosmo_api.h"
#include "gui_obj.h"
#include "gui_views.h"
#include "gui_home_widgets.h"
#include "gui_pending_hintbox.h"
#include "gui_lock_widgets.h"
#include "gui_scan_widgets.h"
#include "qrdecode_task.h"

static int32_t GuiHomeViewInit(void)
{
    GuiHomeAreaInit();
    {
        KosmoRequest req = { .type = KOSMO_REQ_GET_WALLET_DESC };
        KosmoApi_Request(&req, NULL);
    }
    return SUCCESS_CODE;
}

static int32_t GuiHomeViewDeInit(void)
{
    GuiHomeDeInit();
    GuiPendingHintBoxMoveToTargetParent(lv_scr_act());
    return SUCCESS_CODE;
}

int32_t GuiHomeViewEventProcess(void *self, uint16_t usEvent, void *param, uint16_t usLen)
{
    switch (usEvent) {
    case GUI_EVENT_OBJ_INIT:
        return GuiHomeViewInit();
    case GUI_EVENT_OBJ_DEINIT:
        return GuiHomeViewDeInit();
    case GUI_EVENT_DISACTIVE:
        GuiHomeDisActive();
        break;
    case GUI_EVENT_RESTART:
        GuiHomeRestart();
        break;
    case GUI_EVENT_CHANGE_LANGUAGE:
        GuiHomeRestart();
        return ERR_GUI_UNHANDLED;
    case GUI_EVENT_REFRESH:
        GuiHomeRefresh();
        if (param != NULL) {
            KosmoRequest req = { .type = KOSMO_REQ_GET_WALLET_DESC };
            KosmoApi_Request(&req, NULL);
        }
        break;
    case SIG_SETUP_VIEW_TILE_PREV:
        GuiHomeRefresh();
        break;
    case SIG_INIT_GET_CURRENT_WALLET_DESC:
        GuiHomeSetWalletDesc((WalletDesc_t *)param);
        break;
    case SIG_SETUP_RSA_PRIVATE_KEY_PARSER_CONFIRM:
    case SIG_SETUP_RSA_PRIVATE_KEY_RECEIVE_CONFIRM:
        GuiShowRsaSetupasswordHintbox();
        break;
    case SIG_SETUP_RSA_PRIVATE_KEY_RSA_VERIFY_PASSWORD_FAIL:
        if (param != NULL) {
            KosmoPasswordVerifyResult_t *passwordVerifyResult = (KosmoPasswordVerifyResult_t *)param;
            uint16_t sig = *(uint16_t *)passwordVerifyResult->signal;
            if (sig == SIG_LOCK_VIEW_SCREEN_GO_HOME_PASS) {
                GuiLockScreenPassCode(false);
                GuiHomePasswordErrorCount(param);
                return SUCCESS_CODE;
            }
        }
        GuiHomePasswordErrorCount(param);
        break;
    case SIG_SETUP_RSA_PRIVATE_KEY_RSA_VERIFY_PASSWORD_PASS:
        printf("SIG_VERIFY_PASSWORD_PASS\n");
        if (param != NULL) {
            uint16_t sig = *(uint16_t *)param;
            if (sig == SIG_LOCK_VIEW_SCREEN_GO_HOME_PASS) {
                GuiLockScreenToHome();
                return SUCCESS_CODE;
            }
        }
        GuiRemoveKeyboardWidget();
        break;
    case SIG_SETUP_RSA_PRIVATE_KEY_WITH_PASSWORD_START:
        GuiPendingHintBoxOpen(_("InitializingRsaTitle"), _("FindingRsaPrimes"));
        break;
    case SIG_SETUP_RSA_PRIVATE_KEY_GENERATE_ADDRESS:
        GuiUpdatePendingHintBoxSubtitle(_("GeneratingRsaAddress"));
        break;
    case SIG_SETUP_RSA_PRIVATE_KEY_WITH_PASSWORD_PASS:
        GuiShowRsaInitializatioCompleteHintbox();
        break;

    case SIG_CLEAR_HOME_PAGE_INDEX:
        ClearHomePageCurrentIndex();
        break;
    case SIG_QRCODE_VIEW_SCAN_FAIL:
        {
            uint32_t val = *(uint32_t *)param;
            UrViewType_t urViewType = { .viewType = (val >> 8) & 0xFF, .urType = val & 0xFF };
            GuiScanResult(false, &urViewType);
        }
        break;
    case SIG_QRCODE_VIEW_SCAN_PASS:
        {
            uint32_t val = *(uint32_t *)param;
            UrViewType_t urViewType = { .viewType = (val >> 8) & 0xFF, .urType = val & 0xFF };
            GuiScanResult(true, &urViewType);
        }
        break;
    default:
        return ERR_GUI_UNHANDLED;
    }
    return SUCCESS_CODE;
}

GUI_VIEW g_homeView = {
    .id = SCREEN_HOME,
    .previous = NULL,
    .isActive = false,
    .optimization = false,
    .pEvtHandler = GuiHomeViewEventProcess,
};

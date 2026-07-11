#include "gui.h"
#include "gui_obj.h"
#include "gui_views.h"
#include "gui_enter_passcode.h"
#include "gui_status_bar.h"
#include "gui_scan_widgets.h"
#include "gui_status_bar.h"
#include "gui_hintbox.h"
#include "kosmo_api.h"
#include "gui_analyze.h"
#include "gui_button.h"
#include "gui_qr_code.h"
#include "secret_cache.h"
#include "qrdecode_task.h"
#include "gui_chain.h"
#include "assert.h"
#include "gui_web_auth_widgets.h"
#include "gui_qr_hintbox.h"
#include "motor_manager.h"
#include "gui_lock_widgets.h"
#include "screen_manager.h"
#include "fingerprint_process.h"
#include "gui_fullscreen_mode.h"
#include "gui_keyboard_hintbox.h"
#include "gui_page.h"
#include "account_manager.h"
#include "gui_btc.h"
#include "gui_pending_hintbox.h"

static void GuiScanNavBarInit();
static void GuiSetScanCorner(void);
static void ThrowError(int32_t errorCode);
static void GuiScanStart();


#define IsSlip39WalletNotSupported(viewType) (viewType == CHAIN_XMR)

static PageWidget_t *g_pageWidget;
static lv_obj_t *g_scanErrorHintBox = NULL;
static ViewType g_qrcodeViewType;
static uint8_t g_chainType = CHAIN_BUTT;
static ViewType g_viewTypeFilter[2];

void GuiScanInit(void *param, uint16_t len)
{
    if (param == NULL) {
        for (int i = 0; i < NUMBER_OF_ARRAYS(g_viewTypeFilter); i++) {
            g_viewTypeFilter[i] = 0xFF;
        }
    } else {
        memcpy_s(g_viewTypeFilter, sizeof(g_viewTypeFilter), param, len);
        for (int i = 0; i < NUMBER_OF_ARRAYS(g_viewTypeFilter); i++) {
            printf("g_viewTypeFilter %d = %d\n", i, g_viewTypeFilter[i]);
        }
    }
    if (g_pageWidget != NULL) {
        DestroyPageWidget(g_pageWidget);
        g_pageWidget = NULL;
    }
    g_pageWidget = CreatePageWidget();
    GuiScanNavBarInit();
}

void GuiScanDeInit()
{
    if (g_pageWidget != NULL) {
        DestroyPageWidget(g_pageWidget);
        g_pageWidget = NULL;
    }

    SetPageLockScreen(true);
}

void GuiScanRefresh()
{
    SetPageLockScreen(false);
    GuiScanStart();
}

void GuiScanResult(bool result, void *param)
{
    if (result) {
        UrViewType_t urViewType = *(UrViewType_t *)param;
        g_qrcodeViewType = urViewType.viewType;
        g_chainType = ViewTypeToChainTypeSwitch(g_qrcodeViewType);
        // Not a chain based transaction, e.g. WebAuth
        if (KosmoApi_GetMnemonicType() == KOSMO_MNEMONIC_SLIP39) {
            //we don't support ADA & XMR in Slip39 Wallet;
            if (IsSlip39WalletNotSupported(g_chainType)) {
                ThrowError(ERR_INVALID_QRCODE);
                return;
            }
        }
        if (g_chainType == CHAIN_BUTT) {
            if (g_qrcodeViewType == WebAuthResult) {
                GuiCloseCurrentWorkingView();
                GuiFrameOpenView(&g_webAuthResultView);
            }
            if (g_qrcodeViewType == KeyDerivationRequest) {
                if (!GuiCheckIfTopView(&g_homeView)) {
                    GuiCloseCurrentWorkingView();
                }
                GuiFrameOpenViewWithParam(&g_keyDerivationRequestView, NULL, 0);
            }
            if (g_qrcodeViewType == DeriveContextHashRequest) {
                if (!GuiCheckIfTopView(&g_homeView)) {
                    GuiCloseCurrentWorkingView();
                }
                GuiFrameOpenViewWithParam(&g_deriveContextHashRequestView, NULL, 0);
            }

            return;
        }
        if (g_qrcodeViewType == EthBatchTx) {
            printf("g_qrcodeViewType == EthBatchTx\n");
            if (!GuiCheckIfTopView(&g_homeView)) {
                GuiCloseCurrentWorkingView();
            }
            GuiFrameOpenView(&g_ethBatchTxView);
            return;
        }
        uint8_t accountNum = 0;
        KosmoApi_GetExistAccountNum(&accountNum);
        if (accountNum <= 0) {
            ThrowError(ERR_INVALID_QRCODE);
            return;
        }
        { KosmoRequest req = { .type = KOSMO_REQ_CHECK_TRANSACTION, .view_type = { .viewType = g_qrcodeViewType } }; KosmoApi_Request(&req, NULL); }
    } else {
        UrViewType_t *urViewType = (UrViewType_t *)param;
        if (urViewType->viewType == InvalidMessage) {
            ThrowError(ERR_SIGN_MESSAGE_INVALID_CHARACTERS);
        } else {
            ThrowError(ERR_INVALID_QRCODE);
        }
    }
}

void GuiTransactionCheckPass(void)
{
    { KosmoRequest req = { .type = KOSMO_REQ_CLEAR_CHECK_RESULT }; KosmoApi_Request(&req, NULL); }
    SetPageLockScreen(true);
    GuiCloseCurrentWorkingView();
    if (g_chainType == CHAIN_ARWEAVE) {
        if (KosmoApi_GetIsTempAccount()) {
            ThrowError(ERR_INVALID_QRCODE);
            return;
        }
        bool hasArXpub = IsArweaveSetupComplete();
        if (!hasArXpub) {
            GuiPendingHintBoxRemove();
            GoToHomeViewHandler(NULL);
            GuiCreateAttentionHintbox(SIG_SETUP_RSA_PRIVATE_KEY_PARSER_CONFIRM);
            return;
        }
    }
    GuiFrameOpenViewWithParam(&g_transactionDetailView, &g_qrcodeViewType, sizeof(g_qrcodeViewType));
}

//Here return the error code and error message so that we can distinguish the error type later.
void GuiTransactionCheckFailed(PtrT_TransactionCheckResult result)
{
    switch (result->error_code) {
    case BitcoinNoMyInputs:
    case BitcoinWalletTypeError:
    case MasterFingerprintMismatch:
    case UnsupportedTransaction:
        GuiCreateRustErrorWindow(result->error_code, result->error_message, NULL, GuiScanStart);
        break;
    default:
        ThrowError(ERR_INVALID_QRCODE);
        break;
    }
    { KosmoRequest req = { .type = KOSMO_REQ_CLEAR_CHECK_RESULT }; KosmoApi_Request(&req, NULL); }
}

static void GuiScanNavBarInit()
{
    SetNavBarLeftBtn(g_pageWidget->navBarWidget, NVS_BAR_RETURN, CloseTimerCurrentViewHandler, NULL);
}

static void GuiSetScanCorner(void)
{
    UpdatePageContentZone(g_pageWidget);

    lv_obj_t *cont = g_pageWidget->contentZone;
    static lv_point_t topLinePoints[2] = {{0, 0}, {322, 0}};
    static lv_point_t bottomLinePoints[2] = {{0, 0}, {322, 0}};
    static lv_point_t leftLinePoints[2] = {{0, 0}, {0, 322}};
    static lv_point_t rightLinePoints[2] = {{0, 0}, {0, 322}};
    lv_obj_t *line = GuiCreateLine(cont, topLinePoints, 2);
    lv_obj_align(line, LV_ALIGN_DEFAULT, 80, 224 - GUI_MAIN_AREA_OFFSET);

    line = GuiCreateLine(cont, bottomLinePoints, 2);
    lv_obj_align(line, LV_ALIGN_BOTTOM_LEFT, 80, -254);
    line = GuiCreateLine(cont, leftLinePoints, 2);
    lv_obj_align(line, LV_ALIGN_DEFAULT, 80, 224 - GUI_MAIN_AREA_OFFSET);

    line = GuiCreateLine(cont, rightLinePoints, 2);
    lv_obj_align(line, LV_ALIGN_BOTTOM_RIGHT, -78, -254);

    lv_obj_t *img = GuiCreateImg(cont, &imgLTCorner);
    lv_obj_align(img, LV_ALIGN_DEFAULT, 80, 223 - GUI_MAIN_AREA_OFFSET);

    img = GuiCreateImg(cont, &imgLTCorner);
    lv_obj_align(img, LV_ALIGN_TOP_RIGHT, -77 + 28, 223 - GUI_MAIN_AREA_OFFSET - 1);
    lv_img_set_angle(img, 900);
    lv_img_set_pivot(img, 0, 0);

    img = GuiCreateImg(cont, &imgLTCorner);
    lv_obj_align(img, LV_ALIGN_BOTTOM_LEFT, 79, -254 + 28 + 1);
    lv_img_set_angle(img, -900);
    lv_img_set_pivot(img, 0, 0);

    img = GuiCreateImg(cont, &imgLTCorner);
    lv_obj_align(img, LV_ALIGN_BOTTOM_RIGHT, -77 + 28, -254 + 28 + 1);
    lv_img_set_angle(img, 1800);
    lv_img_set_pivot(img, 0, 0);

}

static void ThrowError(int32_t errorCode)
{
    GuiSetScanCorner();
    g_scanErrorHintBox = GuiCreateErrorCodeWindow(errorCode, &g_scanErrorHintBox, GuiScanStart);
}

static void GuiScanStart()
{
    GuiSetScanCorner();
    { KosmoRequest req = { .type = KOSMO_REQ_CONTROL_QR_DECODE, .bool_param = { .enable = true } }; KosmoApi_Request(&req, NULL); }
}
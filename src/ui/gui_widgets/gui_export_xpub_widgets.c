#include <stdint.h>
#include "gui_obj.h"
#include "gui_views.h"
#include "gui_export_xpub_widgets.h"
#include "gui_page.h"
#include "gui_hintbox.h"
#include "gui_resource.h"
#include "gui_qr_code.h"
#include "gui_animating_qrcode.h"
#include "gui_pending_hintbox.h"
#include "keystore.h"
#include "account_public_info.h"
#include "kosmo_api.h"
#include "librust_c.h"

typedef enum {
    TILE_CHAIN_LIST = 0,
    TILE_PATH_SELECT,
    TILE_QR_DISPLAY,
} XpubTileIndex;

typedef struct {
    const char *name;
    const char *icon_label;
    KosmoChainType chain;
    bool hasMultiPath;
} XpubChainItem_t;

typedef struct {
    const char *title;
    const char *desc;
    int pathIndex;
} XpubPathItem_t;

static const XpubChainItem_t g_chainList[] = {
    {"Bitcoin",   "BTC",  KOSMO_CHAIN_BTC_NATIVE_SEGWIT, false},
    {"Ethereum",  "ETH",  KOSMO_CHAIN_ETH,               true },
    {"Solana",    "SOL",  KOSMO_CHAIN_SOL,               true },
    {"Cardano",   "ADA",  KOSMO_CHAIN_ADA,               true },
    {"Avalanche", "AVAX", KOSMO_CHAIN_AVAX,              true },
    {"Monero",    "XMR",  KOSMO_CHAIN_XMR,               false},
    {"Ton",       "TON",  KOSMO_CHAIN_TON,               false},
    {"Tron",      "TRX",  KOSMO_CHAIN_TRX,               false},
    {"XRP",       "XRP",  KOSMO_CHAIN_XRP,               false},
    {"Sui",       "SUI",  KOSMO_CHAIN_SUI,               true },
    {"Aptos",     "APT",  KOSMO_CHAIN_APT,               true },
    {"Arweave",   "AR",   KOSMO_CHAIN_ARWEAVE,           false},
};
#define CHAIN_LIST_LEN  NUMBER_OF_ARRAYS(g_chainList)

/* Path variants for multi-path chains */
static const XpubPathItem_t g_btcPaths[] = {
    {"Native SegWit", "m/84'/0'/0'",  0},
    {"Taproot",       "m/86'/0'/0'",  0},
    {"Legacy",        "m/44'/0'/0'",  0},
};
static const XpubPathItem_t g_ethPaths[] = {
    {"BIP44",         "m/44'/60'/0'",       0},
    {"Ledger Legacy", "m/44'/60'/0'/0",     1},
    {"Ledger Live 0", "m/44'/60'/0'/0/0",   2},
};
static const XpubPathItem_t g_solPaths[] = {
    {"BIP44",         "m/44'/501'/0'",      0},
    {"Root",          "m/44'/501'",         50},
};
static const XpubPathItem_t g_adaPaths[] = {
    {"Icarus",        "m/1852'/1815'/0'",   0},
    {"Ledger",        "m/1852'/1815'/0'",   0},
};
static const XpubPathItem_t g_avaxPaths[] = {
    {"BIP44",         "m/44'/9000'/0'",     0},
};
static const XpubPathItem_t g_suiPaths[] = {
    {"Default",       "m/44'/784'/0'/0'/0'", 0},
};
static const XpubPathItem_t g_aptPaths[] = {
    {"Default",       "m/44'/637'/0'/0'/0'", 0},
};

/* Single-path placeholder */
static const XpubPathItem_t g_singlePath[] = {
    {"Default", "", 0},
};

static PageWidget_t *g_pageWidget;
static lv_obj_t *g_tileview;
static lv_obj_t *g_tileChainList;
static lv_obj_t *g_tilePathSelect;
static lv_obj_t *g_tileQrDisplay;
static lv_obj_t *g_chainListCont;
static lv_obj_t *g_pathListCont;

static XpubTileIndex g_tileIdx;
static int g_selectedChain;
static int g_selectedPath;
static const XpubPathItem_t *g_curPaths;
static uint8_t g_curPathLen;

static void GotoTile(XpubTileIndex idx);
static void RefreshNavBar(void);
static void CreateChainListTile(lv_obj_t *parent);
static void CreatePathSelectTile(lv_obj_t *parent);
static void ChainClickHandler(lv_event_t *e);
static void PathClickHandler(lv_event_t *e);
static const XpubPathItem_t *GetPathsForChain(int chainIdx, uint8_t *outLen);
static UREncodeResult *GenerateExportViewKeys(void);

/* ─── Path lookup ────────────────────────────────── */

static const XpubPathItem_t *GetPathsForChain(int chainIdx, uint8_t *outLen)
{
    switch (g_chainList[chainIdx].chain) {
    case KOSMO_CHAIN_BTC_NATIVE_SEGWIT:
        *outLen = NUMBER_OF_ARRAYS(g_btcPaths); return g_btcPaths;
    case KOSMO_CHAIN_ETH:
        *outLen = NUMBER_OF_ARRAYS(g_ethPaths); return g_ethPaths;
    case KOSMO_CHAIN_SOL:
        *outLen = NUMBER_OF_ARRAYS(g_solPaths); return g_solPaths;
    case KOSMO_CHAIN_ADA:
        *outLen = NUMBER_OF_ARRAYS(g_adaPaths); return g_adaPaths;
    case KOSMO_CHAIN_AVAX:
        *outLen = NUMBER_OF_ARRAYS(g_avaxPaths); return g_avaxPaths;
    case KOSMO_CHAIN_SUI:
        *outLen = NUMBER_OF_ARRAYS(g_suiPaths); return g_suiPaths;
    case KOSMO_CHAIN_APT:
        *outLen = NUMBER_OF_ARRAYS(g_aptPaths); return g_aptPaths;
    default:
        *outLen = 1; return g_singlePath;
    }
}

/* ─── UR data generator (called on backend thread) ── */

static UREncodeResult *GenerateExportViewKeys(void)
{
    KosmoChainType chain = g_chainList[g_selectedChain].chain;
    uint8_t mfp[4] = {0};
    GetMasterFingerPrint(mfp);

    switch (chain) {
    case KOSMO_CHAIN_BTC_NATIVE_SEGWIT: {
        /* BTC: ur:crypto-account with 4 standard paths */
        ExtendedPublicKey key;
        key.path = (char *)g_curPaths[g_selectedPath].desc;
        key.xpub = (char *)KosmoApi_GetPublicKeyRaw(XPUB_TYPE_BTC_NATIVE_SEGWIT);
        if (key.xpub == NULL) return NULL;
        CSliceFFI_ExtendedPublicKey keys;
        keys.data = &key;
        keys.size = 1;
        return generate_btc_crypto_account_ur(mfp, 1, &keys);
    }

    case KOSMO_CHAIN_XMR: {
        /* XMR: JSON text (Feather Wallet format) */
        const char *spendKey = KosmoApi_GetPublicKey(KOSMO_CHAIN_XMR);
        const char *viewKey = KosmoApi_GetPublicKeyRaw(XPUB_TYPE_MONERO_PVK_0);
        if (spendKey == NULL || viewKey == NULL) return NULL;
        return generate_ur_xmr_json((char *)spendKey, (char *)viewKey);
    }

    case KOSMO_CHAIN_ETH: {
        /* ETH: ur:crypto-hd-key */
        const char *xpub = KosmoApi_GetPublicKey(chain);
        const char *path = KosmoApi_GetPath(chain);
        if (xpub == NULL || path == NULL) return NULL;
        return generate_ur_crypto_hd_key(mfp, 4, (char *)xpub, (char *)path, (char *)"Keystone");
    }

    case KOSMO_CHAIN_ADA: {
        /* ADA: ur:crypto-hd-key */
        const char *xpub = KosmoApi_GetPublicKey(chain);
        const char *path = KosmoApi_GetPath(chain);
        if (xpub == NULL || path == NULL) return NULL;
        return generate_ur_crypto_hd_key(mfp, 4, (char *)xpub, (char *)path, (char *)NULL);
    }

    case KOSMO_CHAIN_TON: {
        /* TON: ur:crypto-hd-key */
        const char *xpub = KosmoApi_GetPublicKey(chain);
        const char *path = KosmoApi_GetPath(chain);
        if (xpub == NULL || path == NULL) return NULL;
        return generate_ur_crypto_hd_key(mfp, 4, (char *)xpub, (char *)path, (char *)NULL);
    }

    case KOSMO_CHAIN_ARWEAVE: {
        /* AR: ur:arweave-crypto-account */
        const char *xpub = KosmoApi_GetPublicKey(chain);
        if (xpub == NULL) return NULL;
        return generate_ur_arweave_account(mfp, 4, (char *)xpub);
    }

    default: {
        /* Generic: ur:crypto-multi-accounts */
        const char *xpub = KosmoApi_GetPublicKey(chain);
        if (xpub == NULL) return NULL;

        ExtendedPublicKey key;
        key.path = (char *)KosmoApi_GetPath(chain);
        key.xpub = (char *)xpub;
        if (key.path == NULL) return NULL;

        CSliceFFI_ExtendedPublicKey keys;
        keys.data = &key;
        keys.size = 1;
        return generate_common_crypto_multi_accounts_ur(mfp, 4, &keys, "Kosmo");
    }
    }
}

/* ─── QR callbacks ───────────────────────────────── */

static void OnQrGenerateSuccess(char *data, uint16_t len)
{
    GuiPendingHintBoxRemove();
    printf("[ExportViewKeys] UR generated, len=%u\n", len);
}

static void OnQrGenerateFail(char *message)
{
    GuiPendingHintBoxRemove();
    printf("[ExportViewKeys] UR generate failed: %s\n", message);
}

static void OnQrUpdate(char *data, uint16_t len)
{
    /* Timer-driven update — GuiAnimatingQRCodeUpdate handles lv_qrcode_update */
}

/* ─── Navigation ─────────────────────────────────── */

static void GotoTile(XpubTileIndex idx)
{
    g_tileIdx = idx;
    lv_obj_set_tile_id(g_tileview, (uint32_t)idx, 0, LV_ANIM_OFF);
    RefreshNavBar();
}

static void ReturnFromPathHandler(lv_event_t *e)
{
    GotoTile(TILE_CHAIN_LIST);
}

static void ReturnFromQrHandler(lv_event_t *e)
{
    GuiAnimatingQRCodeDestroyTimer();
    {KosmoRequest r = {.type = KOSMO_REQ_UR_CLEAR}; KosmoApi_Request(&r, NULL);}
    if (g_chainList[g_selectedChain].hasMultiPath) {
        GotoTile(TILE_PATH_SELECT);
    } else {
        GotoTile(TILE_CHAIN_LIST);
    }
}

static void RefreshNavBar(void)
{
    switch (g_tileIdx) {
    case TILE_CHAIN_LIST:
        SetNavBarLeftBtn(g_pageWidget->navBarWidget, NVS_BAR_RETURN, CloseCurrentViewHandler, NULL);
        SetMidBtnLabel(g_pageWidget->navBarWidget, NVS_BAR_MID_LABEL, "Export View Keys");
        SetNavBarRightBtn(g_pageWidget->navBarWidget, NVS_RIGHT_BUTTON_BUTT, NULL, NULL);
        break;
    case TILE_PATH_SELECT:
        SetNavBarLeftBtn(g_pageWidget->navBarWidget, NVS_BAR_RETURN, ReturnFromPathHandler, NULL);
        SetMidBtnLabel(g_pageWidget->navBarWidget, NVS_BAR_MID_LABEL, "Select Path");
        SetNavBarRightBtn(g_pageWidget->navBarWidget, NVS_RIGHT_BUTTON_BUTT, NULL, NULL);
        break;
    case TILE_QR_DISPLAY:
        SetNavBarLeftBtn(g_pageWidget->navBarWidget, NVS_BAR_RETURN, ReturnFromQrHandler, NULL);
        SetMidBtnLabel(g_pageWidget->navBarWidget, NVS_BAR_MID_LABEL, (char *)g_chainList[g_selectedChain].name);
        SetNavBarRightBtn(g_pageWidget->navBarWidget, NVS_RIGHT_BUTTON_BUTT, NULL, NULL);
        break;
    }
}

/* ─── Chain list tile ────────────────────────────── */

static void CreateChainListTile(lv_obj_t *parent)
{
    g_chainListCont = GuiCreateContainerWithParent(parent, 408, 102 * CHAIN_LIST_LEN);
    lv_obj_align(g_chainListCont, LV_ALIGN_TOP_MID, 0, 0);
    lv_obj_set_style_bg_color(g_chainListCont, WHITE_COLOR, LV_PART_MAIN);
    lv_obj_set_style_bg_opa(g_chainListCont, LV_OPA_10 + LV_OPA_2, LV_PART_MAIN);
    lv_obj_set_style_radius(g_chainListCont, 24, LV_PART_MAIN);

    for (int i = 0; i < CHAIN_LIST_LEN; i++) {
        lv_obj_t *btn = lv_btn_create(g_chainListCont);
        lv_obj_set_size(btn, 384, 96);
        lv_obj_align(btn, LV_ALIGN_TOP_LEFT, 12, 4 + 102 * i);
        lv_obj_set_style_pad_all(btn, 0, LV_PART_MAIN);
        lv_obj_set_style_bg_opa(btn, LV_OPA_TRANSP, LV_PART_MAIN);
        lv_obj_set_style_border_width(btn, 0, LV_PART_MAIN);
        lv_obj_set_style_outline_width(btn, 0, LV_PART_MAIN);
        lv_obj_set_style_shadow_width(btn, 0, LV_PART_MAIN);
        lv_obj_add_event_cb(btn, ChainClickHandler, LV_EVENT_CLICKED, (void *)(intptr_t)i);

        lv_obj_t *label = GuiCreateBoldIllustrateLabel(btn, g_chainList[i].name);
        lv_obj_align(label, LV_ALIGN_LEFT_MID, 24, 0);

        lv_obj_t *arrow = GuiCreateImg(btn, &imgArrowRight);
        lv_obj_align(arrow, LV_ALIGN_RIGHT_MID, -24, 0);

        if (i < CHAIN_LIST_LEN - 1) {
            static lv_point_t pts[2] = {{0, 0}, {360, 0}};
            lv_obj_t *line = GuiCreateLine(g_chainListCont, pts, 2);
            lv_obj_align(line, LV_ALIGN_TOP_LEFT, 24, 102 * (i + 1));
        }
    }
}

/* ─── Path select tile ───────────────────────────── */

static void CreatePathSelectTile(lv_obj_t *parent)
{
    g_pathListCont = GuiCreateContainerWithParent(parent, 408, 10);
    lv_obj_align(g_pathListCont, LV_ALIGN_TOP_MID, 0, 0);
    lv_obj_set_style_bg_color(g_pathListCont, WHITE_COLOR, LV_PART_MAIN);
    lv_obj_set_style_bg_opa(g_pathListCont, LV_OPA_10 + LV_OPA_2, LV_PART_MAIN);
    lv_obj_set_style_radius(g_pathListCont, 24, LV_PART_MAIN);
}

static void RefreshPathList(void)
{
    lv_obj_clean(g_pathListCont);
    lv_obj_set_size(g_pathListCont, 408, 102 * g_curPathLen);
    lv_obj_set_style_radius(g_pathListCont, 24, LV_PART_MAIN);

    char desc[64];
    for (int i = 0; i < g_curPathLen; i++) {
        lv_obj_t *btn = lv_btn_create(g_pathListCont);
        lv_obj_set_size(btn, 384, 96);
        lv_obj_align(btn, LV_ALIGN_TOP_LEFT, 12, 4 + 102 * i);
        lv_obj_set_style_pad_all(btn, 0, LV_PART_MAIN);
        lv_obj_set_style_bg_opa(btn, LV_OPA_TRANSP, LV_PART_MAIN);
        lv_obj_set_style_border_width(btn, 0, LV_PART_MAIN);
        lv_obj_set_style_outline_width(btn, 0, LV_PART_MAIN);
        lv_obj_set_style_shadow_width(btn, 0, LV_PART_MAIN);
        lv_obj_add_event_cb(btn, PathClickHandler, LV_EVENT_CLICKED, (void *)(intptr_t)i);

        lv_obj_t *title = GuiCreateBoldIllustrateLabel(btn, g_curPaths[i].title);
        lv_obj_align(title, LV_ALIGN_TOP_LEFT, 24, 16);

        snprintf_s(desc, sizeof(desc), "%s", g_curPaths[i].desc);
        lv_obj_t *label = GuiCreateNoticeLabel(btn, desc);
        lv_obj_align(label, LV_ALIGN_TOP_LEFT, 24, 50);

        lv_obj_t *arrow = GuiCreateImg(btn, &imgArrowRight);
        lv_obj_align(arrow, LV_ALIGN_RIGHT_MID, -24, 0);

        if (i < g_curPathLen - 1) {
            static lv_point_t pts[2] = {{0, 0}, {360, 0}};
            lv_obj_t *line = GuiCreateLine(g_pathListCont, pts, 2);
            lv_obj_align(line, LV_ALIGN_TOP_LEFT, 24, 102 * (i + 1));
        }
    }
}

/* ─── Start QR generation ────────────────────────── */

static void StartQrGeneration(lv_obj_t *qrParent)
{
    /* Clean up any previous UR session */
    GuiAnimatingQRCodeDestroyTimer();
    {KosmoRequest r = {.type = KOSMO_REQ_UR_CLEAR}; KosmoApi_Request(&r, NULL);}

    /* Kick off UR generation via persistent KosmoApi_Request */
    GuiAnimatingQRCodeInit(qrParent, GenerateExportViewKeys, true,
                           OnQrGenerateSuccess, OnQrGenerateFail, OnQrUpdate);
}

/* ─── Event handlers ─────────────────────────────── */

static void ChainClickHandler(lv_event_t *e)
{
    g_selectedChain = (int)(intptr_t)lv_event_get_user_data(e);
    g_selectedPath = 0;

    if (g_chainList[g_selectedChain].hasMultiPath) {
        g_curPaths = GetPathsForChain(g_selectedChain, &g_curPathLen);
        RefreshPathList();
        GotoTile(TILE_PATH_SELECT);
    } else {
        g_curPaths = GetPathsForChain(g_selectedChain, &g_curPathLen);
        /* Go to QR tile and start generation */
        GotoTile(TILE_QR_DISPLAY);
        StartQrGeneration(g_tileQrDisplay);
    }
}

static void PathClickHandler(lv_event_t *e)
{
    g_selectedPath = (int)(intptr_t)lv_event_get_user_data(e);
    GotoTile(TILE_QR_DISPLAY);
    StartQrGeneration(g_tileQrDisplay);
}

/* ─── Public API ─────────────────────────────────── */

void GuiExportXpubInit(void)
{
    g_pageWidget = CreatePageWidget();
    lv_obj_t *cont = g_pageWidget->contentZone;

    g_tileview = GuiCreateTileView(cont);
    g_tileChainList = lv_tileview_add_tile(g_tileview, TILE_CHAIN_LIST, 0, LV_DIR_HOR);
    g_tilePathSelect = lv_tileview_add_tile(g_tileview, TILE_PATH_SELECT, 0, LV_DIR_HOR);
    g_tileQrDisplay = lv_tileview_add_tile(g_tileview, TILE_QR_DISPLAY, 0, LV_DIR_HOR);

    CreateChainListTile(g_tileChainList);
    CreatePathSelectTile(g_tilePathSelect);

    GotoTile(TILE_CHAIN_LIST);
}

void GuiExportXpubDeInit(void)
{
    GuiAnimatingQRCodeDestroyTimer();
    {KosmoRequest r = {.type = KOSMO_REQ_UR_CLEAR}; KosmoApi_Request(&r, NULL);}
    if (g_pageWidget) {
        DestroyPageWidget(g_pageWidget);
        g_pageWidget = NULL;
    }
}

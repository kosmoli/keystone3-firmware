#ifndef _GUI_CHAIN_H
#define _GUI_CHAIN_H

#include "gui_animating_qrcode.h"
#include "gui_btc.h"
#include "gui_zcash.h"
#include "gui_eth.h"
#include "gui_eth_batch_tx_widgets.h"
#include "gui_trx.h"
#include "gui_cosmos.h"
#include "gui_sui.h"
#include "gui_sol.h"
#include "gui_aptos.h"
#include "gui_ada.h"
#include "gui_xrp.h"
#include "gui_ar.h"
#include "gui_stellar.h"
#include "gui_ton.h"
#include "gui_avax.h"
#include "gui_iota.h"
#include "gui_monero.h"
#include "kosmo_types.h"

typedef void (*SetChainDataFunc)(void *resultData, void *multiResultData, bool multi);


// Enumeration of pages used for transaction resolution
typedef enum {
    REMAPVIEW_BTC,
    REMAPVIEW_BTC_MESSAGE,
    REMAPVIEW_ETH,
    REMAPVIEW_ETH_PERSONAL_MESSAGE,
    REMAPVIEW_ETH_TYPEDDATA,
    REMAPVIEW_ETH_BATCH_TX,
    REMAPVIEW_TRX,
    REMAPVIEW_TRX_PERSONAL_MESSAGE,
    REMAPVIEW_TRX_SWAP,
    REMAPVIEW_COSMOS,
    REMAPVIEW_SUI,
    REMAPVIEW_SUI_SIGN_MESSAGE_HASH,
    REMAPVIEW_SOL,
    REMAPVIEW_SOL_MESSAGE,
    REMAPVIEW_IOTA,
    REMAPVIEW_IOTA_SIGN_MESSAGE_HASH,
    REMAPVIEW_APT,
    REMAPVIEW_ADA,
    REMAPVIEW_ADA_SIGN_TX_HASH,
    REMAPVIEW_ADA_SIGN_DATA,
    REMAPVIEW_ADA_CATALYST,
    REMAPVIEW_XRP,
    REMAPVIEW_AR,
    REMAPVIEW_AR_MESSAGE,
    REMAPVIEW_AR_DATAITEM,
    REMAPVIEW_STELLAR,
    REMAPVIEW_STELLAR_HASH,
    REMAPVIEW_TON,
    REMAPVIEW_TON_SIGNPROOF,
    REMAPVIEW_AVAX,
    REMAPVIEW_ZCASH,

    REMAPVIEW_XMR_OUTPUT,
    REMAPVIEW_XMR_UNSIGNED,
    REMAPVIEW_WEB_AUTH,
    REMAPVIEW_BUTT,
} GuiRemapViewType;

typedef struct {
    uint16_t chain;
    SetChainDataFunc func;
} SetChainData_t;

typedef UREncodeResult *(*SignFn)(void *data, PtrBytes seed, uint32_t seed_len);

#define CHECK_CHAIN_BREAK(result)                                       \
    if (result->error_code != 0) {                                      \
        printf("result->code = %d\n", result->error_code);              \
        printf("result->error message = %s\n", result->error_message);  \
        break;  \
    }

#define CHECK_CHAIN_RETURN(result)                                      \
    if (result->error_code != 0) {                                      \
        printf("result->code = %d\n", result->error_code);              \
        printf("result->error message = %s\n", result->error_message);  \
        return NULL;  \
    }

#define CHECK_CHAIN_PRINT(result)                                       \
    if (result->error_code != 0) {                                      \
        printf("result->code = %d\n", result->error_code);              \
        printf("result->error message = %s\n", result->error_message);  \
    }

#define CHECK_FREE_UR_RESULT(result, multi)                             \
    if (result != NULL) {                                               \
        if (multi) {                                                    \
            free_ur_parse_multi_result((PtrT_URParseMultiResult)result);\
        } else {                                                        \
            free_ur_parse_result((PtrT_URParseResult)result);           \
        }                                                               \
        result = NULL;                                                  \
    }

GuiRemapViewType ViewTypeReMap(uint8_t viewType);
GuiChainCoinType ViewTypeToChainTypeSwitch(uint8_t viewType);
PtrT_TransactionCheckResult CheckUrResult(uint8_t viewType);
GenerateUR GetUrGenerator(ViewType viewType);
GenerateUR GetSingleUrGenerator(ViewType viewType);
bool CheckViewTypeIsAllow(uint8_t viewType);
bool IsMessageType(uint8_t type);
bool isTonSignProof(uint8_t type);
bool isCatalystVotingRegistration(uint8_t type);
bool CheckViewTypeIsAllow(uint8_t viewType);
#endif

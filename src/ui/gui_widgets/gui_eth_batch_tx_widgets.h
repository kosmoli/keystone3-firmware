#ifndef _GUI_ETH_BATCH_TX_WIDGETS_H
#define _GUI_ETH_BATCH_TX_WIDGETS_H



#include "stdint.h"
#include "stdlib.h"
#include "stdbool.h"
/* Forward declarations for Rust FFI types */
typedef struct URParseResult URParseResult;
typedef struct URParseMultiResult URParseMultiResult;
typedef struct UREncodeResult UREncodeResult;


void GuiEthBatchTxWidgetsInit();
void GuiEthBatchTxWidgetsDeInit();
void GuiEthBatchTxWidgetsRefresh();
void GuiEthBatchTxWidgetsVerifyPasswordSuccess();
void GuiEthBatchTxWidgetsTransactionParseSuccess();
void GuiEthBatchTxWidgetsTransactionParseFail();
void GuiCreateEthBatchTxWidget();
void GuiSetEthBatchTxData(URParseResult *urResult, URParseMultiResult *urMultiResult, bool multi);
void GuiEthBatchTxWidgetsSignDealFingerRecognize(void *param);
void GuiEthBatchTxWidgetsSignVerifyPasswordErrorCount(void *param);
UREncodeResult *GuiGetEthBatchTxSignQrCodeData();

#endif

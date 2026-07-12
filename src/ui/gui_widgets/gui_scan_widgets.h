#ifndef _GUI_SCAN_WIDGETS_H
#define _GUI_SCAN_WIDGETS_H


void GuiScanInit(void *param, uint16_t len);
void GuiScanDeInit();
void GuiScanRefresh();
void GuiScanResult(bool result, void *param);
void GuiTransactionCheckPass(void);
struct TransactionCheckResult;
void GuiTransactionCheckFailed(struct TransactionCheckResult *result);

#endif /* _GUI_SCAN_WIDGETS_H */

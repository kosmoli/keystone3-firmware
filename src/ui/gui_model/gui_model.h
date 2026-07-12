#ifndef _GUI_MODEL_H
#define _GUI_MODEL_H

#include "kosmo_types.h"
#ifndef COMPILE_SIMULATOR
#include "user_sqlite3.h"
#include "fingerprint_process.h"
#include "screen_manager.h"
#include "anti_tamper.h"
#include "presetting.h"
#include "drv_sdcard.h"
#include "drv_mpu.h"
#include "log.h"
#include "presetting.h"
#include "anti_tamper.h"
#include "drv_battery.h"
#else
#include "simulator_model.h"
#endif
#include "gui_analyze_chains.h"
#include "rsa.h"
#include "rust.h"
#include "drv_rtc.h"
#include "drv_battery.h"
#include "gui_animating_qrcode.h"
#include "account_manager.h"
#include "drv_rtc.h"

#define MAX_LOGIN_PASSWORD_ERROR_COUNT  10
#define MAX_CURRENT_PASSWORD_ERROR_COUNT_SHOW_HINTBOX 4

/* ── GuiModel* / GuiMode* 函数声明 ───────────────────────── */

/* 后端写入 / 状态修改 */
void GuiModelWriteSe(void);
void GuiModelBip39CalWriteSe(Bip39Data_t bip39);
void GuiModelBip39RecoveryCheck(uint8_t wordsCnt);
void GuiModelBip39ForgetPassword(uint8_t wordsCnt);
void GuiModelBip39UpdateMnemonic(uint8_t wordCnt);
void GuiModelBip39UpdateMnemonicWithDiceRolls(uint8_t wordCnt);
void GuiModelSlip39WriteSe(uint8_t wordsCnt);
void GuiModelSlip39CalWriteSe(Slip39Data_t slip39);
void GuiModelSlip39ForgetPassword(Slip39Data_t slip39);
void GuiModelSlip39UpdateMnemonic(Slip39Data_t slip39);
void GuiModelSlip39UpdateMnemonicWithDiceRolls(Slip39Data_t slip39);

/* 密码 / 设备管理 */
void GuiModelChangeAccountPassWord(void);
void GuiModelVerifyAccountPassWord(uint16_t *param);
void GuiModelWriteLastLockDeviceTime(uint32_t time);

/* 钱包描述 / Passphrase */
void GuiModelSettingSaveWalletDesc(WalletDesc_t *wallet);
void GuiModelSettingDelWalletDesc(void);
void GuiModelLockedDeviceDelAllWalletDesc(void);
void GuiModelSettingWritePassphrase(void);

/* 查询 / 计算 */
void GuiModelCalculateCheckSum(void);
void GuiModelStopCalculateCheckSum(void);
void GuiModelCalculateBinSha256(void);
void GuiModelCalculateWebAuthCode(void *webAuthData);

/* SD 卡 / OTA */
void GuiModelFormatMicroSd(void);
void GuiModelCopySdCardOta(void);
void GuiModelUpdateBoot(void);

/* UR / QR */
void GuiModelURGenerateQRCode(GenerateUR func);
void GuiModelURUpdate(void);
void GuiModelURClear(void);

/* 交易 */
void GuiModelCheckTransaction(ViewType viewType);
void GuiModelTransactionCheckResultClear(void);
void GuiModelParseTransaction(ReturnVoidPointerFunc func);
void GuiModelParseTransactionRawData(void);
void GuiModelTransactionParseRawDataDelay(void);

/* RSA */
void GuiModelRsaGenerateKeyPair(void);

/* GuiMode* 查询 */
void GuiModeGetAccount(void);
void GuiModeGetWalletDesc(void);
void GuiModeControlQrDecode(bool en);

#endif /* _GUI_MODEL_H */

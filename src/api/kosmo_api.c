/*
 * kosmo_api.c — 后端操作统一接口实现
 *
 * Phase 1: 同步查询实现（包装 account_public_info / keystore / account_manager）。
 * Phase 2: 异步请求实现（包装 gui_model）。
 *
 * 本文件是唯一允许 #include 后端头文件的"桥梁"。
 * UI 层只 #include "kosmo_api.h"。
 */

#include "kosmo_api.h"
#include "ui_async.h"
#include <string.h>
#include "stdlib.h"

/* ── 后端头文件（只有这里能 include）────────────────── */

#include "account_public_info.h"
#include "account_manager.h"
#include "keystore.h"
#include "bip39.h"
#include "slip39.h"
#include "wordlist.h"
#include "gui_wallet.h"
#include "gui_xrp.h"
#include "gui_ada.h"
#include "rust.h"
#include "gui_status_bar.h"
#include "secret_cache.h"
#include "gui.h"
#include "gui_views.h"
#include "gui_obj.h"
#include "bip39_english.h"
#include "user_memory.h"
#include "log_print.h"
#include "background_task.h"
#include "fetch_sensitive_data_task.h"
#include "gui_setting_widgets.h"
#include "gui_chain.h"
#include "user_utils.h"
#include "device_setting.h"
#include "presetting.h"
#include "ui_display_task.h"
#include "motor_manager.h"
#include "gui_animating_qrcode.h"
#include "screen_manager.h"
#include "qrdecode_task.h"
#include "assert.h"
#include "version.h"
#include "user_delay.h"

#ifndef COMPILE_SIMULATOR
#include "sha256.h"
#include "user_msg.h"
#include "general_msg.h"
#include "cmsis_os.h"
#include "fingerprint_process.h"
#include "user_fatfs.h"
#include "mhscpu_qspi.h"
#include "safe_mem_lib.h"
#include "usb_task.h"
#include "drv_mpu.h"
#include "FreeRTOS.h"
#include "portable.h"
#else
#include "simulator_model.h"
#endif

/* ── Constants (from gui_model.h / gui_model.c) ─────────── */

#define MAX_LOGIN_PASSWORD_ERROR_COUNT  10
#define MAX_CURRENT_PASSWORD_ERROR_COUNT_SHOW_HINTBOX 4

#define SECTOR_SIZE                         4096
#define APP_ADDR                            (0x1001000 + 0x80000)   //108 1000
#define APP_CHECK_START_ADDR                (0x1400000)
#define APP_END_ADDR                        (0x2000000)
#define SD_CARD_OTA_FILE_PATH               "0:/keystone3.bin"
#define INTERNAL_STORAGE_OTA_FILE_PATH      "1:/keystone3.bin"

#define MODEL_WRITE_SE_HEAD                 do {                                \
        ret = CHECK_BATTERY_LOW_POWER();                                        \
        CHECK_ERRCODE_BREAK("save low power", ret);                             \
        ret = GetBlankAccountIndex(&newAccount);                                \
        CHECK_ERRCODE_BREAK("get blank account", ret);                          \
        ret = GetExistAccountNum(&accountCnt);                                  \
        CHECK_ERRCODE_BREAK("get exist account", ret);                          \
        printf("before accountCnt = %d\n", accountCnt);

#define MODEL_WRITE_SE_END(reqType)                                             \
        ret = VerifyPasswordAndLogin(&newAccount, SecretCacheGetNewPassword());    \
        CHECK_ERRCODE_BREAK("login error", ret);                                \
        GetExistAccountNum(&accountCnt);                                        \
        printf("after accountCnt = %d\n", accountCnt);                          \
    } while (0);                                                                \
    if (ret == SUCCESS_CODE) {                                                  \
        ClearSecretCache();                                                     \
        KosmoApi_NotifyResult(reqType, SUCCESS_CODE, NULL, 0);                  \
    } else {                                                                            \
        KosmoApi_NotifyResult(reqType, ret, NULL, 0);                          \
    }

/* ── Model* globals (from gui_model.c) ──────────────────── */

static KosmoPasswordVerifyResult_t g_passwordVerifyResult;
static bool g_stopCalChecksum = false;
static UREncodeResult *g_urResult = NULL;
static PtrT_TransactionCheckResult g_checkResult = NULL;

#ifdef COMPILE_SIMULATOR
int32_t AsyncExecute(BackgroundAsyncFunc_t func, const void *inData, uint32_t inDataLen)
{
    func(inData, inDataLen);
    return SUCCESS_CODE;
}

int32_t AsyncExecuteRunnable(BackgroundAsyncFuncWithRunnable_t func, const void *inData, uint32_t inDataLen, BackgroundAsyncRunnable_t runnable)
{
    func(inData, inDataLen, runnable);
    return SUCCESS_CODE;
}
#endif

/* ── Model* forward declarations ────────────────────────── */

static int32_t ModelSaveWalletDesc(const void *inData, uint32_t inDataLen);
static int32_t ModelDelWallet(const void *inData, uint32_t inDataLen);
static int32_t ModelDelAllWallet(const void *inData, uint32_t inDataLen);
static int32_t ModelWritePassphrase(const void *inData, uint32_t inDataLen);
static int32_t ModelChangeAccountPass(const void *inData, uint32_t inDataLen);
static int32_t ModelVerifyAccountPass(const void *inData, uint32_t inDataLen);
static int32_t ModelGenerateEntropy(const void *inData, uint32_t inDataLen);
static int32_t ModelGenerateEntropyWithDiceRolls(const void *inData, uint32_t inDataLen);
static int32_t ModelBip39CalWriteEntropyAndSeed(const void *inData, uint32_t inDataLen);
static int32_t ModelWriteEntropyAndSeed(const void *inData, uint32_t inDataLen);
static int32_t ModelBip39VerifyMnemonic(const void *inData, uint32_t inDataLen);
static int32_t ModelGenerateSlip39Entropy(const void *inData, uint32_t inDataLen);
static int32_t ModelGenerateSlip39EntropyWithDiceRolls(const void *inData, uint32_t inDataLen);
static int32_t ModelSlip39CalWriteEntropyAndSeed(const void *inData, uint32_t inDataLen);
static int32_t ModeGetAccount(const void *inData, uint32_t inDataLen);
static int32_t ModeGetWalletDesc(const void *inData, uint32_t inDataLen);
static int32_t ModeControlQrDecode(const void *inData, uint32_t inDataLen);
static int32_t ModelSlip39WriteEntropy(const void *inData, uint32_t inDataLen);
static int32_t ModelComparePubkey(MnemonicType mnemonicType, uint8_t *ems, uint8_t emsLen, uint16_t id, bool eb, uint8_t ie, uint8_t *index);
static int32_t ModelBip39ForgetPass(const void *inData, uint32_t inDataLen);
static int32_t ModelSlip39ForgetPass(const void *inData, uint32_t inDataLen);
static int32_t ModelWriteLastLockDeviceTime(const void *inData, uint32_t inDataLen);
static int32_t ModelURGenerateQRCode(const void *indata, uint32_t inDataLen, BackgroundAsyncRunnable_t getUR);
static int32_t ModelCalculateCheckSum(const void *indata, uint32_t inDataLen);
static int32_t ModelCalculateBinSha256(const void *indata, uint32_t inDataLen);
static int32_t ModelURUpdate(const void *inData, uint32_t inDataLen);
static int32_t ModelURClear(const void *inData, uint32_t inDataLen);
static int32_t ModelCheckTransaction(const void *inData, uint32_t inDataLen);
static int32_t ModelTransactionCheckResultClear(const void *inData, uint32_t inDataLen);
static int32_t ModelParseTransaction(const void *indata, uint32_t inDataLen, BackgroundAsyncRunnable_t parseTransactionFunc);
static int32_t ModelFormatMicroSd(const void *indata, uint32_t inDataLen);
static int32_t ModelParseTransactionRawData(const void *inData, uint32_t inDataLen);
static int32_t ModelTransactionParseRawDataDelay(const void *inData, uint32_t inDataLen);
static int32_t ModelRsaGenerateKeyPair(const void *inData, uint32_t inDataLen);
static void ModelStopCalculateCheckSum(void);
static bool ModelGetPassphraseQuickAccess(void);
int32_t RsaGenerateKeyPair(bool needEmitSignal, int requestType);

/* ── ChainType 映射表 ───────────────────────────────── */

typedef struct {
    KosmoChainType kosmo;
    uint32_t xpubType;      /* 原 XPUB_TYPE_* 值 */
} ChainTypeMapping;

static const ChainTypeMapping g_chainTypeMap[] = {
    { KOSMO_CHAIN_BTC_LEGACY,        XPUB_TYPE_BTC_LEGACY },
    { KOSMO_CHAIN_BTC_SEGWIT,        XPUB_TYPE_BTC },
    { KOSMO_CHAIN_BTC_NATIVE_SEGWIT, XPUB_TYPE_BTC_NATIVE_SEGWIT },
    { KOSMO_CHAIN_BTC_TAPROOT,       XPUB_TYPE_BTC_TAPROOT },
    { KOSMO_CHAIN_LTC,               XPUB_TYPE_LTC },
    { KOSMO_CHAIN_DOGE,              XPUB_TYPE_DOGE },
    { KOSMO_CHAIN_DASH,              XPUB_TYPE_DASH },
    { KOSMO_CHAIN_BCH,               XPUB_TYPE_BCH },
    { KOSMO_CHAIN_ETH,               XPUB_TYPE_ETH_BIP44_STANDARD },
    { KOSMO_CHAIN_TRX,               XPUB_TYPE_TRX },
    { KOSMO_CHAIN_COSMOS,            XPUB_TYPE_COSMOS },
    { KOSMO_CHAIN_XRP,               XPUB_TYPE_XRP },
    { KOSMO_CHAIN_AVAX,              XPUB_TYPE_AVAX_BIP44_STANDARD },
    { KOSMO_CHAIN_IOTA,              XPUB_TYPE_IOTA_0 },
    { KOSMO_CHAIN_SOL,               XPUB_TYPE_SOL_BIP44_0 },
    { KOSMO_CHAIN_SUI,               XPUB_TYPE_SUI_0 },
    { KOSMO_CHAIN_APT,               XPUB_TYPE_APT_0 },
    { KOSMO_CHAIN_ADA,               XPUB_TYPE_ADA_0 },
    { KOSMO_CHAIN_ARWEAVE,           XPUB_TYPE_ARWEAVE },
    { KOSMO_CHAIN_STELLAR,           XPUB_TYPE_STELLAR_0 },
    { KOSMO_CHAIN_TON,               XPUB_TYPE_TON_BIP39 },
    { KOSMO_CHAIN_ZEC,               ZCASH_UFVK_ENCRYPTED_0 },
    { KOSMO_CHAIN_XMR,               XPUB_TYPE_MONERO_0 },
};

uint32_t KosmoChainToXPubType(KosmoChainType chain)
{
    for (int i = 0; i < sizeof(g_chainTypeMap) / sizeof(g_chainTypeMap[0]); i++) {
        if (g_chainTypeMap[i].kosmo == chain) {
            return g_chainTypeMap[i].xpubType;
        }
    }
    return XPUB_TYPE_NUM; /* not found */
}

/* ── 内部状态 ───────────────────────────────────────── */

typedef struct {
    KosmoCallback callback;
    bool persistent;
} KosmoCallbackSlot;

static KosmoCallbackSlot g_callbackSlots[KOSMO_REQ_NUM];

/* ── 初始化 ─────────────────────────────────────────── */

void KosmoApi_Init(void)
{
    memset(g_callbackSlots, 0, sizeof(g_callbackSlots));
}

/* ── 异步请求 ───────────────────────────────────────── */

#ifndef COMPILE_SIMULATOR
/*
 * FreeRTOS 路径：KosmoApi_NotifyResult 的异步投递上下文。
 * 堆分配 KosmoResult + 数据拷贝，确保 UI 线程消费时数据仍有效。
 */
typedef struct {
    KosmoCallback cb;
    KosmoResult result;
    uint8_t *dataCopy;   /* 堆拷贝的数据（可能为 NULL） */
} KosmoAsyncResultCtx;

/*
 * UI 线程执行：调用 callback 然后释放堆内存。
 */
static void kosmo_result_dispatch(void *arg)
{
    KosmoAsyncResultCtx *ctx = (KosmoAsyncResultCtx *)arg;
    ctx->result.data = ctx->dataCopy; /* 恢复 data 指针 */
    ctx->cb(&ctx->result);
    if (ctx->dataCopy != NULL) {
        vPortFree(ctx->dataCopy);
    }
    vPortFree(ctx);
}
#endif /* !COMPILE_SIMULATOR */

/*
 * KosmoApi_NotifyResult() — 后端结果回调入口
 *
 * Model* 函数完成操作后调用此函数，触发 UI 层注册的 callback。
 * 替代原来的 GuiApiEmitSignal() 全局广播。
 *
 * [Phase 2] FreeRTOS: 通过 ui_post_rpc_callback 投递到 UI 线程执行，
 *            堆拷贝数据保证生命周期安全。
 *            模拟器: 保持同步执行（同线程）。
 */
void KosmoApi_NotifyResult(KosmoRequestType type, int32_t errorCode, void *data, uint32_t dataLen)
{
    if (type >= KOSMO_REQ_NUM) return;

    KosmoCallbackSlot *slot = &g_callbackSlots[type];
    KosmoCallback cb = slot->callback;
    if (!slot->persistent) {
        slot->callback = NULL; /* 一次性：非持久 callback 清除 */
    }

    if (cb == NULL) return;

#ifndef COMPILE_SIMULATOR
    /* FreeRTOS: 堆分配上下文，投递到 UI 线程 */
    KosmoAsyncResultCtx *ctx = pvPortMalloc(sizeof(KosmoAsyncResultCtx));
    if (ctx == NULL) return;

    ctx->cb = cb;
    ctx->result.requestType = type;
    ctx->result.errorCode = errorCode;
    ctx->result.dataLen = dataLen;
    ctx->result.data = NULL;
    ctx->dataCopy = NULL;

    if (data != NULL && dataLen > 0) {
        ctx->dataCopy = pvPortMalloc(dataLen);
        if (ctx->dataCopy == NULL) {
            vPortFree(ctx);
            return;
        }
        memcpy(ctx->dataCopy, data, dataLen);
    }

    ui_post_rpc_callback(kosmo_result_dispatch, ctx);
#else
    /* 模拟器: 同步执行（同线程，无跨线程问题） */
    KosmoResult result = {
        .requestType = type,
        .errorCode = errorCode,
        .data = data,
        .dataLen = dataLen,
    };
    cb(&result);
#endif
}

/* KosmoApi_Request 实现在文件末尾（Phase 2 分发逻辑） */

void KosmoApi_RegisterCallback(KosmoRequestType type, KosmoCallback cb, bool persistent)
{
    if (type >= KOSMO_REQ_NUM) return;
    g_callbackSlots[type].callback = cb;
    g_callbackSlots[type].persistent = persistent;
}

void KosmoApi_ClearCallback(KosmoRequestType type)
{
    if (type >= KOSMO_REQ_NUM) return;
    g_callbackSlots[type].callback = NULL;
    g_callbackSlots[type].persistent = false;
}

/* ── 同步查询：账户 ─────────────────────────────────── */

int32_t KosmoApi_GetAccountInfo(KosmoAccountInfo *out)
{
    if (out == NULL) return KOSMO_ERR_INVALID;

    memset(out, 0, sizeof(*out));
    out->accountIndex = GetCurrentAccountIndex();
    out->iconIndex = GetWalletIconIndex();

    const char *name = GetWalletName();
    if (name != NULL) {
        strncpy(out->walletName, name, sizeof(out->walletName) - 1);
    }

    uint8_t *mfp = GetCurrentAccountMfp();
    if (mfp != NULL) {
        memcpy(out->mfp, mfp, 4);
    }

    MnemonicType mt = GetMnemonicType();
    switch (mt) {
    case MNEMONIC_TYPE_BIP39:  out->mnemonicType = KOSMO_MNEMONIC_BIP39; break;
    case MNEMONIC_TYPE_SLIP39: out->mnemonicType = KOSMO_MNEMONIC_SLIP39; break;
    case MNEMONIC_TYPE_TON:    out->mnemonicType = KOSMO_MNEMONIC_TON; break;
    }

    PasscodeType pt = GetPasscodeType();
    out->passcodeType = (pt == PASSCODE_TYPE_PIN) ? KOSMO_PASSCODE_PIN : KOSMO_PASSCODE_PASSWORD;

    out->passphraseMark = GetPassphraseMark();
    out->passphraseQuickAccess = GetPassphraseQuickAccess();

    return KOSMO_OK;
}

uint8_t KosmoApi_GetCurrentAccountIndex(void)
{
    return GetCurrentAccountIndex();
}

uint8_t KosmoApi_GetAccountCount(void)
{
    uint8_t count = 0;
    GetExistAccountNum(&count);
    return count;
}

/* ── 账户状态（account_public_info 包装）────────────── */

uint32_t KosmoApi_GetAccountReceiveIndex(const char *chainName)
{
    return GetAccountReceiveIndex(chainName);
}

void KosmoApi_SetAccountReceiveIndex(const char *chainName, uint32_t index)
{
    SetAccountReceiveIndex(chainName, index);
}

uint32_t KosmoApi_GetAccountReceivePath(const char *chainName)
{
    return GetAccountReceivePath(chainName);
}

void KosmoApi_SetAccountReceivePath(const char *chainName, uint32_t index)
{
    SetAccountReceivePath(chainName, index);
}

uint32_t KosmoApi_GetAccountIndex(const char *chainName)
{
    return GetAccountIndex(chainName);
}

void KosmoApi_SetAccountIndex(const char *chainName, uint32_t index)
{
    SetAccountIndex(chainName, index);
}

/* ── 种子/熵/密码（keystore 包装）───────────────────── */

int32_t KosmoApi_GetAccountSeed(uint8_t accountIndex, uint8_t *out, const char *password)
{
    return GetAccountSeed(accountIndex, out, password);
}

int32_t KosmoApi_GetAccountEntropy(uint8_t accountIndex, uint8_t *entropy, uint8_t *entropyLen, const char *password)
{
    return GetAccountEntropy(accountIndex, entropy, entropyLen, password);
}

char *KosmoApi_GetPassphrase(uint8_t accountIndex)
{
    return GetPassphrase(accountIndex);
}

/* ── SecretCache 包装 ─────────────────────────────────── */

const char *KosmoApi_CacheGetPassword(void)
{
    return SecretCacheGetPassword();
}

void KosmoApi_CacheSetPassword(const char *password)
{
    SecretCacheSetPassword((char *)password);
}

const char *KosmoApi_CacheGetMnemonic(void)
{
    return SecretCacheGetMnemonic();
}

void KosmoApi_CacheSetPassphrase(const char *passphrase)
{
    SecretCacheSetPassphrase(passphrase);
}

void KosmoApi_CacheGetChecksum(char *checksum)
{
    SecretCacheGetChecksum(checksum);
}

void KosmoApi_CacheSetWalletIndex(uint8_t index)
{
    SecretCacheSetWalletIndex(index);
}

void KosmoApi_CacheSetWalletName(const char *name)
{
    SecretCacheSetWalletName(name);
}

const char *KosmoApi_CacheGetNewPassword(void)
{
    return SecretCacheGetNewPassword();
}

void KosmoApi_CacheSetNewPassword(const char *password)
{
    SecretCacheSetNewPassword((char *)password);
}

uint32_t KosmoApi_CacheGetDiceRollsLen(void)
{
    return SecretCacheGetDiceRollsLen();
}

void KosmoApi_CacheSetMnemonic(const char *mnemonic)
{
    SecretCacheSetMnemonic((char *)mnemonic);
}

void KosmoApi_CacheSetEntropy(const uint8_t *entropy, uint32_t len)
{
    SecretCacheSetEntropy((uint8_t *)entropy, len);
}

void KosmoApi_CacheCleanSecretCache(void)
{
    ClearSecretCache();
}

void KosmoApi_CacheSetSlip39Mnemonic(char *mnemonic, int index)
{
    SecretCacheSetSlip39Mnemonic(mnemonic, index);
}

const char *KosmoApi_CacheGetSlip39Mnemonic(int index)
{
    return SecretCacheGetSlip39Mnemonic(index);
}

void KosmoApi_CacheSetDiceRollHash(uint8_t *hash)
{
    SecretCacheSetDiceRollHash(hash);
}

void KosmoApi_CacheSetDiceRollsLen(uint32_t len)
{
    SecretCacheSetDiceRollsLen(len);
}

/* ── 账户管理小函数 ───────────────────────────────────── */

void KosmoApi_GetExistAccountNum(uint8_t *count)
{
    GetExistAccountNum(count);
}

bool KosmoApi_GetPassphraseQuickAccess(void)
{
    return GetPassphraseQuickAccess();
}

/* ── 账户状态小函数 ───────────────────────────────────── */

bool KosmoApi_GetIsTempAccount(void)
{
    return GetIsTempAccount();
}

bool KosmoApi_GetFirstReceive(const char *chainName)
{
    return GetFirstReceive(chainName);
}

void KosmoApi_SetFirstReceive(const char *chainName, bool isFirst)
{
    SetFirstReceive(chainName, isFirst);
}

void KosmoApi_AccountPublicHomeCoinGet(void *walletList, uint8_t count)
{
    AccountPublicHomeCoinGet(walletList, count);
}

/* ── 同步查询：链信息 ───────────────────────────────── */

const char *KosmoApi_GetPublicKey(KosmoChainType chain)
{
    uint32_t xpubType = KosmoChainToXPubType(chain);
    if (xpubType == XPUB_TYPE_NUM) return NULL;
    return GetCurrentAccountPublicKey((ChainType)xpubType);
}

/*
 * 获取公钥（原始 ChainType 版本）。
 * 用于调用方已知内部 ChainType/XPUB_TYPE 的场景（如 UTXO 多地址、
 * GetXPubIndexByPath 等）。Phase 4 完成后应逐步迁移到 KosmoApi_GetPublicKeyByPath。
 */
const char *KosmoApi_GetPublicKeyRaw(uint32_t xpubType)
{
    return GetCurrentAccountPublicKey((ChainType)xpubType);
}

const char *KosmoApi_GetPublicKeyByPath(KosmoChainType chain, int pathIndex, int derivationType)
{
    uint32_t xpubType;

    switch (chain) {
    case KOSMO_CHAIN_ETH:
        if (pathIndex == 0)      xpubType = XPUB_TYPE_ETH_BIP44_STANDARD;
        else if (pathIndex == 1) xpubType = XPUB_TYPE_ETH_LEDGER_LEGACY;
        else if (pathIndex >= 2 && pathIndex <= 11)
            xpubType = XPUB_TYPE_ETH_LEDGER_LIVE_0 + (pathIndex - 2);
        else return NULL;
        break;

    case KOSMO_CHAIN_SOL:
        if (pathIndex >= 0 && pathIndex <= 49)
            xpubType = XPUB_TYPE_SOL_BIP44_0 + pathIndex;
        else if (pathIndex == 50)
            xpubType = XPUB_TYPE_SOL_BIP44_ROOT;
        else if (pathIndex >= 51 && pathIndex <= 100)
            xpubType = XPUB_TYPE_SOL_BIP44_CHANGE_0 + (pathIndex - 51);
        else return NULL;
        break;

    case KOSMO_CHAIN_AVAX:
        if (pathIndex == 0)      xpubType = XPUB_TYPE_AVAX_BIP44_STANDARD;
        else if (pathIndex >= 1 && pathIndex <= 10)
            xpubType = XPUB_TYPE_AVAX_X_P_0 + (pathIndex - 1);
        else return NULL;
        break;

    case KOSMO_CHAIN_ADA: {
        ChainType base = (derivationType == 0) ? XPUB_TYPE_ADA_0 : XPUB_TYPE_LEDGER_ADA_0;
        if (pathIndex < 0 || pathIndex > 23) pathIndex = 0;
        return GetCurrentAccountPublicKey((ChainType)(base + pathIndex));
    }

    case KOSMO_CHAIN_SUI:
        if (pathIndex < 0 || pathIndex > 9) return NULL;
        return GetCurrentAccountPublicKey((ChainType)(XPUB_TYPE_SUI_0 + pathIndex));

    case KOSMO_CHAIN_IOTA:
        if (pathIndex < 0 || pathIndex > 9) return NULL;
        return GetCurrentAccountPublicKey((ChainType)(XPUB_TYPE_IOTA_0 + pathIndex));

    case KOSMO_CHAIN_APT:
        if (pathIndex < 0 || pathIndex > 9) return NULL;
        return GetCurrentAccountPublicKey((ChainType)(XPUB_TYPE_APT_0 + pathIndex));

    case KOSMO_CHAIN_STELLAR:
        if (pathIndex < 0 || pathIndex > 9) return NULL;
        return GetCurrentAccountPublicKey((ChainType)(XPUB_TYPE_STELLAR_0 + pathIndex));

    case KOSMO_CHAIN_XMR:
        if (pathIndex == 0) return GetCurrentAccountPublicKey((ChainType)XPUB_TYPE_MONERO_0);
        if (pathIndex == 1) return GetCurrentAccountPublicKey((ChainType)XPUB_TYPE_MONERO_PVK_0);
        return NULL;

    default:
        /* 单路径链：忽略 pathIndex，退化为 GetPublicKey */
        return KosmoApi_GetPublicKey(chain);
    }

    return GetCurrentAccountPublicKey((ChainType)xpubType);
}

const char *KosmoApi_GetPath(KosmoChainType chain)
{
    uint32_t xpubType = KosmoChainToXPubType(chain);
    if (xpubType == XPUB_TYPE_NUM) return NULL;
    return GetCurrentAccountPath((ChainType)xpubType);
}

int32_t KosmoApi_GetSeed(uint8_t *out, uint32_t *outLen)
{
    if (out == NULL || outLen == NULL) return KOSMO_ERR_INVALID;

    uint8_t accountIdx = GetCurrentAccountIndex();
    const char *password = SecretCacheGetPassword();
    if (password == NULL) return KOSMO_ERR_INVALID;

    int32_t ret = GetAccountSeed(accountIdx, out, password);
    if (ret != 0) return KOSMO_ERR_GENERAL;

    /* BIP39: 64 字节 seed; TON: entropy 长度 */
    MnemonicType mt = GetMnemonicType();
    if (mt == MNEMONIC_TYPE_TON) {
        *outLen = GetCurrentAccountEntropyLen();
    } else {
        *outLen = GetCurrentAccountSeedLen();
    }
    return KOSMO_OK;
}

KosmoMnemonicType KosmoApi_GetMnemonicType(void)
{
    MnemonicType mt = GetMnemonicType();
    switch (mt) {
    case MNEMONIC_TYPE_SLIP39: return KOSMO_MNEMONIC_SLIP39;
    case MNEMONIC_TYPE_TON:    return KOSMO_MNEMONIC_TON;
    default:                   return KOSMO_MNEMONIC_BIP39;
    }
}

uint32_t KosmoApi_GetSeedLen(void)
{
    return GetCurrentAccountSeedLen();
}

uint32_t KosmoApi_GetEntropyLen(void)
{
    return GetCurrentAccountEntropyLen();
}

bool KosmoApi_IsMoneroSupported(void)
{
    return IsMoneroSupportedForCurrentMnemonic();
}

bool KosmoApi_IsZcashSupported(void)
{
    return IsZcashSupportedForCurrentMnemonic();
}

int32_t KosmoApi_GetBip39Word(int index, char *word, int len)
{
    if (word == NULL || index < 0 || index > 2047) return KOSMO_ERR_INVALID;

    struct words *w = NULL;
    bip39_get_wordlist(NULL, &w);
    if (w == NULL) return KOSMO_ERR_GENERAL;

    const char *result = wordlist_lookup_index(w, index);
    if (result == NULL) return KOSMO_ERR_GENERAL;

    strncpy(word, result, len - 1);
    word[len - 1] = '\0';
    return KOSMO_OK;
}

int32_t KosmoApi_ValidateWord(const char *word, int *index)
{
    if (word == NULL || index == NULL) return KOSMO_ERR_INVALID;

    struct words *w = NULL;
    bip39_get_wordlist(NULL, &w);
    if (w == NULL) return KOSMO_ERR_GENERAL;

    size_t idx = wordlist_lookup_word(w, word);
    if (idx == 0) return KOSMO_ERR_INVALID;  /* 0 = not found */

    *index = (int)idx;
    return KOSMO_OK;
}

KosmoChainType KosmoApi_CheckSolPathSupport(const char *path)
{
    if (path == NULL) return KOSMO_CHAIN_NUM;

    ChainType result = CheckSolPathSupport((char *)path);
    /* 将 XPUB_TYPE_SOL_BIP44_* 映射回 KOSMO_CHAIN_SOL */
    if (result >= XPUB_TYPE_SOL_BIP44_0 && result <= XPUB_TYPE_SOL_BIP44_49) {
        return KOSMO_CHAIN_SOL;
    }
    return KOSMO_CHAIN_NUM;
}

void KosmoApi_GetHomeCoinList(void *walletList, uint8_t count)
{
    /* Phase 1: 直接包装，后续改为独立实现 */
    AccountPublicHomeCoinGet((WalletState_t *)walletList, count);
}

int32_t KosmoApi_GetZcashSFP(uint8_t accountIndex, uint8_t *outSFP)
{
    return GetZcashSFP(accountIndex, outSFP);
}

int32_t KosmoApi_GetZcashUFVK(uint8_t accountIndex, char *outUFVK)
{
    return GetZcashUFVK(accountIndex, outUFVK);
}

/* ── Phase 2: 异步请求统一分发 ──────────────────────── */

/*
 * KosmoApi_Request() — 异步请求入口
 *
 * 前端调用此函数发起请求，结果通过 callback 返回。
 * 真机：投递到 FetchSensitiveDataTask 队列。
 * 模拟器：同步执行。
 *
 * callback 在 UI 线程执行（通过 KosmoApi_NotifyResult → ui_post_rpc_callback）。
 */
int32_t KosmoApi_Request(const KosmoRequest *request, KosmoCallback cb)
{
    if (request == NULL) return KOSMO_ERR_INVALID;

    /* 存储 callback（cb=NULL 时保留已有 callback，不清除） */
    if (request->type < KOSMO_REQ_NUM && cb != NULL) {
        g_callbackSlots[request->type].callback = cb;
        g_callbackSlots[request->type].persistent = request->persistent;
    }

    switch (request->type) {
    /* ── 助记词 / 钱包创建 ─────────────────────────── */
    case KOSMO_REQ_BIP39_GENERATE_ENTROPY: {
        static uint32_t s_mnemonicNum;
        s_mnemonicNum = request->bip39_generate.wordCnt;
        AsyncExecute(ModelGenerateEntropy, &s_mnemonicNum, sizeof(s_mnemonicNum));
        return KOSMO_OK;
    }
    case KOSMO_REQ_BIP39_WRITE_SE: {
        static Bip39Data_t s_bip39Data;
        s_bip39Data.wordCnt = request->bip39_write_se.wordCnt;
        s_bip39Data.forget = request->bip39_write_se.forget;
        AsyncExecute(ModelBip39CalWriteEntropyAndSeed, &s_bip39Data, sizeof(s_bip39Data));
        return KOSMO_OK;
    }
    case KOSMO_REQ_BIP39_VERIFY_MNEMONIC: {
        static uint8_t s_wordsCnt;
        s_wordsCnt = request->bip39_verify.wordCnt;
        AsyncExecute(ModelBip39VerifyMnemonic, &s_wordsCnt, sizeof(s_wordsCnt));
        return KOSMO_OK;
    }
    case KOSMO_REQ_BIP39_UPDATE_MNEMONIC: {
        static uint32_t s_mnemonicNum;
        s_mnemonicNum = request->bip39_update.wordCnt;
        AsyncExecute(ModelGenerateEntropy, &s_mnemonicNum, sizeof(s_mnemonicNum));
        return KOSMO_OK;
    }
    case KOSMO_REQ_BIP39_UPDATE_MNEMONIC_DICE: {
        static uint32_t s_mnemonicNum;
        s_mnemonicNum = request->bip39_update_dice.wordCnt;
        AsyncExecute(ModelGenerateEntropyWithDiceRolls, &s_mnemonicNum, sizeof(s_mnemonicNum));
        return KOSMO_OK;
    }
    case KOSMO_REQ_BIP39_FORGET_PASSWORD: {
        static uint8_t s_wordsCnt;
        s_wordsCnt = request->bip39_forget.wordCnt;
        AsyncExecute(ModelBip39ForgetPass, &s_wordsCnt, sizeof(s_wordsCnt));
        return KOSMO_OK;
    }
    case KOSMO_REQ_SLIP39_GENERATE_ENTROPY: {
        static Slip39Data_t s_slip39;
        s_slip39.threShold = request->slip39_generate.threshold;
        s_slip39.memberCnt = request->slip39_generate.memberCnt;
        s_slip39.wordCnt = request->slip39_generate.wordCnt;
        s_slip39.forget = request->slip39_generate.forget;
        ui_post_notification(SIG_SHOW_LOADING_ANIMATION, 0);
        AsyncExecute(ModelGenerateSlip39Entropy, &s_slip39, sizeof(s_slip39));
        return KOSMO_OK;
    }
    case KOSMO_REQ_SLIP39_WRITE_SE: {
        static uint8_t s_wordsCnt;
        s_wordsCnt = request->slip39_write_se.wordCnt;
        ui_post_notification(SIG_SHOW_LOADING_ANIMATION, 0);
        AsyncExecute(ModelSlip39WriteEntropy, &s_wordsCnt, sizeof(s_wordsCnt));
        return KOSMO_OK;
    }
    case KOSMO_REQ_SLIP39_CAL_WRITE_SE: {
        static Slip39Data_t s_slip39;
        s_slip39.threShold = request->slip39_cal_write.threshold;
        s_slip39.memberCnt = request->slip39_cal_write.memberCnt;
        s_slip39.wordCnt = request->slip39_cal_write.wordCnt;
        s_slip39.forget = request->slip39_cal_write.forget;
        AsyncExecute(ModelSlip39CalWriteEntropyAndSeed, &s_slip39, sizeof(s_slip39));
        return KOSMO_OK;
    }
    case KOSMO_REQ_SLIP39_UPDATE_MNEMONIC: {
        static Slip39Data_t s_slip39;
        s_slip39.threShold = request->slip39_update.threshold;
        s_slip39.memberCnt = request->slip39_update.memberCnt;
        s_slip39.wordCnt = request->slip39_update.wordCnt;
        ui_post_notification(SIG_SHOW_LOADING_ANIMATION, 0);
        AsyncExecute(ModelGenerateSlip39Entropy, &s_slip39, sizeof(s_slip39));
        return KOSMO_OK;
    }
    case KOSMO_REQ_SLIP39_UPDATE_MNEMONIC_DICE: {
        static Slip39Data_t s_slip39;
        s_slip39.threShold = request->slip39_update_dice.threshold;
        s_slip39.memberCnt = request->slip39_update_dice.memberCnt;
        s_slip39.wordCnt = request->slip39_update_dice.wordCnt;
        ui_post_notification(SIG_SHOW_LOADING_ANIMATION, 0);
        AsyncExecute(ModelGenerateSlip39EntropyWithDiceRolls, &s_slip39, sizeof(s_slip39));
        return KOSMO_OK;
    }
    case KOSMO_REQ_SLIP39_FORGET_PASSWORD: {
        static Slip39Data_t s_slip39;
        s_slip39.threShold = request->slip39_forget.threshold;
        s_slip39.memberCnt = request->slip39_forget.memberCnt;
        s_slip39.wordCnt = request->slip39_forget.wordCnt;
        s_slip39.forget = request->slip39_forget.forget;
        AsyncExecute(ModelSlip39ForgetPass, &s_slip39, sizeof(s_slip39));
        return KOSMO_OK;
    }
    case KOSMO_REQ_WRITE_SE: {
        ui_post_notification(SIG_SHOW_LOADING_ANIMATION, 0);
        AsyncExecute(ModelWriteEntropyAndSeed, NULL, 0);
        return KOSMO_OK;
    }

    /* ── 账户管理 ─────────────────────────────────── */
    case KOSMO_REQ_GET_ACCOUNT: {
        AsyncExecute(ModeGetAccount, NULL, 0);
        return KOSMO_OK;
    }
    case KOSMO_REQ_GET_WALLET_DESC: {
        AsyncExecute(ModeGetWalletDesc, NULL, 0);
        return KOSMO_OK;
    }
    case KOSMO_REQ_SAVE_WALLET_DESC: {
        static WalletDesc_t s_walletDesc;
        s_walletDesc.iconIndex = request->save_wallet_desc.iconIndex;
        strncpy(s_walletDesc.name, request->save_wallet_desc.name, WALLET_NAME_MAX_LEN);
        s_walletDesc.name[WALLET_NAME_MAX_LEN] = '\0';
        AsyncExecute(ModelSaveWalletDesc, &s_walletDesc, sizeof(s_walletDesc));
        return KOSMO_OK;
    }
    case KOSMO_REQ_DEL_WALLET_DESC: {
        AsyncExecute(ModelDelWallet, NULL, 0);
        return KOSMO_OK;
    }
    case KOSMO_REQ_DEL_ALL_WALLET_DESC: {
        AsyncExecute(ModelDelAllWallet, NULL, 0);
        return KOSMO_OK;
    }
    case KOSMO_REQ_WRITE_PASSPHRASE: {
        AsyncExecute(ModelWritePassphrase, NULL, 0);
        return KOSMO_OK;
    }
    case KOSMO_REQ_CHANGE_PASSWORD: {
        AsyncExecute(ModelChangeAccountPass, NULL, 0);
        return KOSMO_OK;
    }
    case KOSMO_REQ_VERIFY_PASSWORD: {
        static uint16_t s_param;
        s_param = request->verify_password.signalId;
        AsyncExecute(ModelVerifyAccountPass, &s_param, sizeof(s_param));
        return KOSMO_OK;
    }
    case KOSMO_REQ_WRITE_LOCK_TIME: {
        static uint32_t s_lockTime;
        s_lockTime = request->uint32_param.value;
        AsyncExecute(ModelWriteLastLockDeviceTime, &s_lockTime, sizeof(s_lockTime));
        return KOSMO_OK;
    }

    /* ── 系统操作 ─────────────────────────────────── */
    case KOSMO_REQ_CALCULATE_CHECKSUM: {
        SetPageLockScreen(false);
        AsyncExecute(ModelCalculateCheckSum, NULL, 0);
        return KOSMO_OK;
    }
    case KOSMO_REQ_STOP_CHECKSUM: {
        SetPageLockScreen(true);
        ModelStopCalculateCheckSum();
        return KOSMO_OK;
    }
    case KOSMO_REQ_CALCULATE_SHA256: {
        SetPageLockScreen(false);
        AsyncExecute(ModelCalculateBinSha256, NULL, 0);
        return KOSMO_OK;
    }
    case KOSMO_REQ_FORMAT_SD_CARD: {
        SetPageLockScreen(false);
        AsyncExecute(ModelFormatMicroSd, NULL, 0);
        return KOSMO_OK;
    }
    case KOSMO_REQ_CONTROL_QR_DECODE: {
        static bool s_en;
        s_en = request->bool_param.enable;
        AsyncExecute(ModeControlQrDecode, &s_en, sizeof(s_en));
        return KOSMO_OK;
    }

    /* ── UR 操作 ──────────────────────────────────── */
    case KOSMO_REQ_UR_GENERATE_QR: {
        /* GenerateUR 函数指针通过 raw_ptr 传入 */
        AsyncExecuteRunnable(ModelURGenerateQRCode, NULL, 0,
                             (BackgroundAsyncRunnable_t)request->raw_ptr.ptr);
        return KOSMO_OK;
    }
    case KOSMO_REQ_UR_UPDATE: {
        AsyncExecute(ModelURUpdate, NULL, 0);
        return KOSMO_OK;
    }
    case KOSMO_REQ_UR_CLEAR: {
        AsyncExecute(ModelURClear, NULL, 0);
        return KOSMO_OK;
    }

    /* ── 交易 ─────────────────────────────────────── */
    case KOSMO_REQ_CHECK_TRANSACTION: {
        static ViewType s_viewType;
        s_viewType = (ViewType)request->view_type.viewType;
        AsyncExecute(ModelCheckTransaction, &s_viewType, sizeof(s_viewType));
        return KOSMO_OK;
    }
    case KOSMO_REQ_CLEAR_CHECK_RESULT: {
        AsyncExecute(ModelTransactionCheckResultClear, NULL, 0);
        return KOSMO_OK;
    }
    case KOSMO_REQ_PARSE_TRANSACTION: {
        /* ReturnVoidPointerFunc 通过 raw_ptr 传入 */
        AsyncExecuteRunnable(ModelParseTransaction, NULL, 0,
                             (BackgroundAsyncRunnable_t)request->raw_ptr.ptr);
        return KOSMO_OK;
    }
    case KOSMO_REQ_PARSE_TRANSACTION_RAW: {
        AsyncExecute(ModelParseTransactionRawData, NULL, 0);
        return KOSMO_OK;
    }
    case KOSMO_REQ_PARSE_TRANSACTION_RAW_DELAY: {
        AsyncExecute(ModelTransactionParseRawDataDelay, NULL, 0);
        return KOSMO_OK;
    }

    /* ── RSA ──────────────────────────────────────── */
    case KOSMO_REQ_RSA_GENERATE_KEYPAIR: {
        AsyncExecute(ModelRsaGenerateKeyPair, NULL, 0);
        return KOSMO_OK;
    }

    default:
        return KOSMO_ERR_INVALID;
    }
}


/* ═══════════════════════════════════════════════════════════
 * Phase 8: ConnectWallet 状态管理 + 地址生成包装
 * ═══════════════════════════════════════════════════════════ */


/* ── ConnectWallet 状态 ──────────────────────────────── */

uint32_t KosmoApi_GetConnectWalletPathIndex(const char *walletName) {
    return GetConnectWalletPathIndex(walletName);
}

void KosmoApi_SetConnectWalletPathIndex(const char *walletName, uint32_t index) {
    SetConnectWalletPathIndex(walletName, index);
}

uint32_t KosmoApi_GetConnectWalletAccountIndex(const char *walletName) {
    return GetConnectWalletAccountIndex(walletName);
}

void KosmoApi_SetConnectWalletAccountIndex(const char *walletName, uint32_t index) {
    SetConnectWalletAccountIndex(walletName, index);
}

uint32_t KosmoApi_GetConnectWalletNetwork(const char *walletName) {
    return GetConnectWalletNetwork(walletName);
}

void KosmoApi_SetConnectWalletNetwork(const char *walletName, uint32_t network) {
    SetConnectWalletNetwork(walletName, network);
}

const char *KosmoApi_GetWalletName(void) {
    return GetWalletName();
}

const char *KosmoApi_GetWalletNameByIndex(uint8_t index) {
    return GetWalletNameByIndex(index);
}

/* ── 地址生成 ────────────────────────────────────────── */

char *KosmoApi_GetXrpAddressByIndex(uint16_t index) {
    return GuiGetXrpAddressByIndex(index);
}

char *KosmoApi_GetAdaBaseAddressByXPub(char *xpub) {
    return GuiGetADABaseAddressByXPub(xpub);
}

UREncodeResult *KosmoApi_GetKeplrDataByIndex(uint32_t index) {
    return GuiGetKeplrDataByIndex(index);
}

UREncodeResult *KosmoApi_GetAdaDataByIndex(const char *walletName) {
    return GuiGetADADataByIndex((char *)walletName);
}

UREncodeResult *KosmoApi_GetXrpToolkitDataByIndex(uint16_t index) {
    return GuiGetXrpToolkitDataByIndex(index);
}

UREncodeResult *KosmoApi_GetTonkeeperWalletUr(const char *xpub, const char *walletName,
                                               const char *mfp, uint32_t mfpLen, const char *path) {
    return get_tonkeeper_wallet_ur((char *)xpub, (char *)walletName, (char *)mfp, mfpLen, (char *)path);
}

UREncodeResult *KosmoApi_GetFewchaData(bool isSui) {
    return GuiGetFewchaDataByCoin(isSui ? CHAIN_SUI : CHAIN_APT);
}

/* ═══════════════════════════════════════════════════════════
 * Phase 9: 链操作工具函数包装
 * ═══════════════════════════════════════════════════════════ */

GuiChainCoinType KosmoApi_ViewTypeToChainTypeSwitch(uint8_t viewType) {
    return ViewTypeToChainTypeSwitch(viewType);
}

void *KosmoApi_GetUrGenerator(uint8_t viewType) {
    return (void *)GetUrGenerator(viewType);
}

void *KosmoApi_GetSingleUrGenerator(uint8_t viewType) {
    return (void *)GetSingleUrGenerator(viewType);
}

bool KosmoApi_IsMessageType(uint8_t type) {
    return IsMessageType(type);
}

bool KosmoApi_IsTonSignProof(uint8_t type) {
    return isTonSignProof(type);
}

bool KosmoApi_IsCatalystVotingRegistration(uint8_t type) {
    return isCatalystVotingRegistration(type);
}

uint32_t KosmoApi_GetAdaXPubType(void) {
    return (uint32_t)GetAdaXPubType();
}

/* ═══════════════════════════════════════════════════════════
 * Phase 10: BIP39 包装
 * ═══════════════════════════════════════════════════════════ */

int32_t KosmoApi_Bip39MnemonicFromBytes(const uint8_t *entropy, uint32_t entropyLen, char **outMnemonic) {
    return bip39_mnemonic_from_bytes(NULL, (uint8_t *)entropy, entropyLen, outMnemonic);
}

/* ═══════════════════════════════════════════════════════════
 * Phase 17: Rust FFI 包装
 * ═══════════════════════════════════════════════════════════ */

UREncodeResult *KosmoApi_EthSignBatchTx(void *data, const uint8_t *seed, uint32_t seedLen)
{
    return eth_sign_batch_tx((PtrUR)data, (PtrBytes)seed, seedLen);
}

void KosmoApi_FreeSimpleResponseCChar(void *ptr)
{
    free_simple_response_c_char((PtrT_SimpleResponse_c_char)ptr);
}

int KosmoApi_CardanoGetAddress(const char *xPub, uint32_t index, uint8_t type, char *addrOut, uint32_t addrOutLen)
{
    SimpleResponse_c_char *result = NULL;
    switch (type) {
    case 1:
        result = cardano_get_enterprise_address(xPub, 0, 1);
        break;
    case 2:
        result = cardano_get_stake_address(xPub, 0, 1);
        break;
    default:
        result = cardano_get_base_address(xPub, 0, 1);
        break;
    }
    if (result == NULL || result->data == NULL) {
        return -1;
    }
    strncpy(addrOut, result->data, addrOutLen - 1);
    addrOut[addrOutLen - 1] = '0';
    free_simple_response_c_char(result);
    return 0;
}

void KosmoApi_FreeUrEncodeResult(void *ptr)
{
    free_ur_encode_result((PtrT_UREncodeResult)ptr);
}

void KosmoApi_FreeUrParseMultiResult(void *ptr)
{
    free_ur_parse_multi_result((PtrT_URParseMultiResult)ptr);
}

void KosmoApi_FreeUrParseResult(void *ptr)
{
    free_ur_parse_result((PtrT_URParseResult)ptr);
}

void *KosmoApi_ParseDeriveContextHash(void *ur)
{
    return parse_derive_context_hash((PtrUR)ur);
}

void *KosmoApi_ParseQrHardwareCall(void *ur)
{
    return parse_qr_hardware_call((PtrUR)ur);
}

/* =================================================================
 * Model and Mode execution functions (merged from gui_model.c in Phase 21.3)
 * ================================================================= */

static void ModelStopCalculateCheckSum(void)
{
    g_stopCalChecksum = true;
}

// bip39 generate
static int32_t ModelGenerateEntropy(const void *inData, uint32_t inDataLen)
{
    bool enable = IsPreviousLockScreenEnable();
    SetLockScreen(false);
    int32_t ret = ERR_GENERAL_FAIL;
    char *mnemonic = NULL;
    uint8_t entropy[32];
    uint32_t mnemonicNum = 0, entropyLen = 0;

    if (inData == NULL) {
        goto cleanup;
    }
    mnemonicNum = *((const uint32_t *)inData);
    if (mnemonicNum == 24) {
        entropyLen = 32;
    } else if (mnemonicNum == 12) {
        entropyLen = 16;
    } else {
        ret = ERR_GENERAL_FAIL;
        goto cleanup;
    }
    const char *pwd = SecretCacheGetNewPassword();
    if (pwd == NULL || strnlen_s(pwd, PASSWORD_MAX_LEN) == 0) {
        ret = ERR_GENERAL_FAIL;
        goto cleanup;
    }

    do {
        ret = GenerateEntropy(entropy, entropyLen, pwd);
        CHECK_ERRCODE_BREAK("generate entropy", ret);

        ret = bip39_mnemonic_from_bytes(NULL, entropy, entropyLen, &mnemonic);
        CHECK_ERRCODE_BREAK("generate mnemonic", ret);

        SecretCacheSetEntropy(entropy, entropyLen);
        SecretCacheSetMnemonic(mnemonic);
    } while (0);

cleanup:
    if (mnemonic != NULL) {
        memset_s(mnemonic, strnlen_s(mnemonic, MNEMONIC_MAX_LEN), 0, strnlen_s(mnemonic, MNEMONIC_MAX_LEN));
        SRAM_FREE(mnemonic);
    }
    if (ret != SUCCESS_CODE) {
        KosmoApi_NotifyResult(KOSMO_REQ_BIP39_UPDATE_MNEMONIC, ret, NULL, 0);
    } else {
        KosmoApi_NotifyResult(KOSMO_REQ_BIP39_UPDATE_MNEMONIC, SUCCESS_CODE, NULL, 0);
    }
    CLEAR_ARRAY(entropy);
    SetLockScreen(enable);
    return ret;
}

static int32_t ModelGenerateEntropyWithDiceRolls(const void *inData, uint32_t inDataLen)
{
    bool enable = IsPreviousLockScreenEnable();
    SetLockScreen(false);
    int32_t ret = SUCCESS_CODE;
    char *mnemonic = NULL;
    uint8_t entropy[32];
    uint8_t *hash = NULL;
    uint32_t mnemonicNum, entropyLen;
    mnemonicNum = *((uint32_t *)inData);

    do {
        if (mnemonicNum != 12 && mnemonicNum != 24) {
            ret = ERR_GENERAL_FAIL;
            break;
        }
        if (mnemonicNum == 24 && SecretCacheGetDiceRollsLen() < 100) {
            ret = ERR_GENERAL_FAIL;
            break;
        }
        entropyLen = (mnemonicNum == 24) ? 32 : 16;
        hash = SecretCacheGetDiceRollHash();
        memcpy_s(entropy, sizeof(entropy), hash, entropyLen);
        SecretCacheSetEntropy(entropy, entropyLen);

        ret = bip39_mnemonic_from_bytes(NULL, entropy, entropyLen, &mnemonic);
        CHECK_ERRCODE_BREAK("generate mnemonic", ret);

        SecretCacheSetMnemonic(mnemonic);
    } while (0);

    if (mnemonic != NULL) {
        size_t mlen = strnlen_s(mnemonic, MNEMONIC_MAX_LEN);
        memset_s(mnemonic, mlen, 0, mlen);
        SRAM_FREE(mnemonic);
    }
    if (ret == SUCCESS_CODE) {
        KosmoApi_NotifyResult(KOSMO_REQ_BIP39_UPDATE_MNEMONIC_DICE, SUCCESS_CODE, NULL, 0);
    } else {
        KosmoApi_NotifyResult(KOSMO_REQ_BIP39_UPDATE_MNEMONIC_DICE, ret, NULL, 0);
    }
    CLEAR_ARRAY(entropy);
    SetLockScreen(enable);
    return ret;
}

static int32_t ModelParseTransactionRawData(const void *inData, uint32_t inDataLen)
{
    UserDelay(100);
    KosmoApi_NotifyResult(KOSMO_REQ_PARSE_TRANSACTION_RAW, KOSMO_OK, NULL, 0);
    return SUCCESS_CODE;
}

static int32_t ModelTransactionParseRawDataDelay(const void *inData, uint32_t inDataLen)
{
    KosmoApi_NotifyResult(KOSMO_REQ_PARSE_TRANSACTION_RAW_DELAY, KOSMO_OK, NULL, 0);
    return SUCCESS_CODE;
}

// Generate bip39 wallet writes
static int32_t ModelWriteEntropyAndSeed(const void *inData, uint32_t inDataLen)
{
    bool enable = IsPreviousLockScreenEnable();
    SetLockScreen(false);
    int32_t ret;
    uint8_t *entropy, *entropyCheck;
    uint32_t entropyLen;
    uint8_t newAccount;
    uint8_t accountCnt;
    size_t entropyOutLen;

    entropy = SecretCacheGetEntropy(&entropyLen);
    entropyCheck = SRAM_MALLOC(entropyLen);
    ret = bip39_mnemonic_to_bytes(NULL, SecretCacheGetMnemonic(), entropyCheck, entropyLen, &entropyOutLen);
    if (memcmp(entropyCheck, entropy, entropyLen) != 0) {
        memset_s(entropyCheck, entropyLen, 0, entropyLen);
        SRAM_FREE(entropyCheck);
        SetLockScreen(enable);
        return 0;
    }
    memset_s(entropyCheck, entropyLen, 0, entropyLen);
    SRAM_FREE(entropyCheck);
    MODEL_WRITE_SE_HEAD
    ret = ModelComparePubkey(MNEMONIC_TYPE_BIP39, NULL, 0, 0, false, 0, NULL);
    CHECK_ERRCODE_BREAK("duplicated entropy", ret);
    ret = CreateNewAccount(newAccount, entropy, entropyLen, SecretCacheGetNewPassword());
    ClearAccountPassphrase(newAccount);
    if (strnlen_s(SecretCacheGetPassphrase(), PASSPHRASE_MAX_LEN) > 0) {
        ret = SetPassphrase(GetCurrentAccountIndex(), SecretCacheGetPassphrase(), SecretCacheGetNewPassword());
        CHECK_ERRCODE_BREAK("set passphrase error", ret);
        SetPassphraseQuickAccess(g_ui_passphrase_quick_access);
    }
    MODEL_WRITE_SE_END(KOSMO_REQ_WRITE_SE)
    SetLockScreen(enable);
    return 0;
}

// Import of mnemonic words for bip39
static int32_t ModelBip39CalWriteEntropyAndSeed(const void *inData, uint32_t inDataLen)
{
    bool enable = IsPreviousLockScreenEnable();
    SetLockScreen(false);
    int32_t ret = SUCCESS_CODE;
    uint8_t *entropy = NULL;
    size_t entropyInLen;
    size_t entropyOutLen;
    Bip39Data_t *bip39Data = (Bip39Data_t *)inData;
    uint8_t newAccount = 0;
    uint8_t accountCnt = 0;
    AccountInfo_t accountInfo = {0};

    entropyInLen = bip39Data->wordCnt * 16 / 12;
    entropy = SRAM_MALLOC(entropyInLen);

    MODEL_WRITE_SE_HEAD
    ret = bip39_mnemonic_to_bytes(NULL, SecretCacheGetMnemonic(), entropy, entropyInLen, &entropyOutLen);
    CHECK_ERRCODE_BREAK("mnemonic error", ret);
    if (bip39Data->forget) {
        ret = ModelComparePubkey(MNEMONIC_TYPE_BIP39, NULL, 0, 0, false, 0, &newAccount);
        CHECK_ERRCODE_BREAK("mnemonic not match", !ret);
    } else {
        ret = ModelComparePubkey(MNEMONIC_TYPE_BIP39, NULL, 0, 0, false, 0, NULL);
        CHECK_ERRCODE_BREAK("mnemonic repeat", ret);
    }
    if (bip39Data->forget) {
        ret = GetAccountInfo(newAccount, &accountInfo);
        CHECK_ERRCODE_BREAK("get account info error", ret);
    }
    ret = CreateNewAccount(newAccount, entropy, (uint8_t)entropyOutLen, SecretCacheGetNewPassword());
    CHECK_ERRCODE_BREAK("save entropy error", ret);
    ClearAccountPassphrase(newAccount);
    if (strnlen_s(SecretCacheGetPassphrase(), PASSPHRASE_MAX_LEN) > 0) {
        ret = SetPassphrase(GetCurrentAccountIndex(), SecretCacheGetPassphrase(), SecretCacheGetNewPassword());
        CHECK_ERRCODE_BREAK("set passphrase error", ret);
        SetPassphraseQuickAccess(g_ui_passphrase_quick_access);
    }
    ret = VerifyPasswordAndLogin(&newAccount, SecretCacheGetNewPassword());
    CHECK_ERRCODE_BREAK("login error", ret);
    UpdateFingerSignFlag(GetCurrentAccountIndex(), false);
    if (bip39Data->forget) {
        SetWalletName(accountInfo.walletName);
        SetWalletIconIndex(accountInfo.iconIndex);
        LogoutCurrentAccount();
        CloseUsb();
    }
    GetExistAccountNum(&accountCnt);
}
while (0);
if (ret == SUCCESS_CODE)
{
    ClearSecretCache();
    KosmoApi_NotifyResult(KOSMO_REQ_BIP39_WRITE_SE, SUCCESS_CODE, NULL, 0);
} else
{
    KosmoApi_NotifyResult(KOSMO_REQ_BIP39_WRITE_SE, ret, NULL, 0);
}
memset_s(entropy, entropyInLen, 0, entropyInLen);
memset_s(&accountInfo, sizeof(accountInfo), 0, sizeof(accountInfo));
SRAM_FREE(entropy);
SetLockScreen(enable);
return 0;
}

// Auxiliary word verification for bip39
static int32_t ModelBip39VerifyMnemonic(const void *inData, uint32_t inDataLen)
{
    bool enable = IsPreviousLockScreenEnable();
    SetLockScreen(false);
    int32_t ret = SUCCESS_CODE;
    SimpleResponse_c_char *xPubResult;
    uint8_t seed[64];

    do {
        ret = bip39_mnemonic_to_seed(SecretCacheGetMnemonic(), NULL, seed, 64, NULL);
        xPubResult = get_extended_pubkey_by_seed(seed, 64, "M/49'/0'/0'");
        if (xPubResult->error_code != 0) {
            free_simple_response_c_char(xPubResult);
            break;
        }
        CLEAR_ARRAY(seed);
        char *xpub = GetCurrentAccountPublicKey(XPUB_TYPE_BTC);
        if (!strcmp(xpub, xPubResult->data)) {
            ret = SUCCESS_CODE;
        } else {
            ret = ERR_GENERAL_FAIL;
        }
        free_simple_response_c_char(xPubResult);
    } while (0);
    ClearSecretCache();
    if (ret != SUCCESS_CODE) {
        KosmoApi_NotifyResult(KOSMO_REQ_BIP39_VERIFY_MNEMONIC, ret, NULL, 0);
    } else {
        KosmoApi_NotifyResult(KOSMO_REQ_BIP39_VERIFY_MNEMONIC, SUCCESS_CODE, NULL, 0);
    }
    SetLockScreen(enable);
    return 0;
}

// Auxiliary word verification for bip39
static int32_t ModelBip39ForgetPass(const void *inData, uint32_t inDataLen)
{
    bool enable = IsPreviousLockScreenEnable();
    SetLockScreen(false);
    int32_t ret = SUCCESS_CODE;
    do {
        ret = CHECK_BATTERY_LOW_POWER();
        CHECK_ERRCODE_BREAK("save low power", ret);
        ret = ModelComparePubkey(MNEMONIC_TYPE_BIP39, NULL, 0, 0, false, 0, NULL);
        if (ret != SUCCESS_CODE) {
            // Mnemonic doesn't match wallet → password reset allowed
            KosmoApi_NotifyResult(KOSMO_REQ_BIP39_FORGET_PASSWORD, SUCCESS_CODE, NULL, 0);
            SetLockScreen(enable);
            return ret;
        }
        ret = ERR_KEYSTORE_MNEMONIC_NOT_MATCH_WALLET;
    } while (0);
    KosmoApi_NotifyResult(KOSMO_REQ_BIP39_FORGET_PASSWORD, ret, NULL, 0);
    SetLockScreen(enable);
    return ret;
}

static int32_t ModelURGenerateQRCode(const void *indata, uint32_t inDataLen, BackgroundAsyncRunnable_t getUR)
{
    GenerateUR func = (GenerateUR)getUR;
    g_urResult = func();
    if (g_urResult->error_code == 0) {
        // printf("%s\r\n", g_urResult->data);
        KosmoApi_NotifyResult(KOSMO_REQ_UR_GENERATE_QR, KOSMO_OK, g_urResult->data, strnlen_s(g_urResult->data, SIMPLERESPONSE_C_CHAR_MAX_LEN) + 1);
    } else {
        char *message = g_urResult->error_message != NULL ? g_urResult->error_message : "";
        printf("error message: %s\r\n", message);
        KosmoApi_NotifyResult(KOSMO_REQ_UR_GENERATE_QR, ERR_GENERAL_FAIL, message, strnlen_s(message, SIMPLERESPONSE_C_CHAR_MAX_LEN) + 1);
    }
    return SUCCESS_CODE;
}

static bool ShouldUseCyclicPart(void)
{
    if (g_urResult == NULL) return false;
    if (strnlen_s(g_urResult->data, SIMPLERESPONSE_C_CHAR_MAX_LEN) < 6) return false;
    if (strncmp(g_urResult->data, "ur:xmr", 6) == 0 || strncmp(g_urResult->data, "UR:XMR", 6) == 0) {
        return true;
    }
    return false;
}

static int32_t ModelURUpdate(const void *inData, uint32_t inDataLen)
{
    if (g_urResult == NULL) return SUCCESS_CODE;
    if (g_urResult->is_multi_part) {
        UREncodeMultiResult *result = NULL;
        if (ShouldUseCyclicPart()) {
            result = get_next_cyclic_part(g_urResult->encoder);
        } else {
            result = get_next_part(g_urResult->encoder);
        }
        if (result->error_code == 0) {
            // printf("%s\r\n", result->data);
            KosmoApi_NotifyResult(KOSMO_REQ_UR_UPDATE, KOSMO_OK, result->data, strnlen_s(result->data, SIMPLERESPONSE_C_CHAR_MAX_LEN) + 1);
        } else {
            //TODO: deal with error
        }
        free_ur_encode_muilt_result(result);
    }
    return SUCCESS_CODE;
}

static int32_t ModelURClear(const void *inData, uint32_t inDataLen)
{
    if (g_urResult != NULL) {
        free_ur_encode_result(g_urResult);
        g_urResult = NULL;
    }
    return SUCCESS_CODE;
}

// Compare the generated extended public key
static int32_t ModelComparePubkey(MnemonicType mnemonicType, uint8_t *ems, uint8_t emsLen, uint16_t id, bool eb, uint8_t ie, uint8_t *index)
{
    bool enable = IsPreviousLockScreenEnable();
    SetLockScreen(false);
    bool bip39 = mnemonicType == MNEMONIC_TYPE_BIP39;
    bool slip39 = mnemonicType == MNEMONIC_TYPE_SLIP39;
    uint8_t seed[64] = {0};
    int ret = SUCCESS_CODE;
    uint8_t existIndex = 0;

    do {
        SimpleResponse_c_char *xPubResult;
        if (bip39) {
            ret = bip39_mnemonic_to_seed(SecretCacheGetMnemonic(), NULL, seed, 64, NULL);
            CHECK_ERRCODE_BREAK("bip39_mnemonic_to_seed", ret);
            xPubResult = get_extended_pubkey_by_seed(seed, 64, "M/49'/0'/0'");
        }
        if (slip39) {
            ret = Slip39GetSeed(ems, seed, emsLen, "", ie, eb, id);
            CHECK_ERRCODE_BREAK("Slip39GetSeed", ret);
            xPubResult = get_extended_pubkey_by_seed(seed, emsLen, "M/49'/0'/0'");
        }

        CHECK_CHAIN_BREAK(xPubResult);
        CLEAR_ARRAY(seed);
        existIndex = SpecifiedXPubExist(xPubResult->data);
        if (index != NULL) {
            *index = existIndex;
        }
        if (existIndex != 0xFF) {
            ret = ERR_KEYSTORE_MNEMONIC_REPEAT;
        } else {
            ret = SUCCESS_CODE;
        }
        free_simple_response_c_char(xPubResult);
    } while (0);
    SetLockScreen(enable);
    return ret;
}

static int32_t Slip39CreateGenerate(Slip39Data_t *slip39, bool isDiceRoll, KosmoRequestType requestType)
{
    bool enable = IsPreviousLockScreenEnable();
    SetLockScreen(false);
    int32_t ret = ERR_GENERAL_FAIL;
    uint8_t entropy[32] = {0}, ems[32] = {0};
    uint32_t entropyLen = 0;
    uint16_t id = 0;
    uint8_t ie = 0;
    bool eb = false;
    char *wordsList[SLIP39_MAX_MEMBER];

    if (slip39 == NULL) {
        goto cleanup;
    }
    if (!(slip39->wordCnt == SLIP39_MNEMONIC_20_WORDS || slip39->wordCnt == SLIP39_MNEMONIC_33_WORDS)) {
        goto cleanup;
    }
    if (slip39->memberCnt == 0 || slip39->threShold == 0 || slip39->threShold > slip39->memberCnt || slip39->memberCnt > SLIP39_MAX_MEMBER) {
        goto cleanup;
    }

    entropyLen = (slip39->wordCnt == SLIP39_MNEMONIC_20_WORDS) ? 16 : 32;

    if (isDiceRoll) {
        const uint8_t *dice = SecretCacheGetDiceRollHash();
        if (dice == NULL) goto cleanup;
        if (slip39->wordCnt == SLIP39_MNEMONIC_33_WORDS && SecretCacheGetDiceRollsLen() < 100) {
            goto cleanup;
        }
        memcpy_s(entropy, sizeof(entropy), dice, entropyLen);
    } else {
        const char *pwd = SecretCacheGetNewPassword();
        if (pwd == NULL || strnlen_s(pwd, PASSWORD_MAX_LEN) == 0) {
            goto cleanup;
        }
        ret = GenerateEntropy(entropy, entropyLen, pwd);
        if (ret != SUCCESS_CODE) {
            goto cleanup;
        }
    }

    ret = GetSlip39MnemonicsWords(entropy, ems, slip39->wordCnt, slip39->memberCnt, slip39->threShold, wordsList, &id, &eb, &ie);
    if (ret != SUCCESS_CODE) {
        goto cleanup_words;
    }

    SecretCacheSetEntropy(entropy, entropyLen);
    SecretCacheSetEms(ems, entropyLen);
    SecretCacheSetIdentifier(id);
    SecretCacheSetIteration(ie);
    SecretCacheSetExtendable(eb);
    for (int i = 0; i < slip39->memberCnt; i++) {
        SecretCacheSetSlip39Mnemonic(wordsList[i], i);
    }
    KosmoApi_NotifyResult(requestType, SUCCESS_CODE, NULL, 0);

cleanup_words:
    for (int i = 0; i < slip39->memberCnt; i++) {
        if (wordsList[i] != NULL) {
            memset_s(wordsList[i], strlen(wordsList[i]), 0, strlen(wordsList[i]));
            SRAM_FREE(wordsList[i]);
        }
    }
cleanup:
    if (ret != SUCCESS_CODE) {
        KosmoApi_NotifyResult(requestType, ret, NULL, 0);
    }
    CLEAR_ARRAY(ems);
    CLEAR_ARRAY(entropy);
    SetLockScreen(enable);
    return ret;
}

// slip39 generate
static int32_t ModelGenerateSlip39Entropy(const void *inData, uint32_t inDataLen)
{
    return Slip39CreateGenerate((Slip39Data_t *)inData, false, KOSMO_REQ_SLIP39_UPDATE_MNEMONIC);
}

// slip39 generate
static int32_t ModelGenerateSlip39EntropyWithDiceRolls(const void *inData, uint32_t inDataLen)
{
    return Slip39CreateGenerate((Slip39Data_t *)inData, true, KOSMO_REQ_SLIP39_UPDATE_MNEMONIC_DICE);
}

// Generate slip39 wallet writes
static int32_t ModelSlip39WriteEntropy(const void *inData, uint32_t inDataLen)
{
    bool enable = IsPreviousLockScreenEnable();
    SetLockScreen(false);
    uint8_t *entropy = NULL;
    uint8_t *ems = NULL;
    uint32_t entropyLen = 0;
    uint8_t newAccount = 0;
    uint8_t accountCnt = 0;
    uint16_t id = 0;
    uint8_t ie = 0;
    bool eb = false;
    uint8_t msCheck[32] = {0}, emsCheck[32] = {0};
    uint8_t threShold = 0;
    uint8_t wordCnt = *(uint8_t *)inData;
    int ret;

    ems = SecretCacheGetEms(&entropyLen);
    entropy = SecretCacheGetEntropy(&entropyLen);
    id = SecretCacheGetIdentifier();
    eb = SecretCacheGetExtendable();
    ie = SecretCacheGetIteration();

    MODEL_WRITE_SE_HEAD
    if (wordCnt != SLIP39_MNEMONIC_20_WORDS && wordCnt != SLIP39_MNEMONIC_33_WORDS) {
        ret = ERR_KEYSTORE_MNEMONIC_INVALID;
        break;
    }
    ret = Slip39CheckFirstWordList(SecretCacheGetSlip39Mnemonic(0), wordCnt, &threShold);
    char *words[threShold];
    for (int i = 0; i < threShold; i++) {
        words[i] = SecretCacheGetSlip39Mnemonic(i);
    }
    ret = Slip39GetMasterSecret(threShold, wordCnt, emsCheck, msCheck, words, &id, &eb, &ie);
    if ((ret != SUCCESS_CODE) || (memcmp(msCheck, entropy, entropyLen) != 0) || (memcmp(emsCheck, ems, entropyLen) != 0)) {
        ret = ERR_KEYSTORE_MNEMONIC_INVALID;
        break;
    }
    CLEAR_ARRAY(emsCheck);
    CLEAR_ARRAY(msCheck);
    ret = ModelComparePubkey(MNEMONIC_TYPE_SLIP39, ems, entropyLen, id, eb, ie, NULL);
    CHECK_ERRCODE_BREAK("duplicated entropy", ret);
    ret = CreateNewSlip39Account(newAccount, ems, entropy, entropyLen, SecretCacheGetNewPassword(), SecretCacheGetIdentifier(), SecretCacheGetExtendable(), SecretCacheGetIteration());
    CHECK_ERRCODE_BREAK("save slip39 entropy error", ret);
    ClearAccountPassphrase(newAccount);
    if (strnlen_s(SecretCacheGetPassphrase(), PASSPHRASE_MAX_LEN) > 0) {
        ret = SetPassphrase(GetCurrentAccountIndex(), SecretCacheGetPassphrase(), SecretCacheGetNewPassword());
        CHECK_ERRCODE_BREAK("set passphrase error", ret);
        SetPassphraseQuickAccess(g_ui_passphrase_quick_access);
    }
    MODEL_WRITE_SE_END(KOSMO_REQ_SLIP39_WRITE_SE)

    SetLockScreen(enable);
    return SUCCESS_CODE;
}

// Import of mnemonic words for slip39
static int32_t ModelSlip39CalWriteEntropyAndSeed(const void *inData, uint32_t inDataLen)
{
    bool enable = IsPreviousLockScreenEnable();
    SetLockScreen(false);

    uint8_t *entropy;
    uint8_t entropyLen;
    int32_t ret;
    uint16_t id;
    uint8_t ie;
    bool eb;
    uint8_t newAccount;
    uint8_t accountCnt;
    Slip39Data_t *slip39 = (Slip39Data_t *)inData;
    AccountInfo_t accountInfo;

    entropyLen = (slip39->wordCnt == 20) ? 16 : 32;
    entropy = SRAM_MALLOC(entropyLen);
    uint8_t ems[32] = {0};
    uint8_t emsBak[32] = {0};

    char *words[slip39->threShold];
    for (int i = 0; i < slip39->threShold; i++) {
        words[i] = SecretCacheGetSlip39Mnemonic(i);
    }

    MODEL_WRITE_SE_HEAD
    ret = Slip39GetMasterSecret(slip39->threShold, slip39->wordCnt, ems, entropy, words, &id, &eb, &ie);
    if (ret != SUCCESS_CODE) {
        printf("get master secret error\n");
        break;
    }
    memcpy_s(emsBak, sizeof(emsBak), ems, entropyLen);

    if (slip39->forget) {
        ret = ModelComparePubkey(MNEMONIC_TYPE_SLIP39, ems, entropyLen, id, eb, ie, &newAccount);
        CHECK_ERRCODE_BREAK("mnemonic not match", !ret);
    } else {
        ret = ModelComparePubkey(MNEMONIC_TYPE_SLIP39, ems, entropyLen, id, eb, ie, NULL);
        CHECK_ERRCODE_BREAK("mnemonic repeat", ret);
    }
    printf("before accountCnt = %d\n", accountCnt);
    if (slip39->forget) {
        GetAccountInfo(newAccount, &accountInfo);
    }
    ret = CreateNewSlip39Account(newAccount, emsBak, entropy, entropyLen, SecretCacheGetNewPassword(), id, eb, ie);
    CHECK_ERRCODE_BREAK("save slip39 entropy error", ret);
    ClearAccountPassphrase(newAccount);
    if (strnlen_s(SecretCacheGetPassphrase(), PASSPHRASE_MAX_LEN) > 0) {
        ret = SetPassphrase(GetCurrentAccountIndex(), SecretCacheGetPassphrase(), SecretCacheGetNewPassword());
        CHECK_ERRCODE_BREAK("set passphrase error", ret);
        SetPassphraseQuickAccess(g_ui_passphrase_quick_access);
    }
    ret = VerifyPasswordAndLogin(&newAccount, SecretCacheGetNewPassword());
    CHECK_ERRCODE_BREAK("login error", ret);
    UpdateFingerSignFlag(GetCurrentAccountIndex(), false);
    if (slip39->forget) {
        SetWalletName(accountInfo.walletName);
        SetWalletIconIndex(accountInfo.iconIndex);
        LogoutCurrentAccount();
        CloseUsb();
    }
    CLEAR_ARRAY(ems);
    CLEAR_ARRAY(emsBak);
    GetExistAccountNum(&accountCnt);
    printf("after accountCnt = %d\n", accountCnt);
}
while (0);
if (ret == SUCCESS_CODE)
{
    ClearSecretCache();
    KosmoApi_NotifyResult(KOSMO_REQ_SLIP39_CAL_WRITE_SE, SUCCESS_CODE, NULL, 0);
} else
{
    KosmoApi_NotifyResult(KOSMO_REQ_SLIP39_CAL_WRITE_SE, ret, NULL, 0);
}
SRAM_FREE(entropy);
SetLockScreen(enable);
return SUCCESS_CODE;
}

static int32_t ModelSlip39ForgetPass(const void *inData, uint32_t inDataLen)
{
    bool enable = IsPreviousLockScreenEnable();
    SetLockScreen(false);
    int32_t ret = SUCCESS_CODE;
#ifndef COMPILE_SIMULATOR
    uint8_t *entropy;
    uint8_t entropyLen;
    uint16_t id;
    uint8_t ie;
    bool eb;
    Slip39Data_t *slip39 = (Slip39Data_t *)inData;

    entropyLen = (slip39->wordCnt == 20) ? 16 : 32;
    entropy = SRAM_MALLOC(entropyLen);
    uint8_t ems[32] = {0};

    char *words[slip39->threShold];
    for (int i = 0; i < slip39->threShold; i++) {
        words[i] = SecretCacheGetSlip39Mnemonic(i);
    }

    do {
        ret = CHECK_BATTERY_LOW_POWER();
        CHECK_ERRCODE_BREAK("save low power", ret);
        ret = Slip39GetMasterSecret(slip39->threShold, slip39->wordCnt, ems, entropy, words, &id, &eb, &ie);
        if (ret != SUCCESS_CODE) {
            printf("get master secret error\n");
            break;
        }
        ret = ModelComparePubkey(MNEMONIC_TYPE_SLIP39, ems, entropyLen, id, eb, ie, NULL);
        if (ret != SUCCESS_CODE) {
            // Mnemonic doesn't match wallet → password reset allowed
            KosmoApi_NotifyResult(KOSMO_REQ_SLIP39_FORGET_PASSWORD, SUCCESS_CODE, NULL, 0);
            SetLockScreen(enable);
            return ret;
        }
        ret = ERR_KEYSTORE_MNEMONIC_NOT_MATCH_WALLET;
    } while (0);
    KosmoApi_NotifyResult(KOSMO_REQ_SLIP39_FORGET_PASSWORD, ret, NULL, 0);

    SRAM_FREE(entropy);
#else
    KosmoApi_NotifyResult(KOSMO_REQ_SLIP39_FORGET_PASSWORD, SUCCESS_CODE, NULL, 0);
#endif
    SetLockScreen(enable);
    return ret;
}

// save wallet desc
static int32_t ModelSaveWalletDesc(const void *inData, uint32_t inDataLen)
{
    bool enable = IsPreviousLockScreenEnable();
    SetLockScreen(false);
    WalletDesc_t *wallet = (WalletDesc_t *)inData;
    SetWalletName(wallet->name);
    SetWalletIconIndex(wallet->iconIndex);

    KosmoApi_NotifyResult(KOSMO_REQ_SAVE_WALLET_DESC, SUCCESS_CODE, NULL, 0);
    SetLockScreen(enable);
    return SUCCESS_CODE;
}

// del wallet
static int32_t ModelDelWallet(const void *inData, uint32_t inDataLen)
{
    bool enable = IsPreviousLockScreenEnable();
    SetLockScreen(false);
    int32_t ret;
    uint8_t accountIndex = GetCurrentAccountIndex();
    UpdateFingerSignFlag(accountIndex, false);
    CloseUsb();
    ret = DestroyAccount(accountIndex);
    if (ret == SUCCESS_CODE) {
        // reset address index in receive page
        {
            ui_post_notification(SIG_RESET_UTXO_ADDRESS_INDEX, accountIndex);
            ui_post_notification(SIG_RESET_ETH_ADDRESS_INDEX, accountIndex);
            ui_post_notification(SIG_RESET_STANDARD_ADDRESS_INDEX, accountIndex);
            ui_post_notification(SIG_RESET_MULTI_ACCOUNTS_CACHE, accountIndex);
        }

        uint8_t accountNum;
        GetExistAccountNum(&accountNum);
        if (accountNum == 0) {
            FpWipeManageInfo();
            SetSetupStep(0);
            SaveDeviceSettings();
            ResetBootParam();
            g_reboot = true;
            uint8_t mode = 0; // 0 = setup mode (last wallet deleted)
            KosmoApi_NotifyResult(KOSMO_REQ_DEL_WALLET_DESC, SUCCESS_CODE, &mode, sizeof(mode));
        } else {
            uint8_t mode = 1; // 1 = normal delete
            KosmoApi_NotifyResult(KOSMO_REQ_DEL_WALLET_DESC, SUCCESS_CODE, &mode, sizeof(mode));
        }
    } else {
        KosmoApi_NotifyResult(KOSMO_REQ_DEL_WALLET_DESC, ret, NULL, 0);
    }
    SetLockScreen(enable);
    return SUCCESS_CODE;
}

// del all wallet
static int32_t ModelDelAllWallet(const void *inData, uint32_t inDataLen)
{
    bool enable = IsPreviousLockScreenEnable();
    SetLockScreen(false);
#ifndef COMPILE_SIMULATOR
    WipeDevice();
    SystemReboot();
#else
    KosmoApi_NotifyResult(KOSMO_REQ_DEL_ALL_WALLET_DESC, SUCCESS_CODE, NULL, 0);
#endif
    SetLockScreen(enable);
    return SUCCESS_CODE;
}

// write passphrase
static int32_t ModelWritePassphrase(const void *inData, uint32_t inDataLen)
{
    bool enable = IsPreviousLockScreenEnable();
    SetLockScreen(false);
    int32_t ret = 0;
    if (CheckPassphraseSame(GetCurrentAccountIndex(), SecretCacheGetPassphrase())) {
        KosmoApi_NotifyResult(KOSMO_REQ_WRITE_PASSPHRASE, SUCCESS_CODE, NULL, 0);
    } else {
        ret = SetPassphrase(GetCurrentAccountIndex(), SecretCacheGetPassphrase(), SecretCacheGetPassword());
        if (ret == SUCCESS_CODE) {
            KosmoApi_NotifyResult(KOSMO_REQ_WRITE_PASSPHRASE, SUCCESS_CODE, NULL, 0);
            ClearSecretCache();
        } else {
            KosmoApi_NotifyResult(KOSMO_REQ_WRITE_PASSPHRASE, ret, NULL, 0);
        }
        ClearSecretCache();
    }
    SetLockScreen(enable);
    return SUCCESS_CODE;
}

// reset wallet password
static int32_t ModelChangeAccountPass(const void *inData, uint32_t inDataLen)
{
    bool enable = IsPreviousLockScreenEnable();
    SetLockScreen(false);
#ifndef COMPILE_SIMULATOR
    int32_t ret;

    ret = VerifyCurrentAccountPassword(SecretCacheGetPassword());
    ret = ChangePassword(GetCurrentAccountIndex(), SecretCacheGetNewPassword(), SecretCacheGetPassword());
    UpdateFingerSignFlag(GetCurrentAccountIndex(), false);
    if (ret == SUCCESS_CODE) {
        KosmoApi_NotifyResult(KOSMO_REQ_CHANGE_PASSWORD, SUCCESS_CODE, NULL, 0);
    } else {
        KosmoApi_NotifyResult(KOSMO_REQ_CHANGE_PASSWORD, ret, NULL, 0);
    }

    ClearSecretCache();
#else
    uint8_t *entropy;
    uint8_t entropyLen;
    int32_t ret;
    uint8_t *accountIndex = (uint8_t *)inData;

    KosmoApi_NotifyResult(KOSMO_REQ_CHANGE_PASSWORD, SUCCESS_CODE, NULL, 0);
#endif
    SetLockScreen(enable);
    return SUCCESS_CODE;
}

static uint16_t ModelVerifyPassSuccess(uint16_t *param)
{
    int32_t ret = SUCCESS_CODE;
    uint8_t walletAmount;
    uint16_t resultSignal = SIG_VERIFY_PASSWORD_PASS;
    switch (*param) {
    case DEVICE_SETTING_ADD_WALLET:
        GetExistAccountNum(&walletAmount);
        if (walletAmount == 3) {
            resultSignal = SIG_SETTING_ADD_WALLET_AMOUNT_LIMIT;
        } else {
            resultSignal = SIG_VERIFY_PASSWORD_PASS;
        }
        break;
    case SIG_SETTING_WRITE_PASSPHRASE:
        resultSignal = SIG_SETTING_WRITE_PASSPHRASE_VERIFY_PASS;
        SetPageLockScreen(false);
        if (SecretCacheGetPassphrase() == NULL) {
            SecretCacheSetPassphrase("");
        }
        ret = SetPassphrase(GetCurrentAccountIndex(), SecretCacheGetPassphrase(), SecretCacheGetPassword());
        SetPageLockScreen(true);
        if (ret == SUCCESS_CODE) {
            resultSignal = SIG_SETTING_WRITE_PASSPHRASE_PASS;
            ClearSecretCache();
        } else {
            resultSignal = SIG_SETTING_WRITE_PASSPHRASE_FAIL;
        }
        break;
    case SIG_LOCK_VIEW_SCREEN_ON_VERIFY_PASSPHRASE:
        resultSignal = SIG_LOCK_VIEW_SCREEN_ON_PASSPHRASE_PASS;
        break;
    case SIG_SETUP_RSA_PRIVATE_KEY_WITH_PASSWORD:
        resultSignal = SIG_SETUP_RSA_PRIVATE_KEY_RSA_VERIFY_PASSWORD_PASS;
        break;
    default:
        resultSignal = SIG_VERIFY_PASSWORD_PASS;
        break;
    }
    return resultSignal;
}

static uint16_t ModelVerifyPassFailed(uint16_t *param)
{
    uint16_t signal = SIG_VERIFY_PASSWORD_FAIL;
    switch (*param) {
    case SIG_LOCK_VIEW_VERIFY_PIN:
    case SIG_LOCK_VIEW_SCREEN_GO_HOME_PASS:
        g_passwordVerifyResult.errorCount = GetLoginPasswordErrorCount();
        printf("gui model get login error count %d \n", g_passwordVerifyResult.errorCount);
        assert(g_passwordVerifyResult.errorCount <= MAX_LOGIN_PASSWORD_ERROR_COUNT);
        if (g_passwordVerifyResult.errorCount == MAX_LOGIN_PASSWORD_ERROR_COUNT) {
            UnlimitedVibrate(SUPER_LONG);
        } else {
            UnlimitedVibrate(LONG);
        }
        break;
    case SIG_SETUP_RSA_PRIVATE_KEY_WITH_PASSWORD:
        signal = SIG_SETUP_RSA_PRIVATE_KEY_RSA_VERIFY_PASSWORD_FAIL;
        g_passwordVerifyResult.errorCount = GetCurrentPasswordErrorCount();
        printf("gui model get current error count %d \n", g_passwordVerifyResult.errorCount);
        assert(g_passwordVerifyResult.errorCount <= MAX_CURRENT_PASSWORD_ERROR_COUNT_SHOW_HINTBOX);
        if (g_passwordVerifyResult.errorCount == MAX_CURRENT_PASSWORD_ERROR_COUNT_SHOW_HINTBOX) {
            UnlimitedVibrate(SUPER_LONG);
        } else {
            UnlimitedVibrate(LONG);
        }
        break;
    default:
        g_passwordVerifyResult.errorCount = GetCurrentPasswordErrorCount();
        printf("gui model get current error count %d \n", g_passwordVerifyResult.errorCount);
        assert(g_passwordVerifyResult.errorCount <= MAX_CURRENT_PASSWORD_ERROR_COUNT_SHOW_HINTBOX);
        if (g_passwordVerifyResult.errorCount == MAX_CURRENT_PASSWORD_ERROR_COUNT_SHOW_HINTBOX) {
            UnlimitedVibrate(SUPER_LONG);
        } else {
            UnlimitedVibrate(LONG);
        }
        break;
    }
    g_passwordVerifyResult.signal = param;
    return signal;
}

// verify wallet password
static int32_t ModelVerifyAccountPass(const void *inData, uint32_t inDataLen)
{
    bool enable = IsPreviousLockScreenEnable();
    static bool firstVerify = true;
    SetLockScreen(false);
    uint8_t accountIndex;
    int32_t ret;
    uint16_t *param = (uint16_t *)inData;

    // Unlock screen
    if (SIG_LOCK_VIEW_VERIFY_PIN == *param || SIG_LOCK_VIEW_SCREEN_GO_HOME_PASS == *param) {
        ret = VerifyPasswordAndLogin(&accountIndex, SecretCacheGetPassword());
        if (ret == ERR_KEYSTORE_EXTEND_PUBLIC_KEY_NOT_MATCH) {
            KosmoApi_NotifyResult(KOSMO_REQ_VERIFY_PASSWORD, ret, NULL, 0);
            SetLockScreen(enable);
            return ret;
        } else if (ret == SUCCESS_CODE) {
            ModeGetWalletDesc(NULL, 0);
        }
    } else {
        ret = VerifyCurrentAccountPassword(SecretCacheGetPassword());
    }

    if (SIG_LOCK_VIEW_VERIFY_PIN == *param && firstVerify && ModelGetPassphraseQuickAccess()) {
        *param = SIG_LOCK_VIEW_SCREEN_ON_VERIFY_PASSPHRASE;
        firstVerify = false;
    }

    // some scene would need clear secret after check
    if (*param != SIG_SETTING_CHANGE_PASSWORD &&
            *param != SIG_SETTING_WRITE_PASSPHRASE &&
            *param != SIG_LOCK_VIEW_SCREEN_ON_VERIFY_PASSPHRASE &&
            *param != SIG_FINGER_SET_SIGN_TRANSITIONS &&
            *param != SIG_FINGER_REGISTER_ADD_SUCCESS &&
            *param != SIG_SIGN_TRANSACTION_WITH_PASSWORD &&
            *param != SIG_SETUP_RSA_PRIVATE_KEY_WITH_PASSWORD &&
            *param != SIG_MULTISIG_WALLET_IMPORT_VERIFY_PASSWORD &&
            *param != SIG_MULTISIG_WALLET_DELETE_VERIFY_PASSWORD &&
            *param != SIG_HARDWARE_CALL_DERIVE_PUBKEY &&
            *param != SIG_INIT_CONNECT_USB &&
            !strnlen_s(SecretCacheGetPassphrase(), PASSPHRASE_MAX_LEN) &&
            !g_ui_create_wallet_view_opened &&
            !ModelGetPassphraseQuickAccess()) {
        ClearSecretCache();
    }
    SetLockScreen(enable);
    uint16_t resultSignal;
    if (ret == SUCCESS_CODE) {
        resultSignal = ModelVerifyPassSuccess(param);
    } else {
        resultSignal = ModelVerifyPassFailed(param);
    }
    KosmoVerifyResult s_verifyContext;
    s_verifyContext.resultSignal = resultSignal;
    s_verifyContext.originalParam = *param;
    s_verifyContext.errorCount = g_passwordVerifyResult.errorCount;
    KosmoApi_NotifyResult(KOSMO_REQ_VERIFY_PASSWORD, ret,
                          &s_verifyContext, sizeof(s_verifyContext));
    return SUCCESS_CODE;
}

// get wallet amount
static int32_t ModeGetAccount(const void *inData, uint32_t inDataLen)
{
    bool enable = IsPreviousLockScreenEnable();
    SetLockScreen(false);
    static uint8_t walletAmount;
    int32_t ret;

    ret = GetExistAccountNum(&walletAmount);
    if (ret != SUCCESS_CODE) {
        walletAmount = 0xFF;
    }
    KosmoApi_NotifyResult(KOSMO_REQ_GET_ACCOUNT, KOSMO_OK, &walletAmount, sizeof(walletAmount));
    SetLockScreen(enable);
    return SUCCESS_CODE;
}

// get wallet desc
static int32_t ModeGetWalletDesc(const void *inData, uint32_t inDataLen)
{
    bool enable = IsPreviousLockScreenEnable();
    SetLockScreen(false);
    static WalletDesc_t wallet;
    uint8_t accountNum = 0;
    GetExistAccountNum(&accountNum);
    if (accountNum == 0 || GetCurrentAccountIndex() > 2) {
        SetLockScreen(enable);
        return SUCCESS_CODE;
    }
    wallet.iconIndex = GetWalletIconIndex();
    strcpy_s(wallet.name, WALLET_NAME_MAX_LEN + 1, GetWalletName());
    KosmoApi_NotifyResult(KOSMO_REQ_GET_WALLET_DESC, KOSMO_OK, &wallet, sizeof(wallet));
    SetLockScreen(enable);
    return SUCCESS_CODE;
}

// stop/start qr decode
static int32_t ModeControlQrDecode(const void *inData, uint32_t inDataLen)
{
    bool enable = IsPreviousLockScreenEnable();
    SetLockScreen(false);
    bool *en = (bool *)inData;
#ifndef COMPILE_SIMULATOR
    UserDelay(100);
    if (en) {
        PubValueMsg(QRDECODE_MSG_START, 0);
    } else {
        PubValueMsg(QRDECODE_MSG_STOP, 0);
    }
#else
    if (en) {
        read_qrcode();
    }
#endif
    SetLockScreen(enable);
    return SUCCESS_CODE;
}

static int32_t ModelWriteLastLockDeviceTime(const void *inData, uint32_t inDataLen)
{
    bool enable = IsPreviousLockScreenEnable();
    SetLockScreen(false);

    uint32_t time = *(uint32_t*)inData;
    SetLastLockDeviceTime(time);

    SetLockScreen(enable);

    /* Phase 3 PoC：通过 callback 通知 UI 层完成 */
    KosmoApi_NotifyResult(KOSMO_REQ_WRITE_LOCK_TIME, KOSMO_OK, NULL, 0);

    return SUCCESS_CODE;
}

static bool CheckNeedDelay(ViewType viewType)
{
    return viewType == ZcashTx;
}

static int32_t ModelCheckTransaction(const void *inData, uint32_t inDataLen)
{
    ViewType viewType = *((ViewType *)inData);
    if (CheckNeedDelay(viewType)) {
        UserDelay(100);
    }
    g_checkResult = CheckUrResult(viewType);
    if (g_checkResult != NULL && g_checkResult->error_code == 0) {
        KosmoApi_NotifyResult(KOSMO_REQ_CHECK_TRANSACTION, KOSMO_OK, g_checkResult, sizeof(g_checkResult));
    } else {
        printf("transaction check fail, error code: %d, error msg: %s\r\n", g_checkResult->error_code, g_checkResult->error_message);
        KosmoApi_NotifyResult(KOSMO_REQ_CHECK_TRANSACTION, ERR_GENERAL_FAIL, g_checkResult, sizeof(g_checkResult));
    }

    return SUCCESS_CODE;
}


static int32_t ModelTransactionCheckResultClear(const void *inData, uint32_t inDataLen)
{
    if (g_checkResult != NULL) {
        free_TransactionCheckResult(g_checkResult);
        g_checkResult = NULL;
    }
    return SUCCESS_CODE;
}

static int32_t ModelParseTransaction(const void *indata, uint32_t inDataLen, BackgroundAsyncRunnable_t parseTransactionFunc)
{
    ReturnVoidPointerFunc func = (ReturnVoidPointerFunc)parseTransactionFunc;
    SetPageLockScreen(false);
    // There is no need to release here, the parsing results will be released when exiting the details page.
    TransactionParseResult_DisplayTx *parsedResult = (TransactionParseResult_DisplayTx *)func();
    if (parsedResult != NULL && parsedResult->error_code == 0 && parsedResult->data != NULL) {
        KosmoApi_NotifyResult(KOSMO_REQ_PARSE_TRANSACTION, KOSMO_OK, parsedResult, sizeof(parsedResult));
    } else {
        KosmoApi_NotifyResult(KOSMO_REQ_PARSE_TRANSACTION, ERR_GENERAL_FAIL, parsedResult, sizeof(parsedResult));
    }
    SetPageLockScreen(true);
    return SUCCESS_CODE;
}

static const uint8_t APP_END_MAGIC_NUMBER[] = {'m', 'h', '1', '9', '0', '3', 'a', 'p', 'p', 'e', 'n', 'd'};
static uint32_t BinarySearchLastNonFFSector(void)
{
    size_t APP_END_MAGIC_NUMBER_SIZE = sizeof(APP_END_MAGIC_NUMBER);
    uint8_t *buffer = SRAM_MALLOC(SECTOR_SIZE);
    uint32_t startIndex = (APP_CHECK_START_ADDR - APP_ADDR) / SECTOR_SIZE;
    uint32_t endIndex = (APP_END_ADDR - APP_ADDR) / SECTOR_SIZE;

    uint8_t percent = 1;
    KosmoApi_NotifyResult(KOSMO_REQ_CALCULATE_CHECKSUM, KOSMO_OK, &percent, sizeof(percent));

    for (int i = startIndex + 1; i < endIndex; i++) {
        if (g_stopCalChecksum == true) {
            SRAM_FREE(buffer);
            return SUCCESS_CODE;
        }
        memcpy_s(buffer, SECTOR_SIZE, (uint32_t *)(APP_ADDR + i * SECTOR_SIZE), SECTOR_SIZE);
        if ((i - startIndex) % 200 == 0) {
            percent++;
            KosmoApi_NotifyResult(KOSMO_REQ_CALCULATE_CHECKSUM, KOSMO_OK, &percent, sizeof(percent));
        }
        if (memcmp(buffer, APP_END_MAGIC_NUMBER, APP_END_MAGIC_NUMBER_SIZE) == 0) {
            if (CheckAllFF(&buffer[APP_END_MAGIC_NUMBER_SIZE], SECTOR_SIZE - APP_END_MAGIC_NUMBER_SIZE)) {
                SRAM_FREE(buffer);
                return i;
            }
        }
    }
    SRAM_FREE(buffer);
    return -1;
}

static int32_t ModelCalculateCheckSum(const void *indata, uint32_t inDataLen)
{
#ifndef COMPILE_SIMULATOR
    g_stopCalChecksum = false;
    uint8_t buffer[4096] = {0};
    uint8_t hash[32] = {0};
    int num = BinarySearchLastNonFFSector();
    ASSERT(num >= 0);
    if (g_stopCalChecksum == true) {
        return SUCCESS_CODE;
    }
    struct sha256_ctx ctx;
    sha256_init(&ctx);
    uint8_t percent = 0;
    for (int i = 0; i <= num; i++) {
        if (g_stopCalChecksum == true) {
            return SUCCESS_CODE;
        }
        memset_s(buffer, SECTOR_SIZE, 0, SECTOR_SIZE);
        memcpy_s(buffer, sizeof(buffer), (uint32_t *)(APP_ADDR + i * SECTOR_SIZE), SECTOR_SIZE);
        sha256_update(&ctx, buffer, SECTOR_SIZE);
        if (percent != i * 100 / num) {
            percent = i * 100 / num;
            if (percent != 100 && percent >= 10) {
                KosmoApi_NotifyResult(KOSMO_REQ_CALCULATE_CHECKSUM, KOSMO_OK, &percent, sizeof(percent));
            }
        }
    }
    sha256_done(&ctx, (struct sha256 *)hash);
    memset_s(buffer, SECTOR_SIZE, 0, SECTOR_SIZE);
    percent = 100;
    SetPageLockScreen(true);
    SecretCacheSetChecksum(hash);
    KosmoApi_NotifyResult(KOSMO_REQ_CALCULATE_CHECKSUM, KOSMO_OK, &percent, sizeof(percent));
#else
    uint8_t percent = 100;
    char *hash = "131b3a1e9314ba076f8e459a1c4c6713eeb38862f3eb6f9371360aa234cdde1f";
    SecretCacheSetChecksum(hash);
    KosmoApi_NotifyResult(KOSMO_REQ_CALCULATE_CHECKSUM, KOSMO_OK, &percent, sizeof(percent));
#endif
    return SUCCESS_CODE;
}

#define FATFS_SHA256_BUFFER_SIZE              4096
static int32_t ModelCalculateBinSha256(const void *indata, uint32_t inDataLen)
{
    uint8_t percent;
#ifndef COMPILE_SIMULATOR
    g_stopCalChecksum = false;
    FIL fp;
    uint8_t *data = NULL;
    uint32_t fileSize, actualSize, copyOffset, totalSize = 0;
    uint8_t oldPercent = 0;
    FRESULT res;
    struct sha256_ctx ctx;
    sha256_init(&ctx);
    unsigned char hash[32];
    do {
        res = f_open(&fp, SD_CARD_OTA_BIN_PATH, FA_OPEN_EXISTING | FA_READ);
        if (res) {
            return res;
        }
        fileSize = f_size(&fp);
        data = SRAM_MALLOC(FATFS_SHA256_BUFFER_SIZE);
        for (copyOffset = 0; copyOffset <= fileSize; copyOffset += FATFS_SHA256_BUFFER_SIZE) {
            if (!SdCardInsert() || (g_stopCalChecksum == true)) {
                res = ERR_GENERAL_FAIL;
                break;
            }

            res = f_read(&fp, data, FATFS_SHA256_BUFFER_SIZE, &actualSize);
            if (res) {
                FatfsError(res);
                break;
            }
            sha256_update(&ctx, data, actualSize);
            totalSize += actualSize;

            uint8_t percent = totalSize * 100 / fileSize;
            if (oldPercent != percent) {
                printf("==========copy %d%%==========\n", percent);
                oldPercent = percent;
                if (percent != 100 && percent >= 2) {
                    KosmoApi_NotifyResult(KOSMO_REQ_CALCULATE_SHA256, KOSMO_OK, &percent, sizeof(percent));
                }
            }
        }
    } while (0);

    if (res == FR_OK) {
        sha256_done(&ctx, (struct sha256 *)hash);
        for (int i = 0; i < sizeof(hash); i++) {
            printf("%02x", hash[i]);
        }
        SecretCacheSetChecksum(hash);
        percent = 100;
        KosmoApi_NotifyResult(KOSMO_REQ_CALCULATE_SHA256, KOSMO_OK, &percent, sizeof(percent));
    } else {
        KosmoApi_NotifyResult(KOSMO_REQ_CALCULATE_SHA256, ERR_GENERAL_FAIL, NULL, 0);
    }
    SRAM_FREE(data);
    f_close(&fp);
    SetPageLockScreen(true);
#else
    percent = 100;
    char *hash = "131b3a1e9314ba076f8e459a1c4c6713eeb38862f3eb6f9371360aa234cdde1f";
    SecretCacheSetChecksum(hash);
    KosmoApi_NotifyResult(KOSMO_REQ_CALCULATE_SHA256, KOSMO_OK, &percent, sizeof(percent));
#endif
    return SUCCESS_CODE;
}

static bool ModelGetPassphraseQuickAccess(void)
{
#ifdef COMPILE_SIMULATOR
    return false;
#else
    if (PassphraseExist(GetCurrentAccountIndex()) == false && GetPassphraseQuickAccess() == true && GetPassphraseMark() == true) {
        return true;
    } else {
        return false;
    }
#endif
}

static int32_t ModelFormatMicroSd(const void *indata, uint32_t inDataLen)
{
    int ret = FormatSdFatfs();
    if (ret != SUCCESS_CODE) {
        KosmoApi_NotifyResult(KOSMO_REQ_FORMAT_SD_CARD, ERR_GENERAL_FAIL, NULL, 0);
    } else {
        KosmoApi_NotifyResult(KOSMO_REQ_FORMAT_SD_CARD, KOSMO_OK, NULL, 0);
    }
    SetPageLockScreen(true);

    return SUCCESS_CODE;
}


static int32_t ModelRsaGenerateKeyPair(const void *inData, uint32_t inDataLen)
{
    UNUSED(inData);
    UNUSED(inDataLen);
    return RsaGenerateKeyPair(true, KOSMO_REQ_RSA_GENERATE_KEYPAIR);
}

int32_t RsaGenerateKeyPair(bool needEmitSignal, int requestType)
{
    bool lockState = IsPreviousLockScreenEnable();
    SetLockScreen(false);
    if (needEmitSignal) {
        uint16_t stage = SIG_SETUP_RSA_PRIVATE_KEY_WITH_PASSWORD_START;
        KosmoApi_NotifyResult(requestType, KOSMO_OK, &stage, sizeof(stage));
    }

    int32_t ret = SUCCESS_CODE;
    uint8_t seed[SEED_LEN] = {0};
    SimpleResponse_u8* secret = NULL;

    do {
        int len = GetMnemonicType() == MNEMONIC_TYPE_BIP39 ? sizeof(seed) : GetCurrentAccountEntropyLen();

        ret = GetAccountSeed(GetCurrentAccountIndex(), seed, SecretCacheGetPassword());
        CHECK_ERRCODE_BREAK("get account seed", ret);

        secret = generate_arweave_secret(seed, len);
        CHECK_ERRCODE_BREAK("generate arweave secret", secret->error_code);

        ret = FlashWriteRsaPrimes(secret->data);
        CHECK_ERRCODE_BREAK("flash write rsa primes", ret);

        if (needEmitSignal) {
            uint16_t stage = SIG_SETUP_RSA_PRIVATE_KEY_GENERATE_ADDRESS;
            KosmoApi_NotifyResult(requestType, KOSMO_OK, &stage, sizeof(stage));
        }

        ret = AccountPublicInfoSwitch(GetCurrentAccountIndex(), SecretCacheGetPassword(), true);
        CHECK_ERRCODE_BREAK("account public info switch", ret);

        RecalculateManageWalletState();
    } while (0);

    if (needEmitSignal) {
        uint16_t stage;
        if (ret == SUCCESS_CODE) {
            stage = SIG_SETUP_RSA_PRIVATE_KEY_WITH_PASSWORD_PASS;
            KosmoApi_NotifyResult(requestType, SUCCESS_CODE, &stage, sizeof(stage));
        } else {
            stage = SIG_SETUP_RSA_PRIVATE_KEY_WRITE_FAIL;
            KosmoApi_NotifyResult(requestType, ret, &stage, sizeof(stage));
        }
        stage = SIG_SETUP_RSA_PRIVATE_KEY_HIDE_LOADING;
        KosmoApi_NotifyResult(requestType, KOSMO_OK, &stage, sizeof(stage));
    }
    memset_s(seed, sizeof(seed), 0, sizeof(seed));
    if (secret != NULL) {
        free_simple_response_u8(secret);
    }
    SetLockScreen(lockState);
    ClearLockScreenTime();
    return ret;
}

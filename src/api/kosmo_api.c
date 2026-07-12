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
#include <string.h>

/* ── 后端头文件（只有这里能 include）────────────────── */

#include "account_public_info.h"
#include "account_manager.h"
#include "keystore.h"
#include "bip39.h"
#include "wordlist.h"
#include "gui_wallet.h"
#include "gui_xrp.h"
#include "gui_ada.h"
#include "rust.h"
#include "gui_status_bar.h"
#include "secret_cache.h"

/* Phase 2: gui_model.h 的 GuiModel* 函数作为异步分发目标。
 * Phase 4 完成后将移除此依赖，逻辑直接内联到本文件。 */
#include "gui_model.h"

#ifndef COMPILE_SIMULATOR
#include "user_memory.h"
#include "gui_views.h"
#endif

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

static KosmoCallback g_pendingCallbacks[KOSMO_REQ_NUM];
static bool g_persistentCallbacks[KOSMO_REQ_NUM];

/* ── 初始化 ─────────────────────────────────────────── */

void KosmoApi_Init(void)
{
    memset(g_pendingCallbacks, 0, sizeof(g_pendingCallbacks));
    memset(g_persistentCallbacks, 0, sizeof(g_persistentCallbacks));
}

/* ── 异步请求 ───────────────────────────────────────── */

/*
 * KosmoApi_NotifyResult() — 后端结果回调入口
 *
 * Model* 函数完成操作后调用此函数，触发 UI 层注册的 callback。
 * 替代原来的 GuiApiEmitSignal() 全局广播。
 *
 * Phase 3 PoC：当前仅 WRITE_LOCK_TIME 使用。逐步扩展到所有请求类型。
 */
void KosmoApi_NotifyResult(KosmoRequestType type, int32_t errorCode, void *data, uint32_t dataLen)
{
    if (type >= KOSMO_REQ_NUM) return;

    KosmoCallback cb = g_pendingCallbacks[type];
    if (!g_persistentCallbacks[type]) {
        g_pendingCallbacks[type] = NULL; /* 一次性：非持久 callback 清除 */
    }

    if (cb != NULL) {
        KosmoResult result = {
            .requestType = type,
            .errorCode = errorCode,
            .data = data,
            .dataLen = dataLen,
        };
        cb(&result);
    }
}

/* KosmoApi_Request 实现在文件末尾（Phase 2 分发逻辑） */

void KosmoApi_RegisterCallback(KosmoRequestType type, KosmoCallback cb, bool persistent)
{
    if (type >= KOSMO_REQ_NUM) return;
    g_pendingCallbacks[type] = cb;
    g_persistentCallbacks[type] = persistent;
}

void KosmoApi_ClearCallback(KosmoRequestType type)
{
    if (type >= KOSMO_REQ_NUM) return;
    g_pendingCallbacks[type] = NULL;
    g_persistentCallbacks[type] = false;
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
 * KosmoApi_Request() — 统一异步入口
 *
 * 当前实现：分发到 GuiModel* 包装函数（保留旧 signal 回传机制）。
 * Phase 3 将改为：分发到 Model* 内部函数 + KosmoCallback 回传。
 * Phase 4 将改为：逻辑直接内联，移除 gui_model.h 依赖。
 *
 * callback 参数暂时未使用（Model* 函数仍通过 GuiApiEmitSignal 回传结果）。
 * Phase 3 完成后将启用。
 */
int32_t KosmoApi_Request(const KosmoRequest *request, KosmoCallback cb)
{
    if (request == NULL) return KOSMO_ERR_INVALID;

    /* 存储 callback（cb=NULL 时保留已有 callback，不清除） */
    if (request->type < KOSMO_REQ_NUM && cb != NULL) {
        g_pendingCallbacks[request->type] = cb;
        g_persistentCallbacks[request->type] = request->persistent;
    }

    switch (request->type) {
    /* ── 助记词 / 钱包创建 ─────────────────────────── */
    case KOSMO_REQ_BIP39_GENERATE_ENTROPY: {
        GuiModelBip39UpdateMnemonic(request->bip39_generate.wordCnt);
        return KOSMO_OK;
    }
    case KOSMO_REQ_BIP39_WRITE_SE: {
        Bip39Data_t d = { .wordCnt = request->bip39_write_se.wordCnt,
                          .forget = request->bip39_write_se.forget };
        GuiModelBip39CalWriteSe(d);
        return KOSMO_OK;
    }
    case KOSMO_REQ_BIP39_VERIFY_MNEMONIC: {
        GuiModelBip39RecoveryCheck(request->bip39_verify.wordCnt);
        return KOSMO_OK;
    }
    case KOSMO_REQ_BIP39_UPDATE_MNEMONIC: {
        GuiModelBip39UpdateMnemonic(request->bip39_update.wordCnt);
        return KOSMO_OK;
    }
    case KOSMO_REQ_BIP39_UPDATE_MNEMONIC_DICE: {
        GuiModelBip39UpdateMnemonicWithDiceRolls(request->bip39_update_dice.wordCnt);
        return KOSMO_OK;
    }
    case KOSMO_REQ_BIP39_FORGET_PASSWORD: {
        GuiModelBip39ForgetPassword(request->bip39_forget.wordCnt);
        return KOSMO_OK;
    }
    case KOSMO_REQ_SLIP39_GENERATE_ENTROPY: {
        Slip39Data_t d = { .threShold = request->slip39_generate.threshold,
                           .memberCnt = request->slip39_generate.memberCnt,
                           .wordCnt = request->slip39_generate.wordCnt,
                           .forget = request->slip39_generate.forget };
        GuiModelSlip39UpdateMnemonic(d);
        return KOSMO_OK;
    }
    case KOSMO_REQ_SLIP39_WRITE_SE: {
        GuiModelSlip39WriteSe(request->slip39_write_se.wordCnt);
        return KOSMO_OK;
    }
    case KOSMO_REQ_SLIP39_CAL_WRITE_SE: {
        Slip39Data_t d = { .threShold = request->slip39_cal_write.threshold,
                           .memberCnt = request->slip39_cal_write.memberCnt,
                           .wordCnt = request->slip39_cal_write.wordCnt,
                           .forget = request->slip39_cal_write.forget };
        GuiModelSlip39CalWriteSe(d);
        return KOSMO_OK;
    }
    case KOSMO_REQ_SLIP39_UPDATE_MNEMONIC: {
        Slip39Data_t d = { .threShold = request->slip39_update.threshold,
                           .memberCnt = request->slip39_update.memberCnt,
                           .wordCnt = request->slip39_update.wordCnt };
        GuiModelSlip39UpdateMnemonic(d);
        return KOSMO_OK;
    }
    case KOSMO_REQ_SLIP39_UPDATE_MNEMONIC_DICE: {
        Slip39Data_t d = { .threShold = request->slip39_update_dice.threshold,
                           .memberCnt = request->slip39_update_dice.memberCnt,
                           .wordCnt = request->slip39_update_dice.wordCnt };
        GuiModelSlip39UpdateMnemonicWithDiceRolls(d);
        return KOSMO_OK;
    }
    case KOSMO_REQ_SLIP39_FORGET_PASSWORD: {
        Slip39Data_t d = { .threShold = request->slip39_forget.threshold,
                           .memberCnt = request->slip39_forget.memberCnt,
                           .wordCnt = request->slip39_forget.wordCnt,
                           .forget = request->slip39_forget.forget };
        GuiModelSlip39ForgetPassword(d);
        return KOSMO_OK;
    }
    case KOSMO_REQ_WRITE_SE: {
        GuiModelWriteSe();
        return KOSMO_OK;
    }

    /* ── 账户管理 ─────────────────────────────────── */
    case KOSMO_REQ_GET_ACCOUNT: {
        GuiModeGetAccount();
        return KOSMO_OK;
    }
    case KOSMO_REQ_GET_WALLET_DESC: {
        GuiModeGetWalletDesc();
        return KOSMO_OK;
    }
    case KOSMO_REQ_SAVE_WALLET_DESC: {
        WalletDesc_t w = { .iconIndex = request->save_wallet_desc.iconIndex };
        strncpy(w.name, request->save_wallet_desc.name, WALLET_NAME_MAX_LEN);
        w.name[WALLET_NAME_MAX_LEN] = '\0';
        GuiModelSettingSaveWalletDesc(&w);
        return KOSMO_OK;
    }
    case KOSMO_REQ_DEL_WALLET_DESC: {
        GuiModelSettingDelWalletDesc();
        return KOSMO_OK;
    }
    case KOSMO_REQ_DEL_ALL_WALLET_DESC: {
        GuiModelLockedDeviceDelAllWalletDesc();
        return KOSMO_OK;
    }
    case KOSMO_REQ_WRITE_PASSPHRASE: {
        GuiModelSettingWritePassphrase();
        return KOSMO_OK;
    }
    case KOSMO_REQ_CHANGE_PASSWORD: {
        GuiModelChangeAccountPassWord();
        return KOSMO_OK;
    }
    case KOSMO_REQ_VERIFY_PASSWORD: {
        uint16_t param = request->verify_password.signalId;
        GuiModelVerifyAccountPassWord(&param);
        return KOSMO_OK;
    }
    case KOSMO_REQ_WRITE_LOCK_TIME: {
        GuiModelWriteLastLockDeviceTime(request->uint32_param.value);
        return KOSMO_OK;
    }

    /* ── 系统操作 ─────────────────────────────────── */
    case KOSMO_REQ_CALCULATE_CHECKSUM: {
        GuiModelCalculateCheckSum();
        return KOSMO_OK;
    }
    case KOSMO_REQ_STOP_CHECKSUM: {
        GuiModelStopCalculateCheckSum();
        return KOSMO_OK;
    }
    case KOSMO_REQ_CALCULATE_SHA256: {
        GuiModelCalculateBinSha256();
        return KOSMO_OK;
    }
    case KOSMO_REQ_FORMAT_SD_CARD: {
        GuiModelFormatMicroSd();
        return KOSMO_OK;
    }
    case KOSMO_REQ_COPY_SD_CARD_OTA: {
        GuiModelCopySdCardOta();
        return KOSMO_OK;
    }
    case KOSMO_REQ_UPDATE_BOOT: {
        GuiModelUpdateBoot();
        return KOSMO_OK;
    }
    case KOSMO_REQ_CALCULATE_WEB_AUTH_CODE: {
        GuiModelCalculateWebAuthCode(request->raw_ptr.ptr);
        return KOSMO_OK;
    }
    case KOSMO_REQ_CONTROL_QR_DECODE: {
        GuiModeControlQrDecode(request->bool_param.enable);
        return KOSMO_OK;
    }

    /* ── UR 操作 ──────────────────────────────────── */
    case KOSMO_REQ_UR_GENERATE_QR: {
        /* GenerateUR 函数指针通过 raw_ptr 传入 */
        GuiModelURGenerateQRCode((GenerateUR)request->raw_ptr.ptr);
        return KOSMO_OK;
    }
    case KOSMO_REQ_UR_UPDATE: {
        GuiModelURUpdate();
        return KOSMO_OK;
    }
    case KOSMO_REQ_UR_CLEAR: {
        GuiModelURClear();
        return KOSMO_OK;
    }

    /* ── 交易 ─────────────────────────────────────── */
    case KOSMO_REQ_CHECK_TRANSACTION: {
        GuiModelCheckTransaction((ViewType)request->view_type.viewType);
        return KOSMO_OK;
    }
    case KOSMO_REQ_CLEAR_CHECK_RESULT: {
        GuiModelTransactionCheckResultClear();
        return KOSMO_OK;
    }
    case KOSMO_REQ_PARSE_TRANSACTION: {
        /* ReturnVoidPointerFunc 通过 raw_ptr 传入 */
        GuiModelParseTransaction((ReturnVoidPointerFunc)request->raw_ptr.ptr);
        return KOSMO_OK;
    }
    case KOSMO_REQ_PARSE_TRANSACTION_RAW: {
        GuiModelParseTransactionRawData();
        return KOSMO_OK;
    }
    case KOSMO_REQ_PARSE_TRANSACTION_RAW_DELAY: {
        GuiModelTransactionParseRawDataDelay();
        return KOSMO_OK;
    }

    /* ── RSA ──────────────────────────────────────── */
    case KOSMO_REQ_RSA_GENERATE_KEYPAIR: {
        GuiModelRsaGenerateKeyPair();
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

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
#include "secret_cache.h"

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

/* ── 初始化 ─────────────────────────────────────────── */

void KosmoApi_Init(void)
{
    memset(g_pendingCallbacks, 0, sizeof(g_pendingCallbacks));
}

/* ── 异步请求 ───────────────────────────────────────── */

int32_t KosmoApi_Request(const KosmoRequest *request, KosmoCallback cb)
{
    if (request == NULL || request->type >= KOSMO_REQ_NUM) {
        return KOSMO_ERR_INVALID;
    }
    /* Phase 2: 路由到原 gui_model 的 Model 函数 */
    (void)cb;
    return KOSMO_ERR_GENERAL;
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

/* ── 同步查询：链信息 ───────────────────────────────── */

const char *KosmoApi_GetPublicKey(KosmoChainType chain)
{
    uint32_t xpubType = KosmoChainToXPubType(chain);
    if (xpubType == XPUB_TYPE_NUM) return NULL;
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

bool KosmoApi_GetPassphraseQuickAccess(void)
{
    return GetPassphraseQuickAccess();
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

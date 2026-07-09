/*
 * kosmo_api.c — 后端操作统一接口实现
 *
 * Phase 0: 空实现骨架。
 * Phase 1: 全局状态隔离。
 * Phase 2: 完整实现（替代 gui_model.c）。
 */

#include "kosmo_api.h"
#include <string.h>

#ifndef COMPILE_SIMULATOR
#include "cmsis_os.h"
#include "user_msg.h"
#include "user_memory.h"
#else
#include <stdlib.h>
#include <string.h>
#endif

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
    /* 目前返回未实现 */
    (void)cb;
    return KOSMO_ERR_GENERAL;
}

/* ── 同步查询 ───────────────────────────────────────── */

int32_t KosmoApi_GetAccountInfo(KosmoAccountInfo *out)
{
    /* Phase 1: 实现 */
    (void)out;
    return KOSMO_ERR_GENERAL;
}

int32_t KosmoApi_GetChainList(KosmoChainInfo *out, int *count)
{
    /* Phase 1: 实现 */
    (void)out;
    (void)count;
    return KOSMO_ERR_GENERAL;
}

bool KosmoApi_IsMoneroSupported(void)
{
    /* Phase 1: 包装 IsMoneroSupportedForCurrentMnemonic() */
    return false;
}

bool KosmoApi_IsZcashSupported(void)
{
    /* Phase 1: 包装 IsZcashSupportedForCurrentMnemonic() */
    return false;
}

int32_t KosmoApi_GetBip39Word(int index, char *word, int len)
{
    /* Phase 1: 包装 bip39_english wordlist */
    (void)index;
    (void)word;
    (void)len;
    return KOSMO_ERR_GENERAL;
}

int32_t KosmoApi_ValidateWord(const char *word, int *index)
{
    /* Phase 1: 包装 bip39_english 查找 */
    (void)word;
    (void)index;
    return KOSMO_ERR_GENERAL;
}

bool KosmoApi_GetPassphraseQuickAccess(void)
{
    /* Phase 1: 包装 GetPassphraseQuickAccess() */
    return false;
}

const char *KosmoApi_GetPublicKey(KosmoChainType chain)
{
    /* Phase 1: 包装 GetCurrentAccountPublicKey() */
    (void)chain;
    return NULL;
}

const char *KosmoApi_GetPath(KosmoChainType chain)
{
    /* Phase 1: 包装 GetCurrentAccountPath() */
    (void)chain;
    return NULL;
}

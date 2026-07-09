/*
 * kosmo_chain.c — 链操作统一接口实现
 *
 * Phase 0: 空实现骨架。
 * Phase 4: 完整实现（替代 gui_chain/ 的 18 个文件）。
 */

#include "kosmo_chain.h"
#include <stdlib.h>
#include <string.h>

/* ── UR 操作 ────────────────────────────────────────── */

KosmoUREncodeResult *KosmoChain_GetSignUR(uint8_t viewType)
{
    /* Phase 4: 路由到各链的 GuiGetXxxSignQrCodeData() */
    (void)viewType;
    return NULL;
}

KosmoUREncodeResult *KosmoChain_GetSignURUnlimited(uint8_t viewType)
{
    /* Phase 4: 路由到各链的 GuiGetXxxSignUrDataUnlimited() */
    (void)viewType;
    return NULL;
}

KosmoCheckResult *KosmoChain_CheckTransaction(uint8_t viewType)
{
    /* Phase 4: 路由到各链的 GuiGetXxxCheckResult() */
    (void)viewType;
    return NULL;
}

KosmoParseResult *KosmoChain_ParseTransaction(uint8_t viewType, const void *urData)
{
    /* Phase 4: 路由到各链的 parse 函数 */
    (void)viewType;
    (void)urData;
    return NULL;
}

KosmoUREncodeResult *KosmoChain_SignTransaction(uint8_t viewType,
                                                 const uint8_t *seed, uint32_t seedLen)
{
    /* Phase 4: 路由到各链的 sign 函数 */
    (void)viewType;
    (void)seed;
    (void)seedLen;
    return NULL;
}

int32_t KosmoChain_GetAddress(KosmoChainType chain, int accountIdx,
                              char *out, int outLen)
{
    /* Phase 4: 路由到各链的地址生成函数 */
    (void)chain;
    (void)accountIdx;
    (void)out;
    (void)outLen;
    return KOSMO_ERR_GENERAL;
}

/* ── 内存释放 ───────────────────────────────────────── */

void KosmoChain_FreeURResult(KosmoUREncodeResult *result)
{
    if (result != NULL) {
        free(result->data);
        free(result->errorMessage);
        free(result);
    }
}

void KosmoChain_FreeCheckResult(KosmoCheckResult *result)
{
    if (result != NULL) {
        free(result->errorMessage);
        free(result);
    }
}

void KosmoChain_FreeParseResult(KosmoParseResult *result)
{
    if (result != NULL) {
        /* displayData 由各链的 free 函数释放，这里只释放容器 */
        free(result->errorMessage);
        free(result);
    }
}

/* ── 过渡期映射 ─────────────────────────────────────── */

uint8_t KosmoChain_ViewTypeRemap(uint8_t viewType)
{
    /* Phase 4: 包装原 ViewTypeReMap() */
    (void)viewType;
    return viewType;
}

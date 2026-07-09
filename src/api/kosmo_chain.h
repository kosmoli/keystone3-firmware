/*
 * kosmo_chain.h — 链操作统一接口
 *
 * 替代 gui_chain/ 下 18 个文件各自直调 Rust FFI 的模式。
 * UI 层通过统一接口操作链，不直接调 Rust 函数。
 *
 * Phase 0: 接口声明。Phase 4: 实现。
 */

#ifndef _KOSMO_CHAIN_H
#define _KOSMO_CHAIN_H

#include "kosmo_types.h"

/* ── UR 编码结果（对应 Rust 的 UREncodeResult）──────── */

typedef struct {
    char *data;           /* UR 字符串 */
    int32_t errorCode;
    char *errorMessage;   /* 错误信息（如果有） */
} KosmoUREncodeResult;

/* ── 交易解析结果（通用容器）────────────────────────── */

typedef struct {
    void *displayData;    /* 链特定的显示数据 */
    int32_t errorCode;
    char *errorMessage;
} KosmoParseResult;

/* ── 交易检查结果 ───────────────────────────────────── */

typedef struct {
    int32_t errorCode;
    char *errorMessage;
} KosmoCheckResult;

/* ── 链操作接口 ─────────────────────────────────────── */

/*
 * 获取签名用的 UR QR 码数据。
 * 替代各链的 GuiGetXxxSignQrCodeData()。
 *
 * @param viewType  原 ViewType 枚举值（过渡期保留，后续改为 KosmoChainType）
 * @return UR 编码结果（调用者需用 KosmoChain_FreeURResult 释放）
 */
KosmoUREncodeResult *KosmoChain_GetSignUR(uint8_t viewType);

/*
 * 获取无限长度的签名 UR 数据。
 * 替代各链的 GuiGetXxxSignUrDataUnlimited()。
 */
KosmoUREncodeResult *KosmoChain_GetSignURUnlimited(uint8_t viewType);

/*
 * 检查交易 UR 数据。
 * 替代各链的 GuiGetXxxCheckResult()。
 *
 * @param viewType  ViewType
 * @return 检查结果（调用者需用 KosmoChain_FreeCheckResult 释放）
 */
KosmoCheckResult *KosmoChain_CheckTransaction(uint8_t viewType);

/*
 * 解析交易 UR 数据为显示格式。
 * 替代各链的 parse 函数。
 *
 * @param viewType  ViewType
 * @param urData    UR 原始数据
 * @return 解析结果
 */
KosmoParseResult *KosmoChain_ParseTransaction(uint8_t viewType, const void *urData);

/*
 * 签名交易。
 * 替代各链的 sign 函数。
 *
 * @param viewType  ViewType
 * @param seed      种子数据
 * @param seedLen   种子长度
 * @return UR 编码结果
 */
KosmoUREncodeResult *KosmoChain_SignTransaction(uint8_t viewType,
                                                 const uint8_t *seed, uint32_t seedLen);

/*
 * 获取地址。
 *
 * @param chain       链类型
 * @param accountIdx  账户索引
 * @param out         输出缓冲区
 * @param outLen      缓冲区长度
 * @return KOSMO_OK 或错误码
 */
int32_t KosmoChain_GetAddress(KosmoChainType chain, int accountIdx,
                              char *out, int outLen);

/* ── 内存释放 ───────────────────────────────────────── */

void KosmoChain_FreeURResult(KosmoUREncodeResult *result);
void KosmoChain_FreeCheckResult(KosmoCheckResult *result);
void KosmoChain_FreeParseResult(KosmoParseResult *result);

/* ── ViewType 到 RemapView 映射（过渡期）────────────── */

/*
 * 原 gui_chain.c 的 ViewTypeReMap()。
 * Phase 4 完成后此函数将被内部化，不再暴露给 UI。
 */
uint8_t KosmoChain_ViewTypeRemap(uint8_t viewType);

#endif /* _KOSMO_CHAIN_H */

/*
 * kosmo_api.h — 后端操作统一接口
 *
 * UI 层通过这组函数与后端交互，替代直接调用 gui_model.c 的 39 个函数。
 * 同步/异步差异封装在 API 层内部，UI 不关心。
 *
 * Phase 0: 接口声明。Phase 2: 实现。
 */

#ifndef _KOSMO_API_H
#define _KOSMO_API_H

#include "kosmo_types.h"

/* ── 初始化 ─────────────────────────────────────────── */

/*
 * 初始化 API 层。在 UI 框架启动前调用一次。
 * 设置内部回调，让后端结果能回到 UI 线程。
 */
void KosmoApi_Init(void);

/* ── 异步请求（后端操作）────────────────────────────── */

/*
 * 发送异步请求。结果通过回调返回。
 * 真机：投递到 FetchSensitiveDataTask 队列，立刻返回。
 * 模拟器：同步执行，回调在调用期间触发。
 *
 * @param request  请求参数（栈上分配，API 内部会拷贝）
 * @param cb       结果回调（可为 NULL）
 * @return KOSMO_OK 或错误码
 */
int32_t KosmoApi_Request(const KosmoRequest *request, KosmoCallback cb);

/* ── 同步查询（状态读取）────────────────────────────── */

/*
 * 获取当前账户信息。
 * @param out  输出参数
 * @return KOSMO_OK 或错误码
 */
int32_t KosmoApi_GetAccountInfo(KosmoAccountInfo *out);

/*
 * 获取链列表。
 * @param out    输出数组（调用者分配）
 * @param count  输入：数组容量；输出：实际数量
 * @return KOSMO_OK 或错误码
 */
int32_t KosmoApi_GetChainList(KosmoChainInfo *out, int *count);

/*
 * 查询当前助记词是否支持 Monero/Zcash。
 */
bool KosmoApi_IsMoneroSupported(void);
bool KosmoApi_IsZcashSupported(void);

/*
 * 获取 BIP-39 词表中的单词。
 * @param index  词索引（0-2047）
 * @param word   输出缓冲区
 * @param len    缓冲区长度
 * @return KOSMO_OK 或错误码
 */
int32_t KosmoApi_GetBip39Word(int index, char *word, int len);

/*
 * 验证单词是否有效，返回其索引。
 * @param word   输入单词
 * @param index  输出索引
 * @return KOSMO_OK 或 KOSMO_ERR_INVALID
 */
int32_t KosmoApi_ValidateWord(const char *word, int *index);

/*
 * 查询密码快捷访问状态。
 */
bool KosmoApi_GetPassphraseQuickAccess(void);

/*
 * 获取当前账户的公钥。
 * @param chain  链类型
 * @return 公钥字符串（只读，不要 free），失败返回 NULL
 */
const char *KosmoApi_GetPublicKey(KosmoChainType chain);

/*
 * 获取当前账户的派生路径。
 * @param chain  链类型
 * @return 路径字符串（只读），失败返回 NULL
 */
const char *KosmoApi_GetPath(KosmoChainType chain);

/* ── 便捷宏 ─────────────────────────────────────────── */

/* 简化异步调用：自动构造 KosmoRequest */
#define KOSMO_REQ_BIP39_GENERATE(wordCnt_, cb_) \
    do { KosmoRequest _req = { .type = KOSMO_REQ_BIP39_GENERATE_ENTROPY, \
         .bip39_generate = { .wordCnt = (wordCnt_) } }; \
         KosmoApi_Request(&_req, (cb_)); } while(0)

#define KOSMO_REQ_WRITE_SE(cb_) \
    do { KosmoRequest _req = { .type = KOSMO_REQ_WRITE_SE }; \
         KosmoApi_Request(&_req, (cb_)); } while(0)

#endif /* _KOSMO_API_H */

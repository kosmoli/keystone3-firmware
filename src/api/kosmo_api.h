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

/*
 * 后端结果通知。Model* 函数完成后调用，触发 UI 注册的 callback。
 * 替代 GuiApiEmitSignal() 全局广播。
 *
 * @param type      请求类型（用于查找对应 callback）
 * @param errorCode 结果码（KOSMO_OK 或错误码）
 * @param data      结果数据（可为 NULL）
 * @param dataLen   数据长度
 */
void KosmoApi_NotifyResult(KosmoRequestType type, int32_t errorCode, void *data, uint32_t dataLen);

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
 * 获取当前账户的多路径公钥。
 * @param chain         链类型
 * @param pathIndex     路径索引（0=标准路径，1+=Ledger Live 等）
 * @param derivationType ADA 专用：0=STANDARD_ADA, 1=LEDGER_ADA。其他链忽略。
 * @return 公钥字符串（只读），失败返回 NULL
 *
 * 路径索引映射：
 *   ETH: 0=BIP44, 1=Ledger Legacy, 2-11=Ledger Live 0-9
 *   SOL: 0-49=BIP44, 50=Root, 51-100=Change 0-49
 *   AVAX: 0=BIP44, 1-10=X/P 0-9
 *   ADA: 0-23=账户索引（base 由 derivationType 决定）
 *   其他链：忽略 pathIndex，等同于 KosmoApi_GetPublicKey
 */
const char *KosmoApi_GetPublicKeyByPath(KosmoChainType chain, int pathIndex, int derivationType);

/* 原始 ChainType 版本，Phase 4 过渡用 */
const char *KosmoApi_GetPublicKeyRaw(uint32_t xpubType);

/*
 * 获取当前账户的派生路径。
 * @param chain  链类型
 * @return 路径字符串（只读），失败返回 NULL
 */
const char *KosmoApi_GetPath(KosmoChainType chain);

/*
 * 获取当前账户的种子数据（用于签名）。
 * 自动处理 BIP39（64 字节 seed）vs TON（entropy）差异。
 * @param out      输出缓冲区（调用者分配，至少 64 字节）
 * @param outLen   输出：实际数据长度
 * @return KOSMO_OK 或错误码
 */
int32_t KosmoApi_GetSeed(uint8_t *out, uint32_t *outLen);

/*
 * 获取当前助记词类型。
 */
KosmoMnemonicType KosmoApi_GetMnemonicType(void);

/*
 * 获取当前账户的种子长度。
 * BIP39: 64 字节, TON: 32 字节。
 */
uint32_t KosmoApi_GetSeedLen(void);

/*
 * 获取当前账户的熵长度。
 */
uint32_t KosmoApi_GetEntropyLen(void);

/*
 * 获取当前账户索引。
 */
uint8_t KosmoApi_GetCurrentAccountIndex(void);

/*
 * 获取已存在的账户数量。
 * @return 账户数量
 */
uint8_t KosmoApi_GetAccountCount(void);

/* ── 账户状态（account_public_info 包装）────────────── */

/*
 * 获取链的接收路径索引。
 * @param chainName  链名（如 "BTC", "ETH"）
 */
uint32_t KosmoApi_GetAccountReceiveIndex(const char *chainName);
void KosmoApi_SetAccountReceiveIndex(const char *chainName, uint32_t index);
uint32_t KosmoApi_GetAccountReceivePath(const char *chainName);
void KosmoApi_SetAccountReceivePath(const char *chainName, uint32_t index);

/*
 * 获取/设置链的账户索引（多账户用）。
 */
uint32_t KosmoApi_GetAccountIndex(const char *chainName);
void KosmoApi_SetAccountIndex(const char *chainName, uint32_t index);

/* ── 种子/熵/密码（keystore 包装）───────────────────── */

/*
 * 获取账户种子。
 * @param accountIndex  账户索引
 * @param out           输出缓冲区
 * @param password      设备密码
 * @return KOSMO_OK 或错误码
 */
int32_t KosmoApi_GetAccountSeed(uint8_t accountIndex, uint8_t *out, const char *password);

/*
 * 获取账户熵。
 */
int32_t KosmoApi_GetAccountEntropy(uint8_t accountIndex, uint8_t *entropy, uint8_t *entropyLen, const char *password);

/*
 * 获取账户密码短语。
 * @return 密码短语字符串（只读，不要 free）
 */
char *KosmoApi_GetPassphrase(uint8_t accountIndex);

/*
 * 检查 Solana 派生路径是否支持。
 * @param path  HD 路径字符串
 * @return 对应的 KosmoChainType，不支持返回 KOSMO_CHAIN_NUM
 */
KosmoChainType KosmoApi_CheckSolPathSupport(const char *path);

/*
 * 填充首页钱包列表（替代 AccountPublicHomeCoinGet）。
 * @param walletList  输出数组
 * @param count       数组容量
 */
void KosmoApi_GetHomeCoinList(void *walletList, uint8_t count);

/*
 * Zcash 特有操作。
 */
int32_t KosmoApi_GetZcashSFP(uint8_t accountIndex, uint8_t *outSFP);
int32_t KosmoApi_GetZcashUFVK(uint8_t accountIndex, char *outUFVK);

/* ── ChainType 映射（过渡期内部使用）────────────────── */

/*
 * KosmoChainType → 原 ChainType（XPUB_TYPE_*）的主类型映射。
 * Phase 4 完成后将被内部化。
 */
uint32_t KosmoChainToXPubType(KosmoChainType chain);

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

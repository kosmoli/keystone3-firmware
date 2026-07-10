/*
 * kosmo_types.h — 共享数据类型
 *
 * UI 层和后端层共用的类型定义。双方只 include 这个文件，
 * 不直接 include account_manager.h / account_public_info.h 等后端头文件。
 *
 * Phase 0: 类型声明，后续阶段逐步从原头文件迁移实现。
 */

#ifndef _KOSMO_TYPES_H
#define _KOSMO_TYPES_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

/* ── 错误码 ─────────────────────────────────────────── */

#define KOSMO_OK              0
#define KOSMO_ERR_GENERAL    -1
#define KOSMO_ERR_INVALID    -2
#define KOSMO_ERR_BUSY       -3
#define KOSMO_ERR_TIMEOUT    -4

/* ── 助记词类型 ─────────────────────────────────────── */

typedef enum {
    KOSMO_MNEMONIC_BIP39  = 0,
    KOSMO_MNEMONIC_SLIP39 = 1,
    KOSMO_MNEMONIC_TON    = 2,
} KosmoMnemonicType;

/* ── 密码类型 ───────────────────────────────────────── */

typedef enum {
    KOSMO_PASSCODE_PIN      = 0,
    KOSMO_PASSCODE_PASSWORD = 1,
} KosmoPasscodeType;

/* ── 链类型（精简版，替代原 220+ 的 ChainType 枚举）─── */

typedef enum {
    KOSMO_CHAIN_BTC_LEGACY = 0,
    KOSMO_CHAIN_BTC_SEGWIT,
    KOSMO_CHAIN_BTC_NATIVE_SEGWIT,
    KOSMO_CHAIN_BTC_TAPROOT,
    KOSMO_CHAIN_LTC,
    KOSMO_CHAIN_DOGE,
    KOSMO_CHAIN_DASH,
    KOSMO_CHAIN_BCH,
    KOSMO_CHAIN_ETH,
    KOSMO_CHAIN_TRX,
    KOSMO_CHAIN_COSMOS,
    KOSMO_CHAIN_XRP,
    KOSMO_CHAIN_AVAX,
    KOSMO_CHAIN_IOTA,
    KOSMO_CHAIN_SOL,
    KOSMO_CHAIN_SUI,
    KOSMO_CHAIN_APT,
    KOSMO_CHAIN_ADA,
    KOSMO_CHAIN_ARWEAVE,
    KOSMO_CHAIN_STELLAR,
    KOSMO_CHAIN_TON,
    KOSMO_CHAIN_ZEC,
    KOSMO_CHAIN_XMR,
    KOSMO_CHAIN_NUM,
} KosmoChainType;

/* ── 请求类型（对应原 gui_model 的 39 个操作）───────── */

typedef enum {
    /* 助记词 / 钱包创建 */
    KOSMO_REQ_BIP39_GENERATE_ENTROPY = 0,   /* 生成助记词 */
    KOSMO_REQ_BIP39_WRITE_SE,                /* 写入 SE */
    KOSMO_REQ_BIP39_VERIFY_MNEMONIC,         /* 验证助记词 */
    KOSMO_REQ_BIP39_UPDATE_MNEMONIC,         /* 更新助记词（骰子） */
    KOSMO_REQ_BIP39_UPDATE_MNEMONIC_DICE,    /* 骰子路径更新助记词 */
    KOSMO_REQ_BIP39_FORGET_PASSWORD,         /* 忘记密码 */
    KOSMO_REQ_SLIP39_GENERATE_ENTROPY,       /* SLIP39 生成 */
    KOSMO_REQ_SLIP39_WRITE_SE,               /* SLIP39 写入 SE */
    KOSMO_REQ_SLIP39_CAL_WRITE_SE,           /* SLIP39 计算+写入 */
    KOSMO_REQ_SLIP39_UPDATE_MNEMONIC,        /* SLIP39 更新 */
    KOSMO_REQ_SLIP39_UPDATE_MNEMONIC_DICE,   /* SLIP39 骰子更新 */
    KOSMO_REQ_SLIP39_FORGET_PASSWORD,        /* SLIP39 忘记密码 */
    KOSMO_REQ_WRITE_SE,                      /* 通用写入 SE */

    /* 账户管理 */
    KOSMO_REQ_GET_ACCOUNT,                   /* 获取账户列表 */
    KOSMO_REQ_GET_WALLET_DESC,               /* 获取钱包描述 */
    KOSMO_REQ_SAVE_WALLET_DESC,              /* 保存钱包描述 */
    KOSMO_REQ_DEL_WALLET_DESC,               /* 删除钱包描述 */
    KOSMO_REQ_DEL_ALL_WALLET_DESC,           /* 删除所有钱包描述 */
    KOSMO_REQ_WRITE_PASSPHRASE,              /* 写入 passphrase */
    KOSMO_REQ_CHANGE_PASSWORD,               /* 修改密码 */
    KOSMO_REQ_VERIFY_PASSWORD,               /* 验证密码 */
    KOSMO_REQ_WRITE_LOCK_TIME,               /* 写入锁定时间 */

    /* 系统操作 */
    KOSMO_REQ_CALCULATE_CHECKSUM,            /* 计算 checksum */
    KOSMO_REQ_STOP_CHECKSUM,                 /* 停止 checksum */
    KOSMO_REQ_CALCULATE_SHA256,              /* 计算 SHA256 */
    KOSMO_REQ_FORMAT_SD_CARD,                /* 格式化 SD 卡 */
    KOSMO_REQ_COPY_SD_CARD_OTA,              /* SD 卡 OTA 复制 */
    KOSMO_REQ_UPDATE_BOOT,                   /* 更新 boot */
    KOSMO_REQ_CALCULATE_WEB_AUTH_CODE,       /* 计算 WebAuth 码 */
    KOSMO_REQ_CONTROL_QR_DECODE,             /* 控制 QR 解码 */

    /* UR 操作 */
    KOSMO_REQ_UR_GENERATE_QR,                /* 生成 UR QR 码 */
    KOSMO_REQ_UR_UPDATE,                     /* 更新 UR */
    KOSMO_REQ_UR_CLEAR,                      /* 清除 UR */

    /* 交易 */
    KOSMO_REQ_CHECK_TRANSACTION,             /* 检查交易 */
    KOSMO_REQ_CLEAR_CHECK_RESULT,            /* 清除检查结果 */
    KOSMO_REQ_PARSE_TRANSACTION,             /* 解析交易 */
    KOSMO_REQ_PARSE_TRANSACTION_RAW,         /* 解析原始交易 */
    KOSMO_REQ_PARSE_TRANSACTION_RAW_DELAY,   /* 延迟解析原始交易 */

    /* RSA */
    KOSMO_REQ_RSA_GENERATE_KEYPAIR,          /* 生成 RSA 密钥对 */

    KOSMO_REQ_NUM,
} KosmoRequestType;

/* ── 请求参数 ───────────────────────────────────────── */

typedef struct {
    KosmoRequestType type;
    union {
        /* BIP39 */
        struct { uint8_t wordCnt; } bip39_generate;
        struct { uint8_t wordCnt; bool forget; } bip39_write_se;
        struct { uint8_t wordCnt; } bip39_verify;
        struct { uint8_t wordCnt; } bip39_update;
        struct { uint8_t wordCnt; } bip39_update_dice;
        struct { uint8_t wordCnt; } bip39_forget;

        /* SLIP39 */
        struct { uint8_t threshold; uint8_t memberCnt; uint8_t wordCnt; bool forget; } slip39_generate;
        struct { uint8_t wordCnt; } slip39_write_se;
        struct { uint8_t threshold; uint8_t memberCnt; uint8_t wordCnt; bool forget; } slip39_cal_write;
        struct { uint8_t threshold; uint8_t memberCnt; uint8_t wordCnt; } slip39_update;
        struct { uint8_t threshold; uint8_t memberCnt; uint8_t wordCnt; } slip39_update_dice;
        struct { uint8_t threshold; uint8_t memberCnt; uint8_t wordCnt; bool forget; } slip39_forget;

        /* 账户 */
        struct { uint8_t iconIndex; char name[17]; } save_wallet_desc;
        struct { uint16_t errorCount; } verify_password;

        /* 通用 */
        struct { uint32_t value; } uint32_param;
        struct { bool enable; } bool_param;
        struct { uint8_t viewType; } view_type;
        struct { void *ptr; } raw_ptr;
    };
} KosmoRequest;

/* ── 异步结果 ───────────────────────────────────────── */

typedef struct {
    KosmoRequestType requestType;  /* 对应哪个请求 */
    int32_t errorCode;             /* KOSMO_OK 或错误码 */
    void *data;                    /* 结果数据（如果有的话） */
    uint32_t dataLen;              /* 数据长度 */
} KosmoResult;

/* ── 回调类型 ───────────────────────────────────────── */

typedef void (*KosmoCallback)(const KosmoResult *result);

/* ── 账户信息（只读查询用）──────────────────────────── */

typedef struct {
    uint8_t accountIndex;
    uint8_t iconIndex;
    char walletName[17];
    uint8_t mfp[4];                /* master fingerprint */
    KosmoMnemonicType mnemonicType;
    KosmoPasscodeType passcodeType;
    bool passphraseMark;
    bool passphraseQuickAccess;
} KosmoAccountInfo;

/* ── 链信息（只读查询用）────────────────────────────── */

typedef struct {
    KosmoChainType type;
    const char *name;              /* "BTC", "ETH", ... */
    const char *hdPath;            /* "m/84'/0'/0'" */
    const char *xpub;              /* 当前账户的公钥 */
    bool supported;                /* 当前助记词是否支持此链 */
} KosmoChainInfo;

/* ── 助记词操作结果 ─────────────────────────────────── */

typedef struct {
    const char *mnemonic;          /* 助记词字符串 */
    uint8_t wordCnt;               /* 12 或 24 */
    int32_t errorCode;
} KosmoMnemonicResult;

#endif /* _KOSMO_TYPES_H */

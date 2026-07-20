# Phase 6 Analysis: Signing Service API — Comprehensive Report

> **Goal**: Move all transaction signing from the frontend (`gui_chain/*.c`) to the backend
> (`kosmo_api.c` Model* handlers), so the frontend never touches seeds/passwords.

---

## 1. Inventory of All Chain Signing Code

### Summary Table

| Chain | Frontend File | Signing Function(s) | Seed Access | Uses SignInternal | Complexity | ViewTypes |
|-------|--------------|---------------------|-------------|-------------------|------------|-----------|
| **ETH** | `gui_eth.c` (73K) | `eth_sign_tx`, `eth_sign_tx_unlimited`, `eth_sign_tx_bytes`, `eth_sign_tx_dynamic` | `KosmoApi_GetSeed()` | No (custom) | **High** | EthTx, EthPersonalMessage, EthTypedData |
| **ETH Batch** | `gui_eth_batch_tx_widgets.c` | `eth_sign_batch_tx` (via `KosmoApi_EthSignBatchTx`) | `KosmoApi_GetAccountSeed()` + `KosmoApi_CacheGetPassword()` | No | **Medium** | EthBatchTx |
| **BTC** (+LTC/DOGE/DASH/BCH) | `gui_btc.c` (49.6K) | `btc_sign_psbt`, `btc_sign_psbt_unlimited`, `btc_sign_multisig_psbt`, `utxo_sign_keystone`, `btc_sign_msg`, `sign_seed_signer_message` | `GetAccountSeed()` + `SecretCacheGetPassword()` | No (custom) | **Very High** | BtcNativeSegwitTx, BtcSegwitTx, BtcLegacyTx, BtcTx, BtcMsg |
| **SOL** | `gui_sol.c` (66.8K) | `solana_sign_tx` | `KosmoApi_GetSeed()` | No (inline) | **Low** | SolanaTx, SolanaMessage |
| **ADA** | `gui_ada.c` (44K) | `cardano_sign_tx`, `cardano_sign_tx_unlimited`, `cardano_sign_tx_with_ledger_bitbox02`, `cardano_sign_sign_data`, `cardano_sign_sign_cip8_data`, `cardano_sign_catalyst` + Ledger variants | `GetAccountAdaEntropy()` → `SecretCacheGetPassword()` | No (custom) | **Very High** | CardanoTx, CardanoSignTxHash, CardanoSignData, CardanoSignCip8Data, CardanoCatalystVotingRegistration |
| **TON** | `gui_ton.c` (17.2K) | `ton_sign_transaction`, `ton_sign_proof` | `KosmoApi_GetSeed()` | No (inline) | **Low** | TonTx, TonSignProof |
| **TRX/TRON** | `gui_trx.c` (14.6K) | `tron_sign_request`, `tron_sign_keystone` | `KosmoApi_GetSeed()` | No (inline) | **Medium** | TronTx, TronPersonalMessage, TronSwapTx |
| **COSMOS** | `gui_cosmos.c` (24.8K) | `cosmos_sign_tx` | `KosmoApi_GetSeed()` | No (inline) | **Medium** | CosmosTx, CosmosEvmTx |
| **AVAX** | `gui_avax.c` (9.5K) | `avax_sign`, `avax_sign_unlimited` | Via `SignInternal` → `KosmoApi_GetSeed()` | **Yes** | **Low** | AvaxTx |
| **SUI** | `gui_sui.c` (12.2K) | `sui_sign_intent`, `sui_sign_hash` | Via `SignInternal` → `KosmoApi_GetSeed()` | **Yes** | **Low** | SuiTx, SuiSignMessageHash |
| **IOTA** | `gui_iota.c` (7.3K) | `iota_sign_intent`, `iota_sign_hash` | Via `SignInternal` → `KosmoApi_GetSeed()` | **Yes** | **Low** | IotaTx, IotaSignMessageHash |
| **APTOS** | `gui_aptos.c` (4.1K) | `aptos_sign_tx` | `KosmoApi_GetSeed()` | No (inline) | **Low** | AptosTx |
| **XRP** | `gui_xrp.c` (6.3K) | `xrp_sign_tx_bytes`, `xrp_sign_tx` | `KosmoApi_GetSeed()` | No (inline) | **Medium** | XRPTx |
| **STELLAR** | `gui_stellar.c` (4.7K) | `stellar_sign` | `KosmoApi_GetSeed()` | No (inline) | **Low** | StellarTx, StellarHash |
| **MONERO** | `gui_monero.c` (17K) | `monero_generate_keyimage`, `monero_generate_signature` | `KosmoApi_GetSeed()` | No (inline) | **Medium** | XmrOutput, XmrTxUnsigned |
| **ZCASH** | `gui_zcash.c` (12.4K) | `sign_zcash_tx` | Via `SignInternal` → `KosmoApi_GetSeed()` | **Yes** | **Medium** | ZcashTx |
| **ARWEAVE** | `gui_ar.c` (14.8K) | `ar_sign_tx` | `FlashReadRsaPrimes()` (**RSA, not seed!**) | No (custom) | **Medium** | ArweaveTx, ArweaveMessage, ArweaveDataItem |

### Chains NOT in gui_chain/ (no frontend signing)
- **NEAR**: Rust `near_sign_tx` exists but no `gui_near.c`. Not wired up for signing.
- **DOT/KSM**: Listed in `COMPANION_APP_COINS_ENUM` only. No signing code.
- **FIRO**: Not present in the codebase.

---

## 2. Existing KosmoApi_Request Pattern

### Current Request Types (kosmo_types.h)
```
KOSMO_REQ_BIP39_GENERATE_ENTROPY .. KOSMO_REQ_BIP39_FORGET_PASSWORD  (7)
KOSMO_REQ_SLIP39_GENERATE_ENTROPY .. KOSMO_REQ_SLIP39_FORGET_PASSWORD (5)
KOSMO_REQ_WRITE_SE                                                     (1)
KOSMO_REQ_GET_ACCOUNT .. KOSMO_REQ_WRITE_LOCK_TIME                    (8)
KOSMO_REQ_CALCULATE_CHECKSUM .. KOSMO_REQ_CONTROL_QR_DECODE          (6)
KOSMO_REQ_UR_GENERATE_QR .. KOSMO_REQ_UR_CLEAR                       (3)
KOSMO_REQ_CHECK_TRANSACTION .. KOSMO_REQ_PARSE_TRANSACTION_RAW_DELAY (5)
KOSMO_REQ_RSA_GENERATE_KEYPAIR                                         (1)
```
**Total: 36 request types. NO signing request types exist yet.**

### Handler Pattern
```c
// Frontend calls:
KosmoApi_Request(&request, callback);

// kosmo_api.c dispatches:
switch (request->type) {
    case KOSMO_REQ_*: {
        static SomeParam_t s_param;
        s_param = ...;
        AsyncExecute(ModelHandler, &s_param, sizeof(s_param));
        return KOSMO_OK;
    }
}

// Model handler runs on FetchSensitiveDataTask:
static int32_t ModelHandler(const void *inData, uint32_t inDataLen) {
    // ... do work ...
    KosmoApi_NotifyResult(KOSMO_REQ_*, errorCode, data, dataLen);
    return ret;
}

// UI callback receives result:
void myCallback(const KosmoResult *result) {
    if (result->errorCode == KOSMO_OK) { ... }
}
```

### Key: AsyncExecute runs the function on `FetchSensitiveDataTask` (NOT the UI thread).
This is exactly what we need for signing — move signing off the UI thread.

---

## 3. Rust Signing Layer

### All C-callable Sign Functions

Every Rust signing function follows this pattern:
```rust
pub unsafe extern "C" fn chain_sign_tx(
    ptr: PtrUR,           // parsed UR data (transaction)
    seed: PtrBytes,       // seed bytes
    seed_len: u32,        // seed length
) -> PtrT<UREncodeResult>  // encoded UR result
```

**Variations:**
| Function | Extra Parameters |
|----------|-----------------|
| `eth_sign_tx_bytes` | + `mfp: PtrBytes, mfp_len: u32` |
| `btc_sign_psbt` / `btc_sign_psbt_unlimited` | + `mfp: PtrBytes, mfp_len: u32` |
| `btc_sign_multisig_psbt` | + `mfp`, `mfp_len` |
| `utxo_sign_keystone` | + `ur_type`, `mfp`, `xPub`, `version` |
| `cardano_sign_tx` | + `mfp`, `xpub`, `passphrase`, `is_unlimited`, `is_slip39` |
| `cardano_sign_tx_with_ledger_bitbox02` | + `mfp`, `xpub`, `mnemonic`, `passphrase`, `is_unlimited` |
| `cosmos_sign_tx` | + `ur_type: QRCodeType` |
| `tron_sign_request` | + `fragment_len: usize` |
| `tron_sign_keystone` | + `ur_type`, `mfp`, `xPub`, `version` |
| `xrp_sign_tx` | + `hd_path: PtrString` |
| `xrp_sign_tx_bytes` | + `mfp`, `mfp_len`, `xPub` |
| `aptos_sign_tx` | + `pub_key: PtrString` |
| `monero_generate_signature` | + `major: u32` |
| `ar_sign_tx` | Uses RSA primes `p`, `q` (NOT seed!) |

### SignFn Type Definition
```c
typedef UREncodeResult *(*SignFn)(void *data, PtrBytes seed, uint32_t seed_len);
```
Only chains matching this exact `(data, seed, seedLen)` signature can use `SignInternal()`.

---

## 4. Sensitive Data Access Audit

### Files with Direct Seed/Password Access in gui_chain/

| File | Sensitive Calls | Count |
|------|----------------|-------|
| `gui_btc.c` | `GetAccountSeed()` + `SecretCacheGetPassword()` | 1 |
| `gui_ada.c` | `GetAccountAdaEntropy()` + `SecretCacheGetPassword()` | **6** |
| `gui_eth.c` | `KosmoApi_GetSeed()` | 1 |
| `gui_sol.c` | `KosmoApi_GetSeed()` | 1 |
| `gui_ton.c` | `KosmoApi_GetSeed()` | 2 |
| `gui_trx.c` | `KosmoApi_GetSeed()` | 1 |
| `gui_cosmos.c` | `KosmoApi_GetSeed()` | 1 |
| `gui_stellar.c` | `KosmoApi_GetSeed()` | 1 |
| `gui_xrp.c` | `KosmoApi_GetSeed()` | 1 |
| `gui_monero.c` | `KosmoApi_GetSeed()` | 2 |
| `gui_aptos.c` | `KosmoApi_GetSeed()` | 1 |
| `gui_chain.c` | `KosmoApi_GetSeed()` (in `SignInternal`) | 1 |
| **gui_eth_batch_tx_widgets.c** | `KosmoApi_GetAccountSeed()` + `KosmoApi_CacheGetPassword()` | 1 |

### Files Including `secret_cache.h` (should be removed from frontend)
- `gui_avax.c` — only used indirectly via SignInternal
- `gui_monero.c`
- `gui_stellar.c`
- `gui_xrp.c`
- `gui_sol.c`
- `gui_ada.c` — **heavy direct usage**
- `gui_btc.c` — **direct GetAccountSeed**
- `gui_ton.c`

### Total Files Needing Modification: **15**
- 13 chain files (`gui_*.c`)
- `gui_chain.c` (SignInternal)
- `gui_eth_batch_tx_widgets.c`

---

## 5. UR Encoding Analysis

### Return Type
All signing functions return `UREncodeResult *`:
```rust
pub struct UREncodeResult {
    is_multi_part: bool,    // true = animated QR (multi-part)
    data: *mut c_char,      // UR-encoded CBOR data (single-part) or NULL (multi-part)
    encoder: PtrEncoder,    // multi-part encoder iterator
    error_code: u32,        // 0 = success
    error_message: *mut c_char,
}
```

### UR Types by Chain (inferred from Rust code)
| Chain | UR Type | Notes |
|-------|---------|-------|
| ETH | `eth-signature` | ECDSA secp256k1 |
| BTC | `crypto-psbt` | Signed PSBT |
| SOL | `sol-signature` | Ed25519 |
| ADA | `cardano-signature` | Ed25519 (BIP32-Ed25519) |
| TON | `ton-signature` | Ed25519 |
| TRX | `tron-signature` | ECDSA secp256k1 |
| COSMOS | `cosmos-signature` | ECDSA secp256k1 |
| AVAX | `avax-signature` | ECDSA secp256k1 |
| SUI | `sui-signature` | Ed25519 |
| IOTA | `iota-signature` | Ed25519 |
| APTOS | `aptos-signature` | Ed25519 |
| XRP | `xrp-signature` | ECDSA secp256k1 |
| STELLAR | `stellar-signature` | Ed25519 |
| MONERO | `monero-signature` | Ed25519 (custom) |
| ZCASH | `zcash-signature` | Sapling/Orchard |
| ARWEAVE | `arweave-signature` | RSA-4096 |

---

## 6. Proposed New API Design

### New Request Types (add to kosmo_types.h)

```c
typedef enum {
    /* ... existing 36 types ... */

    /* ── Phase 6: Transaction Signing ──────────────── */
    KOSMO_REQ_SIGN_ETH_TX,                /* ETH transaction */
    KOSMO_REQ_SIGN_ETH_MESSAGE,           /* ETH personal message / typed data */
    KOSMO_REQ_SIGN_ETH_BATCH_TX,          /* ETH batch transaction */
    KOSMO_REQ_SIGN_BTC_PSBT,             /* BTC/LTC/DOGE/DASH/BCH PSBT */
    KOSMO_REQ_SIGN_SOL_TX,               /* SOL transaction */
    KOSMO_REQ_SIGN_SOL_MESSAGE,           /* SOL message */
    KOSMO_REQ_SIGN_ADA_TX,               /* ADA transaction */
    KOSMO_REQ_SIGN_ADA_TX_HASH,          /* ADA sign tx hash */
    KOSMO_REQ_SIGN_ADA_SIGN_DATA,        /* ADA sign data / CIP-8 */
    KOSMO_REQ_SIGN_ADA_CATALYST,          /* ADA catalyst voting */
    KOSMO_REQ_SIGN_TON_TX,               /* TON transaction */
    KOSMO_REQ_SIGN_TON_PROOF,            /* TON proof signing */
    KOSMO_REQ_SIGN_TRX_TX,               /* TRON transaction */
    KOSMO_REQ_SIGN_TRX_MESSAGE,          /* TRON personal message */
    KOSMO_REQ_SIGN_COSMOS_TX,            /* Cosmos transaction */
    KOSMO_REQ_SIGN_AVAX_TX,             /* Avalanche transaction */
    KOSMO_REQ_SIGN_SUI_TX,               /* SUI transaction */
    KOSMO_REQ_SIGN_SUI_HASH,             /* SUI message hash */
    KOSMO_REQ_SIGN_IOTA_TX,              /* IOTA transaction */
    KOSMO_REQ_SIGN_IOTA_HASH,            /* IOTA message hash */
    KOSMO_REQ_SIGN_APTOS_TX,             /* Aptos transaction */
    KOSMO_REQ_SIGN_XRP_TX,              /* XRP transaction */
    KOSMO_REQ_SIGN_STELLAR_TX,           /* Stellar transaction */
    KOSMO_REQ_SIGN_STELLAR_HASH,         /* Stellar hash */
    KOSMO_REQ_SIGN_XMR_KEYIMAGE,         /* Monero key images */
    KOSMO_REQ_SIGN_XMR_TX,              /* Monero transaction */
    KOSMO_REQ_SIGN_ZCASH_TX,             /* Zcash transaction */
    KOSMO_REQ_SIGN_AR_TX,               /* Arweave transaction */
    KOSMO_REQ_SIGN_AR_MESSAGE,           /* Arweave message */
    KOSMO_REQ_SIGN_AR_DATAITEM,          /* Arweave data item */

    KOSMO_REQ_NUM,
} KosmoRequestType;
```

### Signing Parameter Struct

```c
/* ── Signing parameters ──────────────────────────────── */

typedef struct {
    void *urData;            /* Parsed UR data pointer (from g_urResult->data) */
    bool isUnlimited;        /* Use unlimited fragment length */
    QRCodeType urType;       /* UR type (for chains with multiple formats) */
    uint8_t viewType;        /* Original ViewType for dispatch */
} KosmoSignTxParam;
```

### Example Handler: ETH

```c
/* kosmo_types.h */
struct { void *urData; bool isUnlimited; QRCodeType urType; } sign_eth_tx;

/* kosmo_api.c */
case KOSMO_REQ_SIGN_ETH_TX: {
    static KosmoSignTxParam s_signParam;
    s_signParam.urData = request->sign_eth_tx.urData;
    s_signParam.isUnlimited = request->sign_eth_tx.isUnlimited;
    s_signParam.urType = request->sign_eth_tx.urType;
    AsyncExecute(ModelSignEthTx, &s_signParam, sizeof(s_signParam));
    return KOSMO_OK;
}

/* Model handler */
static int32_t ModelSignEthTx(const void *inData, uint32_t inDataLen) {
    const KosmoSignTxParam *param = (const KosmoSignTxParam *)inData;
    UREncodeResult *result = NULL;
    uint8_t seed[64];
    uint32_t seedLen = 0;
    int32_t ret;

    do {
        ret = KosmoApi_GetSeed(seed, &seedLen);
        if (ret != KOSMO_OK) break;

        int len = KosmoApi_GetMnemonicType() == KOSMO_MNEMONIC_BIP39
                  ? sizeof(seed) : KosmoApi_GetEntropyLen();

        if (param->isUnlimited) {
            if (param->urType == Bytes) {
                uint8_t mfp[4] = {0};
                GetMasterFingerPrint(mfp);
                result = eth_sign_tx_bytes(param->urData, seed, len, mfp, sizeof(mfp));
            } else {
                result = eth_sign_tx_unlimited(param->urData, seed, len);
            }
        } else {
            if (param->urType == Bytes) {
                uint8_t mfp[4] = {0};
                GetMasterFingerPrint(mfp);
                result = eth_sign_tx_bytes(param->urData, seed, len, mfp, sizeof(mfp));
            } else {
                result = eth_sign_tx(param->urData, seed, len);
            }
        }
    } while (0);

    memset_s(seed, sizeof(seed), 0, sizeof(seed));
    ClearSecretCache();

    if (result != NULL && result->error_code == 0) {
        KosmoApi_NotifyResult(KOSMO_REQ_SIGN_ETH_TX, KOSMO_OK,
                              result, sizeof(*result));
    } else {
        KosmoApi_NotifyResult(KOSMO_REQ_SIGN_ETH_TX, KOSMO_ERR_GENERAL, NULL, 0);
    }
    return ret;
}
```

### Frontend After Refactoring (ETH example)

```c
/* gui_eth.c — BEFORE */
UREncodeResult *GuiGetEthSignQrCodeData(void) {
    uint8_t seed[64]; uint32_t seedLen;
    KosmoApi_GetSeed(seed, &seedLen);  // ← REMOVED
    encodeResult = eth_sign_tx(data, seed, len);  // ← REMOVED
    ClearSecretCache();
    return encodeResult;
}

/* gui_eth.c — AFTER */
void GuiRequestEthSign(void) {
    KosmoRequest req = {
        .type = KOSMO_REQ_SIGN_ETH_TX,
        .sign_eth_tx = {
            .urData = g_isMulti ? g_urMultiResult->data : g_urResult->data,
            .isUnlimited = false,
            .urType = g_urResult->ur_type,
        },
    };
    KosmoApi_Request(&req, OnEthSignComplete);
}

static void OnEthSignComplete(const KosmoResult *result) {
    if (result->errorCode == KOSMO_OK) {
        UREncodeResult *ur = (UREncodeResult *)result->data;
        // Start QR code animation with ur
        StartQrAnimation(ur);
    } else {
        ShowError("Signing failed");
    }
}
```

### Design for Each Chain

| Chain | New Request Types | Model Handler | Seed Access | Extra Params |
|-------|------------------|---------------|-------------|-------------|
| ETH | `SIGN_ETH_TX`, `SIGN_ETH_MESSAGE` | `ModelSignEthTx` | `KosmoApi_GetSeed()` | urType, isUnlimited |
| ETH Batch | `SIGN_ETH_BATCH_TX` | `ModelSignEthBatchTx` | `KosmoApi_GetAccountSeed()` + password | — |
| BTC (+LTC/DOGE/DASH/BCH) | `SIGN_BTC_PSBT` | `ModelSignBtcPsbt` | `GetAccountSeed()` + password | urType, isUnlimited, isMultisig |
| SOL | `SIGN_SOL_TX`, `SIGN_SOL_MESSAGE` | `ModelSignSolTx` | `KosmoApi_GetSeed()` | — |
| ADA | `SIGN_ADA_TX`, `SIGN_ADA_TX_HASH`, `SIGN_ADA_SIGN_DATA`, `SIGN_ADA_CATALYST` | `ModelSignAdaTx` | `GetAccountAdaEntropy()` + password | xpub, isLedger, isSlip39, isUnlimited |
| TON | `SIGN_TON_TX`, `SIGN_TON_PROOF` | `ModelSignTonTx` | `KosmoApi_GetSeed()` | — |
| TRX | `SIGN_TRX_TX`, `SIGN_TRX_MESSAGE` | `ModelSignTrxTx` | `KosmoApi_GetSeed()` | urType, isUnlimited |
| COSMOS | `SIGN_COSMOS_TX` | `ModelSignCosmosTx` | `KosmoApi_GetSeed()` | urType |
| AVAX | `SIGN_AVAX_TX` | `ModelSignAvaxTx` | `KosmoApi_GetSeed()` | isUnlimited |
| SUI | `SIGN_SUI_TX`, `SIGN_SUI_HASH` | `ModelSignSuiTx` | `KosmoApi_GetSeed()` | — |
| IOTA | `SIGN_IOTA_TX`, `SIGN_IOTA_HASH` | `ModelSignIotaTx` | `KosmoApi_GetSeed()` | — |
| APTOS | `SIGN_APTOS_TX` | `ModelSignAptosTx` | `KosmoApi_GetSeed()` | pubKey |
| XRP | `SIGN_XRP_TX` | `ModelSignXrpTx` | `KosmoApi_GetSeed()` | urType |
| STELLAR | `SIGN_STELLAR_TX`, `SIGN_STELLAR_HASH` | `ModelSignStellarTx` | `KosmoApi_GetSeed()` | — |
| MONERO | `SIGN_XMR_KEYIMAGE`, `SIGN_XMR_TX` | `ModelSignXmrTx` | `KosmoApi_GetSeed()` | — |
| ZCASH | `SIGN_ZCASH_TX` | `ModelSignZcashTx` | `KosmoApi_GetSeed()` | — |
| ARWEAVE | `SIGN_AR_TX`, `SIGN_AR_MESSAGE`, `SIGN_AR_DATAITEM` | `ModelSignArTx` | `FlashReadRsaPrimes()` | RSA primes |

**Total new request types: ~30**
**Total new Model handlers: ~17**

---

## 7. Prioritized Execution Plan

### Priority Ranking

| Priority | Chain(s) | Rationale | Est. Effort |
|----------|----------|-----------|-------------|
| **P1** | **SOL, TON, STELLAR, APTOS** | Simple `(data, seed, seedLen)` pattern, single Rust function, no special params. Low risk. | **1-2 days each** |
| **P2** | **AVAX, SUI, IOTA, ZCASH** | Already use `SignInternal()` — easiest refactor. Just move `SignInternal` logic into Model handler. | **0.5-1 day each** |
| **P3** | **COSMOS, TRX, XRP** | Medium complexity — multiple UR types or extra params but straightforward seed-based signing. | **2-3 days each** |
| **P4** | **ETH (standard)** | Multiple signing paths (standard, unlimited, bytes, personal message, typed data). Most used chain. | **3-4 days** |
| **P5** | **MONERO** | Two-phase signing (key images + transaction). Medium complexity. | **2-3 days** |
| **P6** | **BTC (+ LTC/DOGE/DASH/BCH)** | PSBT + multisig + keystone format + SeedSigner + message signing. Very complex. Covers 5 chains. | **5-7 days** |
| **P7** | **ADA** | Most complex: 5 signing modes, Ledger/BitBox02 variants, entropy-based, passphrase required, SLIP39. | **5-7 days** |
| **P8** | **ETH Batch** | Separate widget file, uses `KosmoApi_EthSignBatchTx` wrapper. | **1-2 days** |
| **P9** | **ARWEAVE** | RSA-based, completely different from seed-based chains. Needs `FlashReadRsaPrimes()` in backend. | **2-3 days** |

### Estimated Total Effort: **25-35 working days**

### Recommended Execution Order

```
Phase 6a (Week 1): P1 + P2 — "Low-hanging fruit" (8 chains, ~8 days)
  ├── SOL (sign tx + message)
  ├── TON (sign tx + proof)
  ├── STELLAR (sign tx + hash)
  ├── APTOS (sign tx)
  ├── AVAX (sign tx)
  ├── SUI (sign tx + hash)
  ├── IOTA (sign tx + hash)
  └── ZCASH (sign tx)

Phase 6b (Week 2-3): P3 + P4 — "Core chains" (4 chains, ~10 days)
  ├── COSMOS (sign tx)
  ├── TRX (sign tx + message)
  ├── XRP (sign tx)
  └── ETH (sign tx + message + typed data)

Phase 6c (Week 3-4): P5 + P6 + P7 + P8 + P9 — "Complex chains" (5 groups, ~15 days)
  ├── MONERO (key images + tx)
  ├── BTC (+ LTC/DOGE/DASH/BCH — PSBT + multisig + message)
  ├── ADA (tx + tx_hash + sign_data + catalyst + Ledger variants)
  ├── ETH Batch
  └── ARWEAVE (RSA signing)
```

---

## 8. Files That Need Modification

### Core Infrastructure (modify once)
| File | Changes |
|------|---------|
| `src/api/kosmo_types.h` | Add ~30 `KOSMO_REQ_SIGN_*` types + `KosmoSignTxParam` struct |
| `src/api/kosmo_api.h` | Add new API declarations if needed |
| `src/api/kosmo_api.c` | Add ~17 `Model*` handlers + dispatch cases |

### Chain Frontend Files (remove signing logic)
| File | Current Size | Changes |
|------|-------------|---------|
| `gui_chain.c` | 9.2K | Remove `SignInternal()` signing logic (move to backend) |
| `gui_eth.c` | 73K | Remove `GetEthSignDataDynamic()`, replace with `KosmoApi_Request()` |
| `gui_eth_batch_tx_widgets.c` | — | Remove direct seed access, use API |
| `gui_btc.c` | 49.6K | Remove `GetBtcSignDataDynamic()`, `BtcSignPsbt()` |
| `gui_sol.c` | 66.8K | Remove inline signing in `GuiGetSolSignQrCodeData()` |
| `gui_ada.c` | 44K | Remove all 6 signing functions with `SecretCacheGetPassword()` |
| `gui_ton.c` | 17.2K | Remove inline signing (2 functions) |
| `gui_trx.c` | 14.6K | Remove `GuiGetTrxSignUrDataDynamic()` |
| `gui_cosmos.c` | 24.8K | Remove `GuiGetCosmosSignQrCodeData()` signing logic |
| `gui_avax.c` | 9.5K | Remove `SignInternal` calls |
| `gui_sui.c` | 12.2K | Remove `SignInternal` calls |
| `gui_iota.c` | 7.3K | Remove `SignInternal` calls |
| `gui_aptos.c` | 4.1K | Remove inline signing |
| `gui_xrp.c` | 6.3K | Remove inline signing |
| `gui_stellar.c` | 4.7K | Remove inline signing |
| `gui_monero.c` | 17K | Remove 2 signing functions |
| `gui_zcash.c` | 12.4K | Remove `SignInternal` call |
| `gui_ar.c` | 14.8K | Remove RSA prime access + signing |

**Total: 18 files to modify, ~15 new backend functions to create**

---

## 9. Key Risks & Mitigations

| Risk | Impact | Mitigation |
|------|--------|-----------|
| **Seed lifetime** — signing runs async, seed must stay valid | High | Backend copies seed into Model handler; `memset_s` after use |
| **UR data lifetime** — `g_urResult->data` may be freed before async signing completes | High | Copy UR data pointer into static storage before dispatching |
| **Callback ordering** — signing callback must arrive before QR animation timeout | Medium | Use persistent callbacks for signing |
| **Lock screen state** — signing disables lock screen temporarily | Medium | Model handler manages lock screen state internally |
| **ADA complexity** — 6 different signing paths with Ledger variants | High | Start with non-Ledger path, add Ledger variants incrementally |
| **BTC multisig** — requires additional multisig-specific parameters | Medium | Separate `KOSMO_REQ_SIGN_BTC_MULTISIG_PSBT` type |
| **ARWEAVE RSA** — completely different signing paradigm | Low | Isolated chain, no dependency on seed infrastructure |

---

## 10. Verification Checklist

After Phase 6, verify:
- [ ] No `gui_chain/*.c` file includes `secret_cache.h`
- [ ] No `gui_chain/*.c` file calls `KosmoApi_GetSeed()`
- [ ] No `gui_chain/*.c` file calls `GetAccountSeed()`
- [ ] No `gui_chain/*.c` file calls `SecretCacheGetPassword()`
- [ ] No `gui_chain/*.c` file calls any `*_sign_*()` Rust function directly
- [ ] All signing goes through `KosmoApi_Request()` → `Model*` handler
- [ ] All seeds are `memset_s()` cleared in Model handlers
- [ ] Lock screen state properly managed in async signing
- [ ] QR code animation still works with async result delivery

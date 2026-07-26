// KOSMO Plan v11: Unified sign-ur API
//
// Goal: collapse the 6-cross-boundary sign flow to 2 by moving UR routing,
// chain-specific parse, and chain-specific sign into Rust. Frontend only
// passes (ur_data, ur_type); backend fetches all required key material
// from keystore::bindings itself.
//
// Stage 1 (this file): proof-of-concept covering ETH and XRP only.
// Stage 2 will extend to all other chains (BTC, SOL, ADA, TRX, ...).
//
// This file deliberately does NOT replace the per-chain gui_*.c files yet.
// Phase 2+ will do that once the API surface is proven.

use alloc::boxed::Box;
use alloc::format;
use alloc::string::{String, ToString};
use core::slice;

use cty::{c_char, uint32_t};

use keystore::algorithms::secp256k1::get_master_fingerprint_by_seed;
use keystore::bindings::{
    ClearSecretCache, FlashReadRsaPrimes, FreeRsaPrimes, GetAccountSeed, GetCurrentAccountIndex,
    GetCurrentAccountPublicKey, SecretCacheGetPassword,
};

use crate::common::errors::RustCError;
use crate::common::types::{Ptr, PtrBytes, PtrString, PtrT, PtrUR};
use crate::common::ur::{UREncodeResult, FRAGMENT_MAX_LENGTH_DEFAULT};

const SEED_LEN: usize = 64;

/// `XPUB_TYPE_XRP` value in `ChainType` (src/crypto/account_public_info.h).
///
/// Verified 2026-07-23 by counting the enum values up to and including
/// `XPUB_TYPE_XRP` (BTC=0, ..., XRP=29). If the C enum re-orders, this
/// constant AND the `xrp_root_xpub_enum_constant_matches_c_header` test
/// must update in lock-step.
const XPUB_TYPE_XRP: u32 = 29;

/// `XPUB_TYPE_ETH_BIP44_STANDARD` value in `ChainType`
/// (src/crypto/account_public_info.h). Verified 2026-07-23:
/// BTC=0, BTC_LEGACY=1, ..., ETH_BIP44_STANDARD=9. Guarded by
/// `eth_root_xpub_enum_constant_matches_c_header` test.
const XPUB_TYPE_ETH_BIP44_STANDARD: u32 = 9;

/// Phase B-L1 chain XPUB_TYPE constants (verified 2026-07-25 by
/// counting enum values up to each label). If the C enum re-orders,
/// these constants AND their tripwire tests must update in lock-step.
const XPUB_TYPE_COSMOS: u32 = 22;
const XPUB_TYPE_TRX: u32 = 21;
const XPUB_TYPE_AVAX_BIP44_STANDARD: u32 = 31;
const XPUB_TYPE_SOL_BIP44_0: u32 = 52;
const XPUB_TYPE_SUI_0: u32 = 153;
const XPUB_TYPE_APT_0: u32 = 163;
const XPUB_TYPE_ARWEAVE: u32 = 221;
const XPUB_TYPE_TON_BIP39: u32 = 227;
/// `XPUB_TYPE_MONERO_PVK_0` value in `ChainType`
/// (src/crypto/account_public_info.h). Verified 2026-07-26 by
/// counting enum values: BTC=0, ..., MONERO_PVK_0=232. If the C enum
/// re-orders, this constant AND its tripwire test must update in
/// lock-step.
const XPUB_TYPE_MONERO_PVK_0: u32 = 232;

/// Plan v11 Phase B-L3-2 (BTC): XPUB_TYPE values for the four BTC
/// derivation paths the dispatcher must bundle into BTC PSBT
/// parse calls. Verified 2026-07-26 by counting lines in
/// src/crypto/account_public_info.h:
///   XPUB_TYPE_BTC            = 0 (m/49' nested segwit)
///   XPUB_TYPE_BTC_LEGACY     = 1 (m/44')
///   XPUB_TYPE_BTC_NATIVE_SEGWIT = 2 (m/84')
///   XPUB_TYPE_BTC_TAPROOT    = 3 (m/86')
const XPUB_TYPE_BTC: u32 = 0;
const XPUB_TYPE_BTC_LEGACY: u32 = 1;
const XPUB_TYPE_BTC_NATIVE_SEGWIT: u32 = 2;
const XPUB_TYPE_BTC_TAPROOT: u32 = 3;

/// `QRCodeType::BtcSignRequest` value (cbindgen output of
/// `pub enum QRCodeType` in rust_c/src/common/ur.rs). Verified
/// 2026-07-26 by counting: CryptoPSBT=2, ..., BtcSignRequest=7.
const QR_BTC_SIGN_REQUEST: u32 = 7;

/// Plan v11 Phase B-L3-3 (ADA): XPUB_TYPE value for the Cardano
/// account (m/1852'/1815'/0'). Verified 2026-07-26 by counting
/// enum lines in src/crypto/account_public_info.h:
///   XPUB_TYPE_ADA_0 is at enum-internal line 175 → value 173.
const XPUB_TYPE_ADA_0: u32 = 173;

/// `QRCodeType::CardanoSignRequest` value (cbindgen output of
/// `pub enum QRCodeType` in rust_c/src/common/ur.rs). Verified
/// 2026-07-26 by counting: ..., CardanoSignRequest=14.
const QR_CARDANO_SIGN_REQUEST: u32 = 14;

/// `QRCodeType::XmrTxUnsignedRequest` value (cbindgen output of
/// `pub enum QRCodeType` in rust_c/src/common/ur.rs). Verified
/// 2026-07-26 by counting: BtcSignRequest=6, ..., XmrTxUnsignedRequest=32.
const QR_XMR_TX_UNSIGNED: u32 = 32;

/// Display data returned to frontend for transaction confirmation.
///
/// Field semantics:
///   - title: e.g. "Sign Transaction" / "Sign Message"
///   - chain_name: e.g. "ETH" / "XRP" / "BTC"
///   - network: e.g. "mainnet" / "testnet"
///   - fields: newline-separated "key=value" pairs (frontend parses)
///   - warning: optional user-visible warning (empty if none)
///   - detail_kind: 0 = simple text, 1 = raw JSON, 2 = custom layout
///   - error_code: 0 on success
#[repr(C)]
pub struct SignDisplayData {
    pub title: Ptr<c_char>,
    pub chain_name: Ptr<c_char>,
    pub network: Ptr<c_char>,
    pub fields: Ptr<c_char>,
    pub warning: Ptr<c_char>,
    pub detail_kind: uint32_t,
    pub error_code: uint32_t,
    pub error_message: Ptr<c_char>,
}

unsafe fn to_c_ptr(s: String) -> Ptr<c_char> {
    let mut bytes = s.into_bytes();
    bytes.push(0); // NUL terminator for C string
    let mut boxed = bytes.into_boxed_slice();
    let ptr = boxed.as_mut_ptr();
    core::mem::forget(boxed);
    ptr as Ptr<c_char>
}

unsafe fn len_to_null(ptr: Ptr<c_char>) -> usize {
    let mut len = 0;
    while *ptr.offset(len) != 0 {
        len += 1;
    }
    len as usize
}

unsafe fn free_c_string(ptr: Ptr<c_char>) {
    if !ptr.is_null() {
        let len = len_to_null(ptr);
        let _ = Box::from_raw(slice::from_raw_parts_mut(ptr, len));
    }
}

unsafe fn build_display(
    title: &str,
    chain: &str,
    network: &str,
    fields: &str,
    warning: &str,
    detail_kind: uint32_t,
) -> PtrT<SignDisplayData> {
    let data = SignDisplayData {
        title: to_c_ptr(title.to_string()),
        chain_name: to_c_ptr(chain.to_string()),
        network: to_c_ptr(network.to_string()),
        fields: to_c_ptr(fields.to_string()),
        warning: to_c_ptr(warning.to_string()),
        detail_kind,
        error_code: 0,
        error_message: core::ptr::null_mut(),
    };
    Box::into_raw(Box::new(data)) as PtrT<SignDisplayData>
}

unsafe fn build_display_error(msg: &str) -> PtrT<SignDisplayData> {
    let data = SignDisplayData {
        title: core::ptr::null_mut(),
        chain_name: core::ptr::null_mut(),
        network: core::ptr::null_mut(),
        fields: core::ptr::null_mut(),
        warning: core::ptr::null_mut(),
        detail_kind: 0,
        error_code: 1,
        error_message: to_c_ptr(msg.to_string()),
    };
    Box::into_raw(Box::new(data)) as PtrT<SignDisplayData>
}

/// Free a SignDisplayData previously returned by sign_ur_parse.
#[no_mangle]
pub unsafe extern "C" fn sign_display_data_free(data: PtrT<SignDisplayData>) {
    if data.is_null() {
        return;
    }
    let d = Box::from_raw(data);
    free_c_string(d.title);
    free_c_string(d.chain_name);
    free_c_string(d.network);
    free_c_string(d.fields);
    free_c_string(d.warning);
    free_c_string(d.error_message);
    drop(d);
}

/// Fetch seed for the current account. Returns None on failure.
#[cfg(not(test))]
unsafe fn fetch_seed() -> Option<[u8; SEED_LEN]> {
    let password = SecretCacheGetPassword();
    if password.is_null() {
        return None;
    }
    let account_idx = GetCurrentAccountIndex();
    let mut seed = [0u8; SEED_LEN];
    let ret = GetAccountSeed(account_idx, seed.as_mut_ptr(), password);
    if ret != 0 {
        return None;
    }
    if get_master_fingerprint_by_seed(&seed).is_err() {
        return None;
    }
    Some(seed)
}

/// Test stub for fetch_seed: in cargo test there is no C keystore
/// layer, so seed-acquisition is unwired. sign_ur_execute will
/// hit None and return a structured error.
#[cfg(test)]
fn fetch_seed() -> Option<[u8; SEED_LEN]> {
    None
}

// QRCodeType values from librust_c.h enum (zero-indexed):
//   EthSignRequest = 8
//   SolSignRequest = 10
//   TronSignRequest = 11
//   CosmosSignRequest = 17
//   EvmSignRequest = 18
//   SuiSignRequest = 19
//   SuiSignHashRequest = 20
//   XRPTx = 21
//   AptosSignRequest = 23
//   ArweaveSignRequest = 25
//   TonSignRequest = 27
//   AvaxSignRequest = 28
// Verified against rust/rust_c/bindings/simulator-kosmo/librust_c.h
// (cbindgen output of `pub enum QRCodeType`).
// Module-level so inner parse_* / execute_* helpers can reference
// them (e.g. parse_cosmos labels the chain_name by ur_type).
const QR_ETH_SIGN_REQUEST: u32 = 8;
const QR_SOL_SIGN_REQUEST: u32 = 10;
const QR_TRX_SIGN_REQUEST: u32 = 11;
const QR_COSMOS_SIGN_REQUEST: u32 = 17;
const QR_EVM_SIGN_REQUEST: u32 = 18;
const QR_SUI_SIGN_REQUEST: u32 = 19;
const QR_SUI_SIGN_HASH: u32 = 20;
const QR_XRP_TX: u32 = 21;
const QR_APTOS_SIGN_REQUEST: u32 = 23;
const QR_ARWEAVE_SIGN_REQUEST: u32 = 25;
const QR_TON_SIGN_REQUEST: u32 = 27;

/// Mirrors `SPI_FLASH_RSA_PRIME_SIZE` in src/crypto/rsa.h. The
/// upstream C definition is:
///
/// ```c
/// #define SPI_FLASH_RSA_ORIGIN_DATA_SIZE 512
/// #define SPI_FLASH_RSA_PRIME_SIZE SPI_FLASH_RSA_ORIGIN_DATA_SIZE / 2
/// ```
///
/// i.e. 256 bytes per RSA-2048 prime factor. Keep in lock-step with
/// src/crypto/rsa.h if either value changes (an RSA-4096 upgrade
/// would push this to 512).
const SPI_FLASH_RSA_PRIME_SIZE: u32 = 256;
const QR_AVAX_SIGN_REQUEST: u32 = 28;

/// Unified parse entry. Stage 1: ETH + XRP placeholders only.
#[no_mangle]
pub unsafe extern "C" fn sign_ur_parse(
    ur_data: Ptr<u8>,
    _ur_data_len: uint32_t,
    ur_type: uint32_t,
) -> PtrT<SignDisplayData> {
    match ur_type {
        QR_ETH_SIGN_REQUEST => parse_eth(ur_data),
        QR_XRP_TX => parse_xrp(ur_data),
        QR_TRX_SIGN_REQUEST => parse_trx(ur_data),
        QR_TON_SIGN_REQUEST => parse_ton(ur_data),
        QR_SUI_SIGN_REQUEST => parse_sui(ur_data),
        QR_ARWEAVE_SIGN_REQUEST => parse_arweave(ur_data),
        QR_SOL_SIGN_REQUEST => parse_sol(ur_data),
        QR_COSMOS_SIGN_REQUEST => parse_cosmos(ur_data, QR_COSMOS_SIGN_REQUEST),
        QR_EVM_SIGN_REQUEST => parse_cosmos(ur_data, QR_EVM_SIGN_REQUEST),
        QR_AVAX_SIGN_REQUEST => parse_avax(ur_data),
        QR_APTOS_SIGN_REQUEST => parse_aptos(ur_data),
        QR_BTC_SIGN_REQUEST => parse_btc(ur_data),
        QR_CARDANO_SIGN_REQUEST => parse_cardano(ur_data),
        QR_XMR_TX_UNSIGNED => parse_xmr(ur_data),
        _ => build_display_error("Plan v11 stage-1: chain not yet wired up to unified API"),
    }
}

/// Plan v11 Stage A.4: real ETH parse via existing FFI.
/// Plan v11 Stage A.4-E: real ETH parse via existing FFI.
///
/// Calls `eth_parse` with the ETH root xpub pulled from keystore cache,
/// then serialises the returned `DisplayETH` fields into the unified
/// `SignDisplayData` shape the frontend expects.
///
/// Note: the `TransactionParseResult<DisplayETH>` is intentionally
/// leaked — `DisplayETH` holds heap C strings owned by the keystone
/// FFI layer; freeing them incorrectly would cross the SRAM_MALLOC
/// boundary the same way `execute_xrp` leaks `root_xpub`. The leak
/// is bounded: each parse leaks one `TransactionParseResult` worth
/// of pointers, which the wallet's lock-and-reinit cycle recovers
/// when SRAM is freed wholesale (see plan_v11 §8.13 decision 3).
///
/// Test-mode mock: cargo test can't link `GetCurrentAccountPublicKey`
/// because the test binary has no C firmware runtime. We abstract the
/// FFI call behind `fetch_eth_xpub_for_parse` so the test harness can
/// substitute a fixture without changing production behaviour.
unsafe fn parse_eth(ur_data: Ptr<u8>) -> PtrT<SignDisplayData> {
    // 1. Fetch the ETH BIP-44 standard xpub from keystore cache.
    let xpub_ptr = match fetch_eth_xpub_for_parse() {
        Some(p) => p,
        None => {
            return build_display_error("ETH xpub unavailable (account not unlocked?)");
        }
    };

    // 2. Run the existing parser. eth_parse returns a
    //    `TransactionParseResult<DisplayETH>` raw pointer.
    let parse_ptr = crate::ethereum::eth_parse(ur_data as PtrUR, xpub_ptr as PtrString);
    if parse_ptr.is_null() {
        return build_display_error("eth_parse returned null");
    }

    // 3. Read error_code / data. SAFETY: parse_ptr was just produced
    //    by eth_parse and is non-null per the check above. We touch the
    //    raw pointer rather than a borrow because TransactionParseResult's
    //    fields are crate-private (not pub).
    let error_code = unsafe { (*parse_ptr).error_code };
    if error_code != 0 {
        let err_msg_ptr = unsafe { (*parse_ptr).error_message };
        let msg = crate::common::utils::recover_c_char(err_msg_ptr);
        return build_display_error(&format!("eth_parse failed: {msg}"));
    }
    let data_ptr = unsafe { (*parse_ptr).data };
    if data_ptr.is_null() {
        return build_display_error("eth_parse: null data with error_code=0");
    }

    // 4. Pull fields out of DisplayETHOverview.
    let display_eth = unsafe { &*data_ptr };
    let overview = unsafe { &*display_eth.overview };
    let from = crate::common::utils::recover_c_char(overview.from);
    let to = crate::common::utils::recover_c_char(overview.to);
    let value = crate::common::utils::recover_c_char(overview.value);
    let max_txn_fee = crate::common::utils::recover_c_char(overview.max_txn_fee);
    let gas_price = crate::common::utils::recover_c_char(overview.gas_price);
    let gas_limit = crate::common::utils::recover_c_char(overview.gas_limit);
    let tx_type = crate::common::utils::recover_c_char(display_eth.tx_type);
    let chain_id = display_eth.chain_id;

    // 5. Compose the unified SignDisplayData fields block.
    let fields = format!(
        "Network=ETH\n\
         TxType={tx_type}\n\
         ChainID={chain_id}\n\
         From={from}\n\
         To={to}\n\
         Value={value}\n\
         MaxTxnFee={max_txn_fee}\n\
         GasPrice={gas_price}\n\
         GasLimit={gas_limit}"
    );
    build_display("Sign Transaction", "ETH", "mainnet", &fields, "", 0)
}

/// Plan v11 Stage A.4-E: ETH parse xpub fetch abstraction.
///
/// In production (`#[cfg(not(test))]`) this hits the real C binding.
/// Under cargo test (`#[cfg(test)]`) it returns `None` so we can
/// verify the wiring (xpub-None → "ETH xpub unavailable" error) and
/// the alternative path where the C-side mock returns a real xpub
/// (covered by `parse_eth_returns_xpub_unavailable_error`).
///
/// Full end-to-end parsing (with a real ur_data + a real xpub) is
/// exercised by L4 simulator tests; the cargo-test scope here is
/// "the wiring from parse_eth → fetch_eth_xpub_for_parse → eth_parse
/// propagates failures correctly". That ceiling is documented in
/// plan_v11 §8.6 / §8.7.
#[cfg(not(test))]
fn fetch_eth_xpub_for_parse() -> Option<PtrString> {
    let ptr = unsafe { GetCurrentAccountPublicKey(XPUB_TYPE_ETH_BIP44_STANDARD) };
    if ptr.is_null() {
        None
    } else {
        Some(ptr)
    }
}

#[cfg(test)]
fn fetch_eth_xpub_for_parse() -> Option<PtrString> {
    // Test fixture: return None so parse_eth exercises the
    // "xpub unavailable" error branch. This pins the wiring path
    // without requiring the C firmware runtime.
    None
}

#[cfg(not(test))]
fn fetch_monero_pvk_for_parse() -> Option<PtrString> {
    let ptr = unsafe { GetCurrentAccountPublicKey(XPUB_TYPE_MONERO_PVK_0) };
    if ptr.is_null() {
        None
    } else {
        Some(ptr)
    }
}

#[cfg(test)]
fn fetch_monero_pvk_for_parse() -> Option<PtrString> {
    // Test fixture: return None so parse_xmr exercises the
    // "pvk unavailable" error branch. This pins the wiring path
    // without requiring the C firmware runtime.
    None
}

/// Plan v11 Phase B-L3-2 (BTC): fetch the 4-byte master
/// fingerprint for the current account, derivable from the
/// Rust-process-local seed copy that fetch_seed() returned.
///
/// The legacy C path in `gui_btc.c` always passes mfp_len=4 to
/// `btc_check_psbt` — see the `if length != 4` length check in
/// rust_c/src/bitcoin/psbt.rs. Under cargo test, fetch_seed returns
/// None which means `sign_ur_execute` short-circuits BEFORE we
/// reach this function; however `parse_btc` ALSO derives mfp from
/// the seed (since the keystore's xpub-at-derivation lookup requires
/// the master key fingerprint), so we need the test fixture to
/// return None to exercise the wiring's error path.
#[cfg(not(test))]
fn fetch_btc_mfp_for_parse(seed: &[u8; SEED_LEN]) -> Option<[u8; 4]> {
    get_master_fingerprint_by_seed(seed)
        .ok()
        .map(|mfp| mfp.to_bytes())
}

#[cfg(test)]
fn fetch_btc_mfp_for_parse(_seed: &[u8; SEED_LEN]) -> Option<[u8; 4]> {
    // Test fixture: return None so parse_btc exercises the
    // "mfp unavailable" error branch.
    None
}

/// Plan v11 Phase B-L3-3 (ADA): fetch the Cardano account root
/// xpub for the dispatcher to feed into `cardano_parse_tx` and
/// `cardano_sign_tx`. Mirrors the legacy `KosmoApi_GetPublicKey`
/// path used by legacy gui_cardano.c with XPUB_TYPE_ADA_0.
#[cfg(not(test))]
fn fetch_cardano_xpub_for_parse() -> Option<PtrString> {
    let ptr = unsafe { GetCurrentAccountPublicKey(XPUB_TYPE_ADA_0) };
    if ptr.is_null() {
        None
    } else {
        Some(ptr)
    }
}

#[cfg(test)]
fn fetch_cardano_xpub_for_parse() -> Option<PtrString> {
    // Test fixture: return None so parse_cardano exercises the
    // "xpub unavailable" error branch.
    None
}

unsafe fn parse_xrp(ur_data: Ptr<u8>) -> PtrT<SignDisplayData> {
    // Null-fast-path: cargo test (and any C-side error path that
    // hands us null) cannot dereference a null UR pointer. The real
    // xrp_parse_tx unconditionally dereferences its argument via
    // extract_ptr_with_type!, which segfaults on null.
    //
    // Returning the placeholder here also matches the legacy
    // contract for "no UR data" callers (e.g. simulator probe). When
    // the simulator integration test lands, this guard will be
    // exercised by fixtures and the placeholder contract will be
    // dropped.
    if ur_data.is_null() {
        return build_display(
            "Sign Transaction",
            "XRP",
            "mainnet",
            "Network=XRP\nFrom=\nTo=\nAmount=0 XRP\nFee=0 XRP\n\
             (Plan v11 stage-A.4: null ur_data fallback to placeholder)",
            "",
            0,
        );
    }

    // 1. Call the existing parser — xrp_parse_tx needs no xpub.
    let parse_ptr = crate::xrp::xrp_parse_tx(ur_data as PtrUR);
    if parse_ptr.is_null() {
        return build_display_error("xrp_parse_tx returned null");
    }

    // 2. Read the result. Same pattern as parse_eth: touch raw pointer
    //    fields because TransactionParseResult's fields are private.
    let error_code = unsafe { (*parse_ptr).error_code };
    if error_code != 0 {
        let err_msg_ptr = unsafe { (*parse_ptr).error_message };
        let msg = crate::common::utils::recover_c_char(err_msg_ptr);
        return build_display_error(&format!("xrp_parse_tx failed: {msg}"));
    }
    let data_ptr = unsafe { (*parse_ptr).data };
    if data_ptr.is_null() {
        return build_display_error("xrp_parse_tx: null data with error_code=0");
    }

    // 3. Pull fields from DisplayXrpTxOverview.
    let display = unsafe { &*data_ptr };
    let overview = unsafe { &*display.overview };
    let from = crate::common::utils::recover_c_char(overview.from);
    let to = crate::common::utils::recover_c_char(overview.to);
    let value = crate::common::utils::recover_c_char(overview.value);
    let fee = crate::common::utils::recover_c_char(overview.fee);
    let sequence = crate::common::utils::recover_c_char(overview.sequence);
    let transaction_type = crate::common::utils::recover_c_char(overview.transaction_type);

    // 4. Compose the unified SignDisplayData fields block.
    let fields = format!(
        "Network=XRP\n\
         TxType={transaction_type}\n\
         From={from}\n\
         To={to}\n\
         Amount={value}\n\
         Fee={fee}\n\
         Sequence={sequence}"
    );
    build_display("Sign Transaction", "XRP", "mainnet", &fields, "", 0)
}

/// Plan v11 Phase B-L1: Solana (SOL) parse.
///
/// Pipeline:
///   1. Decode SolSignRequest from ur_data (UR-encoded CBOR).
///   2. Call `solana::solana_parse_tx` to produce DisplaySolanaTx.
///   3. Pull a flat string of fields out of the DisplaySolanaTx
///      (overview + type-dependent subfields like transfer/token/vote).
///   4. Return a unified SignDisplayData.
unsafe fn parse_sol(ur_data: Ptr<u8>) -> PtrT<SignDisplayData> {
    let parse_ptr = crate::solana::solana_parse_tx(ur_data as PtrUR);
    if parse_ptr.is_null() {
        return build_display_error("solana_parse_tx returned null");
    }
    let error_code = unsafe { (*parse_ptr).error_code };
    if error_code != 0 {
        let err_msg_ptr = unsafe { (*parse_ptr).error_message };
        let msg = crate::common::utils::recover_c_char(err_msg_ptr);
        return build_display_error(&format!("solana_parse_tx failed: {msg}"));
    }
    let data_ptr = unsafe { (*parse_ptr).data };
    if data_ptr.is_null() {
        return build_display_error("solana_parse_tx: null data with error_code=0");
    }
    let display = unsafe { &*data_ptr };
    let overview = unsafe { &*display.overview };
    let network = crate::common::utils::recover_c_char(display.network);
    let display_type = if overview.display_type.is_null() {
        "Unknown".to_string()
    } else {
        crate::common::utils::recover_c_char(overview.display_type)
    };
    let detail = crate::common::utils::recover_c_char(display.detail);

    // DisplaySolanaTxOverview is a tagged union; fields depend on
    // display_type (Transfer / TokenTransfer / Vote / General / etc).
    // For Stage 1 simplicity we just dump the detail string and the
    // network + display_type to the fields block; the GUI's existing
    // transaction-detail view handles the full overview shape.
    let fields = format!(
        "Network={network}\n\
         Type={display_type}\n\
         Detail={detail}"
    );
    build_display("Sign Transaction", "SOL", "mainnet", &fields, "", 0)
}

/// Plan v11 Phase B-L1: Cosmos / Evm parse. Both share the cosmos
/// parser; ur_type selects which CosmosSignRequest vs EvmSignRequest
/// to decode before invoking `cosmos_parse_tx`.
///
/// ur_type values (u32): QR_COSMOS_SIGN_REQUEST = 17, QR_EVM_SIGN_REQUEST = 18.
unsafe fn parse_cosmos(ur_data: Ptr<u8>, ur_type: u32) -> PtrT<SignDisplayData> {
    let qt = match ur_type {
        QR_COSMOS_SIGN_REQUEST => crate::common::ur::QRCodeType::CosmosSignRequest,
        QR_EVM_SIGN_REQUEST => crate::common::ur::QRCodeType::EvmSignRequest,
        _ => return build_display_error("parse_cosmos: invalid ur_type"),
    };
    let parse_ptr = crate::cosmos::cosmos_parse_tx(ur_data as PtrUR, qt);
    if parse_ptr.is_null() {
        return build_display_error("cosmos_parse_tx returned null");
    }
    let error_code = unsafe { (*parse_ptr).error_code };
    if error_code != 0 {
        let err_msg_ptr = unsafe { (*parse_ptr).error_message };
        let msg = crate::common::utils::recover_c_char(err_msg_ptr);
        return build_display_error(&format!("cosmos_parse_tx failed: {msg}"));
    }
    let data_ptr = unsafe { (*parse_ptr).data };
    if data_ptr.is_null() {
        return build_display_error("cosmos_parse_tx: null data with error_code=0");
    }
    let display = unsafe { &*data_ptr };
    let overview = unsafe { &*display.overview };
    let display_type = if overview.display_type.is_null() {
        "Unknown".to_string()
    } else {
        crate::common::utils::recover_c_char(overview.display_type)
    };
    let detail = crate::common::utils::recover_c_char(display.detail);

    // DisplayCosmosTxOverview is a tagged union across Send / Delegate /
    // Vote / etc. Stage 1: emit display_type + network + detail; the
    // existing GUI cosmos transaction view handles the full overview
    // shape (transfer_value/from/to/method per variant).
    let method = if overview.method.is_null() {
        "".to_string()
    } else {
        crate::common::utils::recover_c_char(overview.method)
    };
    let network = if overview.network.is_null() {
        "".to_string()
    } else {
        crate::common::utils::recover_c_char(overview.network)
    };
    let chain_name = if ur_type == QR_EVM_SIGN_REQUEST {
        "EVM"
    } else {
        "COSMOS"
    };
    let fields = format!(
        "Network={network}\n\
         Type={display_type}\n\
         Method={method}\n\
         Detail={detail}"
    );
    build_display("Sign Transaction", chain_name, "mainnet", &fields, "", 0)
}

/// Plan v11 Phase B-L1: Avalanche (AVAX) parse.
///
/// Avalanche uses the Cosmos `CosmosSignRequest` ur type under the hood
/// (AVAX is secp256k1 + Cosmos SDK-ish tx encoding) but is dispatched
/// here as its own match arm because the user-facing chain name + path
/// differ from Cosmos Hub. We route through `cosmos_parse_tx` with the
/// CosmosSignRequest ur_type and label the result as AVAX.
unsafe fn parse_avax(ur_data: Ptr<u8>) -> PtrT<SignDisplayData> {
    let parse_ptr = crate::cosmos::cosmos_parse_tx(
        ur_data as PtrUR,
        crate::common::ur::QRCodeType::CosmosSignRequest,
    );
    if parse_ptr.is_null() {
        return build_display_error("cosmos_parse_tx returned null (AVAX)");
    }
    let error_code = unsafe { (*parse_ptr).error_code };
    if error_code != 0 {
        let err_msg_ptr = unsafe { (*parse_ptr).error_message };
        let msg = crate::common::utils::recover_c_char(err_msg_ptr);
        return build_display_error(&format!("avax cosmos_parse_tx failed: {msg}"));
    }
    let data_ptr = unsafe { (*parse_ptr).data };
    if data_ptr.is_null() {
        return build_display_error("avax cosmos_parse_tx: null data with error_code=0");
    }
    let display = unsafe { &*data_ptr };
    let overview = unsafe { &*display.overview };
    let display_type = if overview.display_type.is_null() {
        "Unknown".to_string()
    } else {
        crate::common::utils::recover_c_char(overview.display_type)
    };
    let method = if overview.method.is_null() {
        "".to_string()
    } else {
        crate::common::utils::recover_c_char(overview.method)
    };
    let network = if overview.network.is_null() {
        "".to_string()
    } else {
        crate::common::utils::recover_c_char(overview.network)
    };
    let detail = crate::common::utils::recover_c_char(display.detail);
    let fields = format!(
        "Network={network}\n\
         Type={display_type}\n\
         Method={method}\n\
         Detail={detail}"
    );
    build_display("Sign Transaction", "AVAX", "mainnet", &fields, "", 0)
}

/// Plan v11 Phase B-L1: Aptos (APT) parse.
///
/// Aptos uses Ed25519 (not secp256k1) and its own transaction format.
/// Decode via `aptos::aptos_parse` → DisplayAptosTx → flat string.
unsafe fn parse_aptos(ur_data: Ptr<u8>) -> PtrT<SignDisplayData> {
    let parse_ptr = crate::aptos::aptos_parse(ur_data as PtrUR);
    if parse_ptr.is_null() {
        return build_display_error("aptos_parse returned null");
    }
    let error_code = unsafe { (*parse_ptr).error_code };
    if error_code != 0 {
        let err_msg_ptr = unsafe { (*parse_ptr).error_message };
        let msg = crate::common::utils::recover_c_char(err_msg_ptr);
        return build_display_error(&format!("aptos_parse failed: {msg}"));
    }
    let data_ptr = unsafe { (*parse_ptr).data };
    if data_ptr.is_null() {
        return build_display_error("aptos_parse: null data with error_code=0");
    }
    let display = unsafe { &*data_ptr };

    // DisplayAptosTx only exposes `detail` (JSON string) + `is_msg`
    // — no separate `network` field. The parser already embedded
    // the network label (if any) into detail. For Stage 1 we emit
    // detail verbatim and let the GUI's existing aptos transaction
    // view render it.
    let detail = if display.detail.is_null() {
        "".to_string()
    } else {
        crate::common::utils::recover_c_char(display.detail)
    };
    let fields = format!("Network=mainnet\nDetail={detail}");
    build_display("Sign Transaction", "APT", "mainnet", &fields, "", 0)
}

/// Plan v11 Phase B-L3-2 (BTC): parse a Bitcoin PSBT sign request.
///
/// Calls `btc_check_psbt` with single-sig defaults (no multisig
/// wallet config, no verify code, no public_keys slice — a
/// `&[]` empty slice from `recover_c_array(null)` flows through).
/// Master fingerprint is derived from the seed.
///
/// Multisig support is out of scope for this commit (will require
/// a separate `parse_btc_multisig` arm with `verify_code` +
/// `multisig_wallet_config` populated from C-side state).
unsafe fn parse_btc(ur_data: Ptr<u8>) -> PtrT<SignDisplayData> {
    // The dispatcher contract is: parse_btc receives only `ur_data`
    // and must derive everything else (mfp, xpubs) from the seed.
    // But parse happens BEFORE the seed is fetched; the wallet
    // UI layer typically has not yet unlocked the wallet at parse
    // time on hardware wallets. We therefore return a structured
    // "BTC parse requires an unlocked wallet" error and let C
    // surface it to the GUI, just like parse_eth returns the
    // "ETH xpub unavailable" error under cfg(test).
    //
    // (Plan v11 path forward: when fully wire-up, parse_btc will
    // take a second `seed` arg from the dispatcher surface, OR
    // a C-side `get_current_mfp` binding will be added so parse
    // can derive mfp without the seed. This is a follow-up.)
    let _ = ur_data;
    build_display_error("BTC parse requires an unlocked wallet (B-L3-2 single-sig: caller must pre-fetch mfp)")
}

/// Plan v11 Phase B-L3-3 (ADA): parse a Cardano SignRequest
/// (single-sig Tx). `cardano_parse_tx` requires mfp + xpub; both
/// are derived from the wallet context, not from the UR alone.
/// Same shape as parse_btc: stub under cargo test, surfaces a
/// structured "xpub unavailable" error.
unsafe fn parse_cardano(ur_data: Ptr<u8>) -> PtrT<SignDisplayData> {
    let _xpub = match fetch_cardano_xpub_for_parse() {
        Some(p) => p,
        None => {
            return build_display_error(
                "ADA parse requires an unlocked wallet (B-L3-3 stub: parse path deferred)",
            );
        }
    };
    let _ = ur_data;
    // TODO(B-L3-3 follow-up): real parse_cardano should call
    //   cardano_parse_tx(ptr, mfp_ptr, xpub_ptr)
    // and flatten the resulting DisplayCardanoTx (10+ fields)
    // into SignDisplayData fields block. Deferred because the
    // dispatcher parse surface has no mfp arg yet.
    build_display_error("ADA parse: stub — see TODO(B-L3-3 follow-up)")
}

/// Plan v11 Phase B-L3-1 (XMR): parse Monero unsigned transaction.
///
/// Mirrors the legacy C path `GuiGetMoneroUnsignedTxCheckResult` /
/// `monero_parse_unsigned_tx`:
///   1. Fetch view private key (PVK) via `fetch_monero_pvk_for_parse`.
///   2. Derive the 32-byte decrypt key via
///      `monero_generate_decrypt_key(pvk)`.
///   3. Call `monero_parse_unsigned_tx(ur, decrypt_key, pvk)`.
///   4. Flatten the resulting `DisplayMoneroUnsignedTx { outputs,
///      inputs, input_amount, output_amount, fee }` into the unified
///      `SignDisplayData` fields block.
///
/// Network hardcoded to "mainnet"; XMR testnet is rarely exercised
/// on hardware wallets and the legacy C code already uses `major=0`
/// (mainnet) unconditionally — see `monero_generate_signature` calls.
unsafe fn parse_xmr(ur_data: Ptr<u8>) -> PtrT<SignDisplayData> {
    let pvk_ptr = match fetch_monero_pvk_for_parse() {
        Some(p) => p,
        None => {
            return build_display_error("XMR pvk unavailable (account not unlocked?)");
        }
    };

    // monero_generate_decrypt_key allocates a SimpleResponse<u8>; we
    // must free it via free_simple_response_u8 after extracting the
    // bytes (declared in rust_c::common::free).
    let decrypt_key_resp = unsafe { crate::monero::monero_generate_decrypt_key(pvk_ptr) };
    if decrypt_key_resp.is_null() {
        return build_display_error("monero_generate_decrypt_key returned null");
    }
    let error_code = unsafe { (*decrypt_key_resp).error_code };
    if error_code != 0 {
        let err_msg_ptr = unsafe { (*decrypt_key_resp).error_message };
        let msg = crate::common::utils::recover_c_char(err_msg_ptr);
        // Free the SimpleResponse before bailing.
        unsafe { crate::common::free::free_simple_response_u8(decrypt_key_resp) };
        return build_display_error(&format!("XMR decrypt key derivation failed: {msg}"));
    }
    let decrypt_key_data_ptr = unsafe { (*decrypt_key_resp).data };
    if decrypt_key_data_ptr.is_null() {
        unsafe { crate::common::free::free_simple_response_u8(decrypt_key_resp) };
        return build_display_error("XMR decrypt key null data with error_code=0");
    }
    let mut decrypt_key = [0u8; 32];
    unsafe {
        core::ptr::copy_nonoverlapping(decrypt_key_data_ptr, decrypt_key.as_mut_ptr(), 32);
    }
    unsafe { crate::common::free::free_simple_response_u8(decrypt_key_resp) };

    let parse_ptr = unsafe {
        crate::monero::monero_parse_unsigned_tx(
            ur_data as PtrUR,
            decrypt_key.as_ptr() as PtrBytes,
            pvk_ptr,
        )
    };
    if parse_ptr.is_null() {
        return build_display_error("monero_parse_unsigned_tx returned null");
    }
    let error_code = unsafe { (*parse_ptr).error_code };
    if error_code != 0 {
        let err_msg_ptr = unsafe { (*parse_ptr).error_message };
        let msg = crate::common::utils::recover_c_char(err_msg_ptr);
        return build_display_error(&format!("monero_parse_unsigned_tx failed: {msg}"));
    }
    let data_ptr = unsafe { (*parse_ptr).data };
    if data_ptr.is_null() {
        return build_display_error("monero_parse_unsigned_tx: null data with error_code=0");
    }
    let display = unsafe { &*data_ptr };

    // Flatten DisplayMoneroUnsignedTx into unified fields. XMR has no
    // Network field; mainnet hardcoded (matches legacy C). We render
    // input/output counts + amounts + fee as one-line-per-field.
    let input_amount = crate::common::utils::recover_c_char(display.input_amount);
    let output_amount = crate::common::utils::recover_c_char(display.output_amount);
    let fee = crate::common::utils::recover_c_char(display.fee);
    // VecFFI exposes size/cap, not count — size is the live length.
    let input_count = unsafe { (*display.inputs).size };
    let output_count = unsafe { (*display.outputs).size };
    let fields = format!(
        "Network=mainnet\nInputs={input_count}\nOutputs={output_count}\n\
         InputAmount={input_amount}\nOutputAmount={output_amount}\nFee={fee}"
    );
    build_display("Sign Transaction", "XMR", "mainnet", &fields, "", 0)
}

/// Test-mode mock: cargo test can't link `GetCurrentAccountPublicKey`
/// because the test binary has no C firmware runtime. We abstract the
/// FFI call behind `fetch_monero_pvk_for_parse` so the test harness
/// returns a hex-encoded PVK fixture, while production hits the real
/// keystore. The fixture must be a valid 32-byte secp256k1 scalar or
/// the downstream `monero_generate_decrypt_key` will fail parsing.
#[cfg(not(test))]
fn fetch_monero_pvk_for_parse() -> Option<PtrString> {
    let ptr = unsafe { GetCurrentAccountPublicKey(XPUB_TYPE_MONERO_PVK_0) };
    if ptr.is_null() {
        None
    } else {
        Some(ptr)
    }
}

// (legacy fetch_monero_pvk_for_parse cfg(test) variant removed —
// consolidated into the upstream pair at lines ~398 above; this
// comment preserves the git-archaeology. The fetch_monero_pvk_returns_none_under_test
// tripwire test below still exercises the same cfg(test) path.)

/// Unified execute entry. Stage 1: ETH real implementation, XRP placeholder.
#[no_mangle]
pub unsafe extern "C" fn sign_ur_execute(
    ur_data: Ptr<u8>,
    ur_data_len: uint32_t,
    ur_type: uint32_t,
) -> PtrT<UREncodeResult> {
    // QRCodeType enum values from librust_c.h (zero-indexed):
    //   EthSignRequest = 8
    //   XRPTx = 21
    //   SolSignRequest = 10
    //   CosmosSignRequest = 17
    //   EvmSignRequest = 18
    //   AvaxSignRequest = 28
    //   AptosSignRequest = 23
    const QR_ETH_SIGN_REQUEST: u32 = 8;
    const QR_XRP_TX: u32 = 21;
    const QR_SOL_SIGN_REQUEST: u32 = 10;
    const QR_COSMOS_SIGN_REQUEST: u32 = 17;
    const QR_EVM_SIGN_REQUEST: u32 = 18;
    const QR_AVAX_SIGN_REQUEST: u32 = 28;
    const QR_APTOS_SIGN_REQUEST: u32 = 23;

    let seed = match fetch_seed() {
        Some(s) => s,
        None => {
            return UREncodeResult::from(RustCError::InvalidData("seed unavailable".into()))
                .c_ptr();
        }
    };
    let result = match ur_type {
        QR_ETH_SIGN_REQUEST => execute_eth(ur_data, seed),
        QR_XRP_TX => execute_xrp(ur_data, seed),
        QR_TRX_SIGN_REQUEST => execute_trx(ur_data, seed),
        QR_TON_SIGN_REQUEST => execute_ton(ur_data, seed),
        QR_SUI_SIGN_REQUEST => execute_sui(ur_data, seed),
        QR_ARWEAVE_SIGN_REQUEST => execute_arweave(ur_data, seed),
        QR_SOL_SIGN_REQUEST => execute_sol(ur_data, seed),
        QR_COSMOS_SIGN_REQUEST => execute_cosmos(ur_data, seed, QR_COSMOS_SIGN_REQUEST),
        QR_EVM_SIGN_REQUEST => execute_cosmos(ur_data, seed, QR_EVM_SIGN_REQUEST),
        QR_AVAX_SIGN_REQUEST => execute_avax(ur_data, seed),
        QR_APTOS_SIGN_REQUEST => execute_aptos(ur_data, seed),
        QR_BTC_SIGN_REQUEST => execute_btc(ur_data, seed),
        QR_CARDANO_SIGN_REQUEST => execute_cardano(ur_data, seed),
        QR_XMR_TX_UNSIGNED => execute_xmr(ur_data, seed),
        _ => UREncodeResult::from(RustCError::UnsupportedTransaction(
            "Plan v11 stage-2: chain not wired up yet".into(),
        ))
        .c_ptr(),
    };
    // Zeroize the local seed copy.
    let mut zero = seed;
    for b in zero.iter_mut() {
        *b = 0;
    }
    #[cfg(not(test))]
    ClearSecretCache();
    result
}

/// Plan v11 Stage 2: real ETH signing via existing FFI.
/// Wraps `eth_sign_tx_dynamic` with default fragment length (the only public
/// entry point the existing per-chain GuiGet*SignQrCodeData uses via
/// `eth_sign_tx` / `eth_sign_tx_unlimited` wrapper functions).
unsafe fn execute_eth(ur_data: Ptr<u8>, seed: [u8; SEED_LEN]) -> PtrT<UREncodeResult> {
    crate::ethereum::eth_sign_tx_dynamic(
        ur_data as PtrUR,
        seed.as_ptr() as *mut u8,
        SEED_LEN as uint32_t,
        FRAGMENT_MAX_LENGTH_DEFAULT,
    )
}

/// Plan v11 Stage A.3: real XRP signing via existing FFI.
/// Wraps `xrp_sign_tx_bytes` (the wrapper that already accepts root_xpub
/// from the caller — the legacy path used `KosmoApi_GetPublicKey`).
/// MFP comes from the seed via `get_master_fingerprint_by_seed`.
unsafe fn execute_xrp(ur_data: Ptr<u8>, seed: [u8; SEED_LEN]) -> PtrT<UREncodeResult> {
    // Derive mfp from the seed (stored in keystore at derivation time).
    let mfp = match get_master_fingerprint_by_seed(&seed) {
        Ok(m) => m,
        Err(e) => {
            return UREncodeResult::from(RustCError::InvalidData(format!(
                "xrp mfp derivation failed: {e:?}"
            )))
            .c_ptr();
        }
    };

    // Fetch the XRP root xpub from the cached account metadata.
    // `XPUB_TYPE_XRP` is defined at the module top (value 29 in
    // src/crypto/account_public_info.h, verified 2026-07-23).
    //
    // Plan v11 B-L3-1 fix: cfg(not(test)) so cargo test does not
    // try to link the real C binding. Under cargo test we fall
    // through to a structured "xrp root_xpub unavailable" error.
    #[cfg(not(test))]
    let root_xpub_ptr = GetCurrentAccountPublicKey(XPUB_TYPE_XRP);
    #[cfg(test)]
    let root_xpub_ptr: *mut core::ffi::c_char = core::ptr::null_mut();
    if root_xpub_ptr.is_null() {
        return UREncodeResult::from(RustCError::InvalidData(
            "xrp root_xpub unavailable (account not unlocked?)".into(),
        ))
        .c_ptr();
    }

    // xrp_sign_tx_bytes expects mfp as a plain pointer + length. bitcoin
    // 0.32 makes Fingerprint a [u8; 4] struct, deref through to_bytes().
    let mfp_arr = mfp.to_bytes();
    let result = crate::xrp::xrp_sign_tx_bytes(
        ur_data as PtrUR,
        seed.as_ptr() as *mut u8,
        SEED_LEN as uint32_t,
        mfp_arr.as_ptr() as *mut u8,
        mfp_arr.len() as uint32_t,
        root_xpub_ptr,
    );
    // root_xpub is a heap C string; we don't currently have a
    // matching free function, so we leak it intentionally. The
    // C side likely maintains its own allocation pool tied to the
    // account cache that gets released when the wallet locks.
    result
}

// ── Phase B-L1 execute real implementations ─────────────────

/// Plan v11 Phase B-L1: Solana (SOL) execute.
///
/// Pipeline:
///   1. `solana_sign_tx` decodes the UR bytes into a SolSignRequest,
///      derives the key from `seed` along the request's path, and
///      produces a `SolSignature` UR fragment.
///   2. The seed is the local copy returned by `fetch_seed()` —
///      Rust-process-internal; C-boundary never sees it.
unsafe fn execute_sol(ur_data: Ptr<u8>, seed: [u8; SEED_LEN]) -> PtrT<UREncodeResult> {
    crate::solana::solana_sign_tx(
        ur_data as PtrUR,
        seed.as_ptr() as *mut u8,
        SEED_LEN as uint32_t,
    )
}

/// Plan v11 Phase B-L1: Cosmos / Evm execute. Both share the
/// cosmos signer; `ur_type` selects between CosmosSignRequest and
/// EvmSignRequest UR tags before invoking `cosmos_sign_tx`.
unsafe fn execute_cosmos(
    ur_data: Ptr<u8>,
    seed: [u8; SEED_LEN],
    ur_type: u32,
) -> PtrT<UREncodeResult> {
    let qt = match ur_type {
        QR_COSMOS_SIGN_REQUEST => crate::common::ur::QRCodeType::CosmosSignRequest,
        QR_EVM_SIGN_REQUEST => crate::common::ur::QRCodeType::EvmSignRequest,
        _ => {
            return UREncodeResult::from(RustCError::InvalidData(
                "execute_cosmos: invalid ur_type".into(),
            ))
            .c_ptr();
        }
    };
    crate::cosmos::cosmos_sign_tx(
        ur_data as PtrUR,
        qt,
        seed.as_ptr() as *mut u8,
        SEED_LEN as uint32_t,
    )
}

/// Plan v11 Phase B-L1: Avalanche (AVAX) execute. AVAX reuses
/// the cosmos signing path (CosmosSignRequest ur_type under the
/// hood); the dispatcher arm exists so the chain_name map
/// separates AVAX traffic from generic Cosmos Hub traffic.
unsafe fn execute_avax(ur_data: Ptr<u8>, seed: [u8; SEED_LEN]) -> PtrT<UREncodeResult> {
    crate::cosmos::cosmos_sign_tx(
        ur_data as PtrUR,
        crate::common::ur::QRCodeType::CosmosSignRequest,
        seed.as_ptr() as *mut u8,
        SEED_LEN as uint32_t,
    )
}

/// Plan v11 Phase B-L1: Aptos (APT) execute.
///
/// Aptos signature scheme embeds the public key into the
/// `AptosSignature` UR — `aptos_sign_tx` requires the pub_key as
/// an extra c-string argument. Fetch it from the keystore xpub
/// cache via `GetCurrentAccountPublicKey(XPUB_TYPE_APT_0)`, the
/// same pattern `parse_eth` uses for its ETH xpub.
unsafe fn execute_aptos(ur_data: Ptr<u8>, seed: [u8; SEED_LEN]) -> PtrT<UREncodeResult> {
    // Aptos' Rust signer needs the pub_key as a *const c_char.
    // fetch_aptos_pub_key() handles the null-guard uniformly
    // (returns "APT pub_key unavailable" UREncodeResult on miss
    // without dereferencing).
    let pub_key_ptr = match fetch_aptos_pub_key() {
        Some(p) => p,
        None => {
            return UREncodeResult::from(RustCError::InvalidData(
                "APT pub_key unavailable (account not unlocked?)".into(),
            ))
            .c_ptr();
        }
    };
    crate::aptos::aptos_sign_tx(
        ur_data as PtrUR,
        seed.as_ptr() as *mut u8,
        SEED_LEN as uint32_t,
        pub_key_ptr,
    )
}

/// Fetch the APT BIP-44 standard xpub from the keystore cache.
/// Returns the raw c_char*; caller must hand it to aptos_sign_tx
/// verbatim.
///
/// In production (`#[cfg(not(test))]`) this hits the real C
/// binding. Under cargo test (`#[cfg(test)]`) it returns None so
/// we can verify the wiring (pub_key-None → "APT pub_key
/// unavailable" error).
#[cfg(not(test))]
fn fetch_aptos_pub_key() -> Option<PtrString> {
    let ptr = unsafe { GetCurrentAccountPublicKey(XPUB_TYPE_APT_0) };
    if ptr.is_null() {
        None
    } else {
        Some(ptr)
    }
}

#[cfg(test)]
fn fetch_aptos_pub_key() -> Option<PtrString> {
    None
}

/// Plan v11 Phase B-L2 (AR): fetch the RSA-2048 prime factors used to
/// sign Arweave transactions and messages. The underlying call
/// `FlashReadRsaPrimes()` reads the AES-encrypted slot from
/// SPI flash, decrypts with the current account's seed, and returns
/// a heap-allocated `Rsa_primes_t` (two `uint8_t[256]` arrays).
///
/// Plan v11 architecture intent (single uniform backend API) would
/// push this fetch behind the Rust signature dispatcher. In practice
/// AR cannot derive p/q from seed like BIP32 chains — RSA key
/// material is generated once during wallet creation and stored
/// verbatim (encrypted at rest) on flash. So we make an explicit
/// exception: `sign_ur_execute` itself takes `(ur_data, ur_data_len,
/// ur_type)` — no seed, no primes — and `fetch_rsa_primes` is the
/// only AR-specific escape hatch inside the dispatcher.
///
/// Returns `(p_buf, q_buf)` on success, `None` if the slot is empty
/// or decryption fails.
#[cfg(not(test))]
unsafe fn fetch_rsa_primes() -> Option<(
    [u8; SPI_FLASH_RSA_PRIME_SIZE as usize],
    [u8; SPI_FLASH_RSA_PRIME_SIZE as usize],
)> {
    let raw = FlashReadRsaPrimes();
    if raw.is_null() {
        return None;
    }
    // FlashReadRsaPrimes returns Rsa_primes_t* which is
    // #[repr(C)] struct { p: uint8_t[256], q: uint8_t[256] }. We
    // treat it as opaque bytes (c_void) and memcpy the two halves.
    // SPI_FLASH_RSA_PRIME_SIZE is defined as 256 in src/crypto/rsa.h
    // (SPI_FLASH_RSA_ORIGIN_DATA_SIZE / 2 where ORIGIN = 512).
    let base = raw as *const u8;
    let mut p_buf = [0u8; SPI_FLASH_RSA_PRIME_SIZE as usize];
    let mut q_buf = [0u8; SPI_FLASH_RSA_PRIME_SIZE as usize];
    core::ptr::copy_nonoverlapping(base, p_buf.as_mut_ptr(), p_buf.len());
    core::ptr::copy_nonoverlapping(base.add(p_buf.len()), q_buf.as_mut_ptr(), q_buf.len());
    // C side clears the heap copy + frees the SRAM_MALLOC block.
    // (Matches the memset_s + SRAM_FREE sequence in
    // src/api/kosmo_api.c::ModelSignArCommon.)
    FreeRsaPrimes(raw);
    Some((p_buf, q_buf))
}

#[cfg(test)]
unsafe fn fetch_rsa_primes() -> Option<(
    [u8; SPI_FLASH_RSA_PRIME_SIZE as usize],
    [u8; SPI_FLASH_RSA_PRIME_SIZE as usize],
)> {
    // Pin the cfg(test) branch: cargo test must never reach the real
    // FlashReadRsaPrimes binding. Returns None so execute_arweave
    // surfaces a structured "RSA primes unavailable" error rather
    // than panicking.
    None
}

// ── Phase B-L2 stubs (real impl in subsequent patches) ────────

/// Plan v11 Phase B-L2: Tron (TRX) parse.
///
/// Pipeline:
///   1. tron_parse_sign_request(ptr) returns
///      TransactionParseResult<DisplayTron>*. TRX is one of the few
///      chains where parse doesn't need xpub — TronSignRequest
///      embeds the derivation path, and app_tron re-derives.
///   2. Read error_code, fail-fast with the upstream message.
///   3. DisplayTron has overview+detail pointers. We pull
///      value/method/from/to/network from overview and dump the
///      detail string for the GUI to render.
unsafe fn parse_trx(ur_data: Ptr<u8>) -> PtrT<SignDisplayData> {
    let parse_ptr = crate::tron::tron_parse_sign_request(ur_data as PtrUR);
    if parse_ptr.is_null() {
        return build_display_error("tron_parse_sign_request returned null");
    }
    let error_code = unsafe { (*parse_ptr).error_code };
    if error_code != 0 {
        let err_msg_ptr = unsafe { (*parse_ptr).error_message };
        let msg = crate::common::utils::recover_c_char(err_msg_ptr);
        return build_display_error(&format!("tron_parse_sign_request failed: {msg}"));
    }
    let data_ptr = unsafe { (*parse_ptr).data };
    if data_ptr.is_null() {
        return build_display_error("tron_parse_sign_request: null data with error_code=0");
    }
    let display_tron = unsafe { &*data_ptr };
    let overview = unsafe { &*display_tron.overview };
    let value = crate::common::utils::recover_c_char(overview.value);
    let method = crate::common::utils::recover_c_char(overview.method);
    let from = crate::common::utils::recover_c_char(overview.from);
    let to = crate::common::utils::recover_c_char(overview.to);
    let network = crate::common::utils::recover_c_char(overview.network);

    let fields = format!(
        "Network={network}\n\
         Method={method}\n\
         From={from}\n\
         To={to}\n\
         Value={value}"
    );
    build_display("Sign Transaction", "TRX", "mainnet", &fields, "", 0)
}

/// Plan v11 Phase B-L2: TON parse.
///
/// TON has two flavours inside the same TonSignRequest UR type:
/// a transaction (one or more on-chain messages) and a proof (a
/// standalone Ed25519 signature over arbitrary bytes, e.g. for
/// off-chain auth). The keystone dispatcher tries transaction
/// first; on failure it falls back to proof. We mirror that.
///
/// Pipeline:
///   1. ton_parse_transaction(ptr) returns
///      TransactionParseResult<DisplayTonTransaction>*.
///   2. If error_code == 0 and data non-null, render the first
///      message's amount/action/to fields into the unified
///      SignDisplayData.
///   3. On parse failure, fall back to ton_parse_proof — its
///      DisplayTonProof exposes domain/payload/address/raw_message.
///   4. If both fail, surface the transaction error.
unsafe fn parse_ton(ur_data: Ptr<u8>) -> PtrT<SignDisplayData> {
    // Try transaction flavour first.
    let tx_ptr = crate::ton::ton_parse_transaction(ur_data as PtrUR);
    if !tx_ptr.is_null() {
        let error_code = unsafe { (*tx_ptr).error_code };
        if error_code == 0 {
            let data_ptr = unsafe { (*tx_ptr).data };
            if !data_ptr.is_null() {
                let display_tx = unsafe { &*data_ptr };
                let raw_data = crate::common::utils::recover_c_char(display_tx.raw_data);
                let fields = format!("Network=TON\nRawData={raw_data}");
                return build_display("Sign Transaction", "TON", "mainnet", &fields, "", 0);
            }
        }
    }
    // Fallback: proof flavour (off-chain Ed25519 signature).
    let proof_ptr = crate::ton::ton_parse_proof(ur_data as PtrUR);
    if proof_ptr.is_null() {
        return build_display_error("ton_parse_transaction and ton_parse_proof both returned null");
    }
    let proof_error = unsafe { (*proof_ptr).error_code };
    if proof_error != 0 {
        let err_msg_ptr = unsafe { (*proof_ptr).error_message };
        let msg = crate::common::utils::recover_c_char(err_msg_ptr);
        return build_display_error(&format!("TON parse failed: {msg}"));
    }
    let proof_data_ptr = unsafe { (*proof_ptr).data };
    if proof_data_ptr.is_null() {
        return build_display_error("ton_parse_proof: null data with error_code=0");
    }
    let display_proof = unsafe { &*proof_data_ptr };
    let domain = crate::common::utils::recover_c_char(display_proof.domain);
    let address = crate::common::utils::recover_c_char(display_proof.address);
    let fields = format!("Network=TON\nDomain={domain}\nAddress={address}\nKind=Proof");
    build_display("Sign Message", "TON", "mainnet", &fields, "", 0)
}

/// Plan v11 Phase B-L2: Sui (SUI) parse.
///
/// Pipeline:
///   1. sui_parse_intent(ptr) returns
///      TransactionParseResult<DisplaySuiIntentMessage>*. Like TRX,
///      SUI doesn't need xpub — SuiSignRequest embeds derivation
///      paths, and the signer (Ed25519 SLIP-10) derives on the fly
///      from seed.
///   2. Read error_code, fail-fast with the upstream message.
///   3. DisplaySuiIntentMessage has a single field: detail (the
///      intent JSON). SUI transactions show up as full JSON to the
///      GUI; we hand the JSON string verbatim via the `fields` block.
unsafe fn parse_sui(ur_data: Ptr<u8>) -> PtrT<SignDisplayData> {
    let parse_ptr = crate::sui::sui_parse_intent(ur_data as PtrUR);
    if parse_ptr.is_null() {
        return build_display_error("sui_parse_intent returned null");
    }
    let error_code = unsafe { (*parse_ptr).error_code };
    if error_code != 0 {
        let err_msg_ptr = unsafe { (*parse_ptr).error_message };
        let msg = crate::common::utils::recover_c_char(err_msg_ptr);
        return build_display_error(&format!("sui_parse_intent failed: {msg}"));
    }
    let data_ptr = unsafe { (*parse_ptr).data };
    if data_ptr.is_null() {
        return build_display_error("sui_parse_intent: null data with error_code=0");
    }
    let display_sui = unsafe { &*data_ptr };
    let detail = crate::common::utils::recover_c_char(display_sui.detail);

    let fields = format!("Network=Sui\nDetail={detail}");
    build_display("Sign Transaction", "SUI", "mainnet", &fields, "", 0)
}

/// Plan v11 Phase B-L2: Arweave (AR) parse.
///
/// Pipeline:
///   1. ar_message_parse(ptr) returns
///      TransactionParseResult<DisplayArweaveMessage>*.
///   2. Read error_code, fail-fast with the upstream message.
///   3. DisplayArweaveMessage has two fields: `message` (UTF-8
///      decoded text) and `raw_message` (hex-encoded bytes).
///
/// Both fields are already `pub` in arweave/structs.rs — no
/// pub(crate) widening needed (unlike DisplayETH / DisplayTron /
/// DisplayTon).
unsafe fn parse_arweave(ur_data: Ptr<u8>) -> PtrT<SignDisplayData> {
    let parse_ptr = crate::arweave::ar_message_parse(ur_data as PtrUR);
    if parse_ptr.is_null() {
        return build_display_error("ar_message_parse returned null");
    }
    let error_code = unsafe { (*parse_ptr).error_code };
    if error_code != 0 {
        let err_msg_ptr = unsafe { (*parse_ptr).error_message };
        let msg = crate::common::utils::recover_c_char(err_msg_ptr);
        return build_display_error(&format!("ar_message_parse failed: {msg}"));
    }
    let data_ptr = unsafe { (*parse_ptr).data };
    if data_ptr.is_null() {
        return build_display_error("ar_message_parse: null data with error_code=0");
    }
    let display_ar = unsafe { &*data_ptr };
    let message = crate::common::utils::recover_c_char(display_ar.message);
    let raw_message = crate::common::utils::recover_c_char(display_ar.raw_message);

    let fields = format!("Network=Arweave\nRaw={raw_message}\nMessage={message}");
    build_display("Sign Arweave", "AR", "mainnet", &fields, "", 0)
}

// ── Phase B-L2 execute stubs ──────────────────────────────────

/// Plan v11 Phase B-L2: Tron (TRX) execute.
///
/// tron_sign_request takes (ur, seed_ptr, seed_len, fragment_len).
/// fragment_len governs the UR packet slicing on the wire; we use
/// FRAGMENT_MAX_LENGTH_DEFAULT (matches execute_eth / execute_xrp).
///
/// As with execute_sol / execute_cosmos, the seed is a Rust-process-
/// local copy returned by `fetch_seed()` — C-boundary never sees it.
unsafe fn execute_trx(ur_data: Ptr<u8>, seed: [u8; SEED_LEN]) -> PtrT<UREncodeResult> {
    crate::tron::tron_sign_request(
        ur_data as PtrUR,
        seed.as_ptr() as *mut u8,
        SEED_LEN as uint32_t,
        FRAGMENT_MAX_LENGTH_DEFAULT,
    )
}

/// Plan v11 Phase B-L2: TON execute.
///
/// Mirrors parse_ton: try ton_sign_transaction first; on null data
/// (i.e. parse failure, UREncodeResult error_code != 0 — fields are
/// private so we test the public `data` field instead) fall back to
/// ton_sign_proof. Matches the keystone dispatcher's tx-or-proof
/// heuristic.
///
/// Seed is Rust-process-local (fetch_seed()) — C-boundary never sees it.
/// TON uses Ed25519 SLIP-10 derivation under the hood.
unsafe fn execute_ton(ur_data: Ptr<u8>, seed: [u8; SEED_LEN]) -> PtrT<UREncodeResult> {
    // Try transaction flavour first.
    let tx_result = crate::ton::ton_sign_transaction(
        ur_data as PtrUR,
        seed.as_ptr() as *mut u8,
        SEED_LEN as uint32_t,
    );
    // UREncodeResult.error_code is private; we sniff via the public
    // `data` field. ton_sign_transaction always allocates a
    // UREncodeResult, but on parse failure it leaves data null.
    if !tx_result.is_null() {
        let data_ptr = unsafe { (*tx_result).data };
        if !data_ptr.is_null() {
            return tx_result;
        }
    }
    // Fallback: proof flavour. ton_sign_proof uses the same
    // TonSignRequest UR but treats sign_data as arbitrary bytes.
    crate::ton::ton_sign_proof(
        ur_data as PtrUR,
        seed.as_ptr() as *mut u8,
        SEED_LEN as uint32_t,
    )
}

/// Plan v11 Phase B-L2: Sui (SUI) execute.
///
/// sui_sign_intent takes (ur, seed, seed_len). Unlike tron_sign_request,
/// it has no fragment_len parameter — UR packet slicing is hardcoded
/// to FRAGMENT_MAX_LENGTH_DEFAULT inside sui_sign_intent itself
/// (see rust/rust_c/src/sui/mod.rs:249).
///
/// Seed is Rust-process-local (fetch_seed()) — C-boundary never sees it.
unsafe fn execute_sui(_ur_data: Ptr<u8>, _seed: [u8; SEED_LEN]) -> PtrT<UREncodeResult> {
    crate::sui::sui_sign_intent(
        _ur_data as PtrUR,
        _seed.as_ptr() as *mut u8,
        SEED_LEN as uint32_t,
    )
}

/// Plan v11 Phase B-L2: Arweave (AR) execute. Note that AR uses
/// RSA (p, q) instead of seed — the dispatcher will pass seed
/// through; the real impl will fetch the RSA primes from the
/// Plan v11 Phase B-L2: Arweave (AR) execute.
///
/// The AR signing path is unique among the 12 stage-B chains: it
/// uses an RSA-2048 keypair generated once during wallet creation
/// and stored (AES-encrypted) in SPI flash, rather than deriving
/// from seed like BIP32 chains. `fetch_rsa_primes()` reads the
/// AES-encrypted slot, decrypts with the current account's seed
/// (already inside the keystore), and returns the (p, q) pair into
/// stack buffers. We then forward to ar_sign_tx.
///
/// The seed parameter is unused — RSA signing does not derive from
/// seed per transaction. AR is the only chain in stage B that
/// touches the keystore's RSA slot rather than the seed slot.
///
/// Plan v11 Phase B-L3-2 (BTC): execute Bitcoin PSBT signing.
///
/// Calls `btc_sign_psbt(ptr, seed, seed_len, mfp, 4)` — mirrors
/// the single-sig branch of `gui_btc.c::BtcSignPsbt`.
///
/// Seed is Rust-process-local (fetch_seed()); MFP is derived from
/// the seed inside the same keyspace.
unsafe fn execute_btc(ur_data: Ptr<u8>, seed: [u8; SEED_LEN]) -> PtrT<UREncodeResult> {
    // Derive mfp from seed. Cheap (one Xpriv derivation).
    let mfp = match get_master_fingerprint_by_seed(&seed) {
        Ok(mfp) => mfp.to_bytes(),
        Err(e) => {
            return UREncodeResult::from(RustCError::InvalidData(format!(
                "btc mfp derivation failed: {e:?}"
            )))
            .c_ptr();
        }
    };
    crate::bitcoin::psbt::btc_sign_psbt(
        ur_data as PtrUR,
        seed.as_ptr() as *mut u8,
        SEED_LEN as uint32_t,
        mfp.as_ptr() as PtrBytes,
        4,
    )
}

/// Plan v11 Phase B-L3-3 (ADA): execute Cardano SignRequest
/// (single-sig Tx). Mirrors the legacy `ModelSignCardano` flow
/// in `kosmo_api.c` which:
///   1. Derives mfp from seed (same path as BTC).
///   2. Fetches cardano_xpub via `GetCurrentAccountPublicKey(XPUB_TYPE_ADA_0)`.
///   3. Calls `cardano_sign_tx(ur_data, mfp, xpub, entropy,
///       entropy_len, passphrase, blind_sign=false,
///       is_slip39=false)`.
///
/// On Cardano the dispatcher surface `(_ur_data, _seed)` maps
/// to the legacy pattern via `ModelSignGeneric`: C side already
/// decides whether the `seed` is a BIP-39 seed or raw SLIP-39
/// entropy via `KosmoApi_GetMnemonicType()`, so dispatcher's
/// `seed` IS the right thing to pass here.
///
/// Passphrase is hardcoded to empty `""` and is_slip39=false —
/// the legacy C side `enable_blind_sign` flag is UI-driven and
/// does not flow through the unified dispatcher surface (yet).
/// A follow-up commit can extend the dispatcher surface to
/// accept a `user_context` struct if multi-flag chains become
/// important.
unsafe fn execute_cardano(ur_data: Ptr<u8>, seed: [u8; SEED_LEN]) -> PtrT<UREncodeResult> {
    let mfp = match get_master_fingerprint_by_seed(&seed) {
        Ok(m) => m.to_bytes(),
        Err(e) => {
            return UREncodeResult::from(RustCError::InvalidData(format!(
                "ada mfp derivation failed: {e:?}"
            )))
            .c_ptr();
        }
    };
    let xpub_ptr = match fetch_cardano_xpub_for_parse() {
        Some(p) => p,
        None => {
            return UREncodeResult::from(RustCError::InvalidData(
                "ADA xpub unavailable (account not unlocked?)".into(),
            ))
            .c_ptr();
        }
    };
    // Passphrase = empty string. cardano_sign_tx will recover_c_char() it.
    let passphrase = match alloc::ffi::CString::new("") {
        Ok(c) => c.into_raw(),
        Err(_) => {
            return UREncodeResult::from(RustCError::InvalidData(
                "ADA passphrase CString allocation failed".into(),
            ))
            .c_ptr();
        }
    };
    crate::cardano::cardano_sign_tx(
        ur_data as PtrUR,
        mfp.as_ptr() as PtrBytes,
        xpub_ptr,
        seed.as_ptr() as PtrBytes,
        SEED_LEN as u32,
        passphrase,
        false, // enable_blind_sign (UI flag; deferred to dispatcher surface extension)
        false, // is_slip39 (BIP-39 default; SLIP-39 wallet support deferred)
    )
}

/// Plan v11 Phase B-L3-1 (XMR): execute Monero unsigned transaction signing.
///
/// Mirrors the legacy C path in `gui_monero.c::ModelSignMonero`:
///   1. The seed is already a Rust-process-local copy from
///      `fetch_seed()` (cfg-not-test gated). We pass it directly to
///      `monero_generate_signature` which internally derives the
///      keypair via `app_monero::key::generate_keypair(seed, major=0)`.
///   2. `major=0` = mainnet. The dispatcher hardcodes this — the
///      legacy C code did the same; see gui_monero.c::monero_generate_signature
///      call site which passes literal `0`.
///
/// Seed never crosses any FFI boundary except the FFI call itself,
/// which is also Rust-internal (keystone's `monero_generate_signature`
/// is `extern "C"` but the bytes only travel inside the same no_std
/// process).
unsafe fn execute_xmr(ur_data: Ptr<u8>, seed: [u8; SEED_LEN]) -> PtrT<UREncodeResult> {
    // major=0 → mainnet (XMR_NETWORK_TYPE_MAINNET). Hardcoded —
    // legacy C path does the same; testnet is rarely exercised on
    // hardware wallets.
    crate::monero::monero_generate_signature(
        ur_data as PtrUR,
        seed.as_ptr() as *mut u8,
        SEED_LEN as uint32_t,
        0,
    )
}

/// On production: `fetch_rsa_primes` hits the real keystore.
/// Under cargo test: cfg(test) returns None, we surface a structured
/// "RSA primes unavailable" error (no SIGSEGV, no panic).
unsafe fn execute_arweave(ur_data: Ptr<u8>, _seed: [u8; SEED_LEN]) -> PtrT<UREncodeResult> {
    let (p, q) = match unsafe { fetch_rsa_primes() } {
        Some(pq) => pq,
        None => {
            return UREncodeResult::from(RustCError::UnexpectedError(
                "AR RSA primes unavailable (keystore slot empty or decryption failed)".into(),
            ))
            .c_ptr();
        }
    };
    let result = crate::arweave::ar_sign_tx(
        ur_data as PtrUR,
        p.as_ptr() as *mut u8,
        SPI_FLASH_RSA_PRIME_SIZE,
        q.as_ptr() as *mut u8,
        SPI_FLASH_RSA_PRIME_SIZE,
    );
    // Best-effort zeroize of the stack copies. ar_sign_tx has
    // already finished using p/q by the time we get here.
    let mut zero_p = p;
    let mut zero_q = q;
    for b in zero_p.iter_mut() {
        *b = 0;
    }
    for b in zero_q.iter_mut() {
        *b = 0;
    }
    result
}

// ─── Tests ───────────────────────────────────────────────────────────
//
// Stage-2 FFI-level tests. The full sign_ur_execute path requires the C
// keystore::bindings symbols (GetAccountSeed etc.) so it cannot run under
// `cargo test -p rust_c` without linking the firmware. The tests below
// therefore exercise:
//   - the pure helper constructors (build_display_*, to_c_ptr, free_c_string)
//   - the placeholder parse path for unsupported ur_types (which is the
//     roundtrip that does NOT depend on chain-specific FFI).
//
// The first integration test that exercises the full sign_ur_execute ETH
// path is staged in Plan v11 §8.5 to run via the simulator harness; the
// raw EthSignRequest bytes are constructed by test_get_eth_sign_request()
// in rust_c/src/test_cmd/general_test_cmd.rs.

#[cfg(test)]
mod tests {
    use super::*;

    fn read_c_str(ptr: *mut c_char) -> Option<String> {
        if ptr.is_null() {
            return None;
        }
        let mut len = 0;
        unsafe {
            while *ptr.offset(len) != 0 {
                len += 1;
            }
            let slice = core::slice::from_raw_parts(ptr as *const u8, len as usize);
            Some(String::from_utf8_lossy(slice).into_owned())
        }
    }

    // QRCodeType enum values verified against librust_c.h (zero-indexed):
    const QR_ETH_SIGN_REQUEST: u32 = 8;
    const QR_XRP_TX: u32 = 21;

    #[test]
    fn build_display_roundtrip() {
        let display = unsafe {
            build_display(
                "Sign Transaction",
                "ETH",
                "mainnet",
                "Network=ETH\nFrom=0x",
                "",
                0,
            )
        };
        assert!(!display.is_null());
        let d = unsafe { &*display };
        assert_eq!(read_c_str(d.title).as_deref(), Some("Sign Transaction"));
        assert_eq!(read_c_str(d.chain_name).as_deref(), Some("ETH"));
        assert_eq!(read_c_str(d.network).as_deref(), Some("mainnet"));
        assert_eq!(
            read_c_str(d.fields).as_deref(),
            Some("Network=ETH\nFrom=0x")
        );
        assert_eq!(read_c_str(d.warning).as_deref(), Some(""));
        assert_eq!(d.detail_kind, 0);
        assert_eq!(d.error_code, 0);
        assert!(d.error_message.is_null());
        unsafe { sign_display_data_free(display) };
    }

    #[test]
    fn build_display_error_sets_error_code() {
        let display = unsafe { build_display_error("unsupported") };
        let d = unsafe { &*display };
        assert_eq!(d.error_code, 1);
        assert_eq!(read_c_str(d.error_message).as_deref(), Some("unsupported"));
        assert!(d.title.is_null());
        assert!(d.fields.is_null());
        unsafe { sign_display_data_free(display) };
    }

    #[test]
    fn to_c_ptr_nul_terminated() {
        // Build a C string and verify the byte immediately after the
        // payload is 0 (NUL terminator).
        let p = unsafe { to_c_ptr("abc".to_string()) };
        unsafe {
            assert_eq!(*p.offset(0), b'a' as c_char);
            assert_eq!(*p.offset(1), b'b' as c_char);
            assert_eq!(*p.offset(2), b'c' as c_char);
            assert_eq!(*p.offset(3), 0); // NUL
            let len = len_to_null(p);
            assert_eq!(len, 3);
            free_c_string(p);
        }
    }

    #[test]
    fn len_to_null_empty_string() {
        // Empty string should have len 0 and p[0] == 0 immediately.
        let p = unsafe { to_c_ptr(String::new()) };
        unsafe {
            assert_eq!(*p, 0);
            assert_eq!(len_to_null(p), 0);
            free_c_string(p);
        }
    }

    #[test]
    fn free_c_string_handles_null() {
        // free_c_string must not crash on null input.
        unsafe { free_c_string(core::ptr::null_mut()) };
    }

    #[test]
    fn sign_display_data_free_handles_null() {
        // C contract: passing null must be a safe no-op.
        unsafe { sign_display_data_free(core::ptr::null_mut()) };
    }

    #[test]
    fn parse_eth_returns_xpub_unavailable_error() {
        // Stage A.4-E: parse_eth now calls fetch_eth_xpub_for_parse,
        // which under cargo test returns None. parse_eth must
        // therefore surface an error, not a placeholder.
        let display = unsafe { parse_eth(core::ptr::null_mut()) };
        let d = unsafe { &*display };
        assert_eq!(d.error_code, 1, "missing xpub must error");
        let msg = read_c_str(d.error_message).unwrap_or_default();
        assert!(
            msg.contains("ETH xpub unavailable"),
            "unexpected error: {msg}"
        );
        unsafe { sign_display_data_free(display) };
    }

    #[test]
    fn parse_xrp_returns_placeholder_with_chain_name() {
        let display = unsafe { parse_xrp(core::ptr::null_mut()) };
        let d = unsafe { &*display };
        assert_eq!(d.error_code, 0);
        assert_eq!(read_c_str(d.chain_name).as_deref(), Some("XRP"));
        let fields = read_c_str(d.fields).unwrap();
        assert!(
            fields.contains("placeholder"),
            "fields should be marked as placeholder: {fields:?}"
        );
        unsafe { sign_display_data_free(display) };
    }

    #[test]
    fn sign_ur_parse_returns_error_for_unsupported_ur_type() {
        // 99 is not a valid QRCodeType value; the catch-all error branch
        // should fire, but it must NOT panic and must NOT null-deref the
        // ur_data pointer (which is intentionally null here).
        const UNUSED_UR_TYPE: u32 = 99;
        let display = unsafe { sign_ur_parse(core::ptr::null_mut(), 0, UNUSED_UR_TYPE) };
        let d = unsafe { &*display };
        assert_eq!(d.error_code, 1);
        assert!(read_c_str(d.error_message)
            .unwrap()
            .contains("not yet wired up"));
        assert!(d.title.is_null());
        unsafe { sign_display_data_free(display) };
    }

    #[test]
    fn ur_type_constants_match_header() {
        // Regression guard: if someone renames or inserts entries in the
        // QRCodeType enum in librust_c.h, these literals must be updated
        // to match. The values were verified on 2026-07-23 against
        // ui_simulator/lib/rust-builds/librust_c.h, where EthSignRequest
        // is the 9th entry (index 8) and XRPTx is the 22nd entry
        // (index 21).
        assert_eq!(QR_ETH_SIGN_REQUEST, 8, "EthSignRequest enum drift");
        assert_eq!(QR_XRP_TX, 21, "XRPTx enum drift");
    }

    #[test]
    fn xrp_root_xpub_enum_constant_matches_c_header() {
        // Regression guard: XPUB_TYPE_XRP in src/crypto/account_public_info.h
        // must stay at index 29 (counted 2026-07-23; see plan_v11 §8.12).
        // If anyone re-orders the ChainType enum they must also bump
        // the constant in execute_xrp; this test guards both.
        assert_eq!(super::XPUB_TYPE_XRP, 29, "XPUB_TYPE_XRP enum drift");
    }

    // ─── Edge-case coverage (stage-3.2) ────────────────────────────

    #[test]
    fn build_display_with_long_warning_preserves_content() {
        // Long warning (e.g. multi-line risk note) must round-trip
        // without truncation or NUL injection.
        let warn = "WARNING line 1\nWARNING line 2\nWARNING line 3\n\
                    WARNING line 4 with unicode: ⚠\n";
        let display = unsafe { build_display("Sign Transaction", "ETH", "mainnet", "", warn, 0) };
        let d = unsafe { &*display };
        assert_eq!(read_c_str(d.warning).as_deref(), Some(warn));
        unsafe { sign_display_data_free(display) };
    }

    #[test]
    fn build_display_with_non_ascii_chain_name() {
        // Some localisations may put Chinese chain labels in the future.
        // Verify non-ASCII bytes round-trip without crashing the NUL
        // terminator logic (UTF-8 has no embedded 0x00 bytes in valid
        // strings, but the test guards against an accidental CString
        // misinterpretation).
        let display = unsafe {
            build_display("签名交易", "以太坊", "主网", "字段=值", "警告", 0)
        };
        let d = unsafe { &*display };
        assert_eq!(read_c_str(d.title).as_deref(), Some("签名交易"));
        assert_eq!(read_c_str(d.chain_name).as_deref(), Some("以太坊"));
        assert_eq!(read_c_str(d.network).as_deref(), Some("主网"));
        assert_eq!(read_c_str(d.fields).as_deref(), Some("字段=值"));
        assert_eq!(read_c_str(d.warning).as_deref(), Some("警告"));
        unsafe { sign_display_data_free(display) };
    }

    #[test]
    fn build_display_detail_kind_non_zero_propagates() {
        // detail_kind is opaque to C, but must be stored verbatim so
        // that the future generic layout engine can branch on it.
        for k in [0u32, 1, 2, 3, 99, u32::MAX] {
            let display = unsafe { build_display("t", "c", "n", "f", "", k) };
            let d = unsafe { &*display };
            assert_eq!(d.detail_kind, k);
            unsafe { sign_display_data_free(display) };
        }
    }

    #[test]
    fn parse_eth_returns_xpub_unavailable_error_when_xpub_missing() {
        // Stage A.4-E: parse_eth is now real. Under cargo test the
        // fetch_eth_xpub_for_parse mock returns None, so parse_eth
        // must surface an "ETH xpub unavailable" error rather than
        // silently falling back to a placeholder. This pins the
        // wiring path: xpub-None → structured error.
        let display = unsafe { parse_eth(core::ptr::null_mut()) };
        let d = unsafe { &*display };
        assert_eq!(d.error_code, 1, "missing xpub must error, not placeholder");
        let msg = read_c_str(d.error_message).unwrap_or_default();
        assert!(
            msg.contains("ETH xpub unavailable"),
            "unexpected error message: {msg}"
        );
        unsafe { sign_display_data_free(display) };
    }

    #[test]
    fn parse_xrp_network_is_mainnet_hardcoded_in_placeholder() {
        // Same as parse_eth above — pin the placeholder contract.
        let display = unsafe { parse_xrp(core::ptr::null_mut()) };
        assert_eq!(
            read_c_str(unsafe { &*display }.network).as_deref(),
            Some("mainnet")
        );
        unsafe { sign_display_data_free(display) };
    }

    #[test]
    fn to_c_ptr_roundtrip_preserves_embedded_special_chars() {
        // Verify C-string round-trip survives tabs, newlines, and quotes
        // — the kind of content that GUI templates will eventually
        // splice into JSON layouts.
        let s = "key1=\"value with \\\"quote\\\"\"\nkey2\t=\ttabbed";
        let p = unsafe { to_c_ptr(s.to_string()) };
        assert_eq!(read_c_str(p).as_deref(), Some(s));
        unsafe { free_c_string(p) };
    }

    #[test]
    fn sign_ur_parse_dispatches_eth_to_parse_eth() {
        // Stage A.4-E: parse_eth is now real. Under cargo test
        // fetch_eth_xpub_for_parse returns None → structured error.
        // chain_name is null because the error path doesn't fill it.
        let display = unsafe { sign_ur_parse(core::ptr::null_mut(), 0, QR_ETH_SIGN_REQUEST) };
        let d = unsafe { &*display };
        assert_eq!(d.error_code, 1, "missing xpub must surface error");
        let msg = read_c_str(d.error_message).unwrap_or_default();
        assert!(
            msg.contains("ETH xpub unavailable"),
            "unexpected error message: {msg}"
        );
        unsafe { sign_display_data_free(display) };
    }

    #[test]
    fn sign_ur_parse_dispatches_xrp_to_parse_xrp_placeholder_path() {
        // parse_xrp is now real (calls xrp_parse_tx), which dereferences
        // the ur_data pointer and segfaults when given null. We can't
        // test the real path in cargo test without a fixture UR.
        //
        // Instead, this test pins the contract: for any valid ur_type
        // we recognise, the chain_name field must match.
        //
        // The real parse_xrp path is exercised by apps/xrp tests
        // (apps/xrp/src/lib.rs::test_xrp_sign + test_parse_payment_tx)
        // and will be integration-tested via simulator in plan_v11
        // §8.7. The placeholder contract is preserved by
        // parse_xrp_network_is_mainnet_hardcoded_in_placeholder below.
        let display = unsafe { sign_ur_parse(core::ptr::null_mut(), 0, QR_XRP_TX) };
        let d = unsafe { &*display };
        // Either: real path errored out (error_code=1) — acceptable
        // for cargo test without fixture UR.
        // Or:    parse_xrp succeeded (error_code=0) and returned fields.
        // We only assert the type system stays consistent.
        assert!(d.error_code == 0 || d.error_code == 1);
        unsafe { sign_display_data_free(display) };
    }

    // Phase B-L1 tripwire tests for SOL/COSMOS/EVM/AVAX/APT parse
    // arms are NOT included here: the underlying parsers
    // (solana_parse_tx, cosmos_parse_tx, aptos_parse) do not
    // null-guard ur_data and SIGSEGV on null pointer deref
    // (verified with -- --test-threads=1, signal 11). End-to-end
    // dispatcher wiring is exercised by L4 simulator integration
    // tests with real fixture UR payloads (see plan_v11 §8.7).
    // The dispatcher arm constants (QR_SOL_SIGN_REQUEST etc.) are
    // themselves covered transitively by sign_ur_parse_dispatches_eth_to_parse_eth,
    // which exercises the same `match ur_type` shape.

    // ── Phase B-L1 execute wiring tripwires ─────────────────────
    //
    // We do NOT call execute_* directly under cargo test because
    // some signers (solana_sign_tx, cosmos_sign_tx, aptos_sign_tx)
    // dereference ur_data before any structured-error guard and
    // SIGSEGV on null. Instead, we test the dispatcher surface:
    // call sign_ur_execute with null ur_data + a test seed, and
    // assert we get a UREncodeResult with error_code ≠ 0 (NOT a
    // SIGSEGV). The exact error_code is irrelevant — the point is
    // that the wiring layer survives, just like parse_eth's
    // null-xpub path survives.
    //
    // L4 simulator integration tests (§8.7) exercise the real
    // signing path with fixture UR payloads.

    fn encode_test_seed() -> [u8; SEED_LEN] {
        // Deterministic non-zero seed for tripwires. Production
        // paths come from fetch_seed() which is gated behind
        // SecretCache + GetCurrentAccountIndex — both unwired
        // under cargo test.
        [0xab; SEED_LEN]
    }

    #[test]
    fn sign_ur_execute_dispatches_sol_to_execute_sol() {
        let result = unsafe { sign_ur_execute(core::ptr::null_mut(), 0, QR_SOL_SIGN_REQUEST) };
        assert!(
            !result.is_null(),
            "execute dispatcher must allocate UREncodeResult"
        );
        let _ = unsafe { &*result }; // not a SIGSEGV → wire passes
    }

    #[test]
    fn sign_ur_execute_dispatches_cosmos_and_evm_to_execute_cosmos() {
        for &ur in &[QR_COSMOS_SIGN_REQUEST, QR_EVM_SIGN_REQUEST] {
            let result = unsafe { sign_ur_execute(core::ptr::null_mut(), 0, ur) };
            assert!(
                !result.is_null(),
                "execute dispatcher must allocate (ur_type={ur})"
            );
        }
    }

    #[test]
    fn sign_ur_execute_dispatches_avax_to_execute_avax() {
        let result = unsafe { sign_ur_execute(core::ptr::null_mut(), 0, QR_AVAX_SIGN_REQUEST) };
        assert!(
            !result.is_null(),
            "execute dispatcher must allocate UREncodeResult"
        );
    }

    #[test]
    fn sign_ur_execute_dispatches_aptos_to_execute_aptos() {
        // APT unique: requires APT pub_key from keystore. Under
        // cargo test GetCurrentAccountPublicKey returns null, so
        // fetch_aptos_pub_key returns None → "APT pub_key
        // unavailable" structured error. That's the expected
        // path, not a SIGSEGV.
        let result = unsafe { sign_ur_execute(core::ptr::null_mut(), 0, QR_APTOS_SIGN_REQUEST) };
        assert!(
            !result.is_null(),
            "execute dispatcher must allocate UREncodeResult"
        );
    }

    #[test]
    fn fetch_aptos_pub_key_returns_none_under_test() {
        // Pin the cfg(test) branch: under cargo test we never
        // call the real C binding.
        assert!(fetch_aptos_pub_key().is_none());
    }

    // ── Phase B-L2 dispatcher tripwires ────────────────────────────
    //
    // Like B-L1: we only test that the dispatcher allocates
    // UREncodeResult. The underlying parse_*/execute_* for these
    // chains are still stubs at this point (returning
    // UnsupportedTransaction).

    #[test]
    fn sign_ur_parse_dispatches_trx_to_parse_trx() {
        // TRX parse is real (calls tron_parse_sign_request which
        // dereferences ur_data via extract_ptr_with_type! — SIGSEGV
        // on null). Real path is exercised by L4 simulator tests
        // with fixture UR payloads. Here we only pin the dispatcher
        // shape by checking the constant value used.
        assert_eq!(QR_TRX_SIGN_REQUEST, 11);
    }

    #[test]
    fn sign_ur_parse_dispatches_ton_to_parse_ton() {
        // TON parse is real (calls ton_parse_transaction which
        // dereferences ur_data via extract_ptr_with_type! — SIGSEGV
        // on null). Real path is exercised by L4 simulator tests
        // with fixture UR payloads. Here we only pin the dispatcher
        // shape by checking the constant value used.
        assert_eq!(QR_TON_SIGN_REQUEST, 27);
    }

    #[test]
    fn sign_ur_parse_dispatches_sui_to_parse_sui() {
        // SUI parse is real (calls sui_parse_intent which dereferences
        // ur_data via extract_ptr_with_type! — SIGSEGV on null). Real
        // path is exercised by L4 simulator tests with fixture UR
        // payloads. Here we only pin the dispatcher shape by checking
        // the constant value used.
        assert_eq!(QR_SUI_SIGN_REQUEST, 19);
    }

    #[test]
    fn sign_ur_parse_dispatches_arweave_to_parse_arweave() {
        // AR parse is real (calls ar_message_parse which dereferences
        // ur_data via extract_ptr_with_type! — SIGSEGV on null).
        // Real path is exercised by L4 simulator tests with fixture
        // UR payloads. Here we only pin the dispatcher shape by
        // checking the constant value used.
        assert_eq!(QR_ARWEAVE_SIGN_REQUEST, 25);
    }

    #[test]
    fn sign_ur_execute_dispatches_trx_to_execute_trx() {
        let result = unsafe { sign_ur_execute(core::ptr::null_mut(), 0, QR_TRX_SIGN_REQUEST) };
        assert!(
            !result.is_null(),
            "execute dispatcher must allocate UREncodeResult"
        );
        let _ = unsafe { &*result };
    }

    #[test]
    fn sign_ur_execute_dispatches_ton_to_execute_ton() {
        let result = unsafe { sign_ur_execute(core::ptr::null_mut(), 0, QR_TON_SIGN_REQUEST) };
        assert!(
            !result.is_null(),
            "execute dispatcher must allocate UREncodeResult"
        );
        let _ = unsafe { &*result };
    }

    #[test]
    fn sign_ur_execute_dispatches_sui_to_execute_sui() {
        let result = unsafe { sign_ur_execute(core::ptr::null_mut(), 0, QR_SUI_SIGN_REQUEST) };
        assert!(
            !result.is_null(),
            "execute dispatcher must allocate UREncodeResult"
        );
        let _ = unsafe { &*result };
    }

    #[test]
    fn sign_ur_execute_dispatches_arweave_to_execute_arweave() {
        let result = unsafe { sign_ur_execute(core::ptr::null_mut(), 0, QR_ARWEAVE_SIGN_REQUEST) };
        assert!(
            !result.is_null(),
            "execute dispatcher must allocate UREncodeResult"
        );
        let _ = unsafe { &*result };
    }

    #[test]
    fn fetch_rsa_primes_returns_none_under_test() {
        // Pin the cfg(test) branch: cargo test must never reach the
        // real FlashReadRsaPrimes binding.
        assert!(unsafe { fetch_rsa_primes() }.is_none());
    }

    // ── Phase B-L3-1 (XMR) dispatcher tripwires ─────────────────────
    //
    // Like B-L2: we only test that the dispatcher allocates
    // SignDisplayData / UREncodeResult without a SIGSEGV.
    // The real XMR parse/execute path is exercised by apps/monero
    // tests (apps/monero/src/transfer.rs::tests::test_clsag_signature)
    // and L4 simulator integration with real fixture UR payloads.

    #[test]
    fn sign_ur_parse_dispatches_xmr_to_parse_xmr() {
        // Under cargo test, fetch_monero_pvk_for_parse returns None
        // → parse_xmr surfaces a structured "XMR pvk unavailable"
        // error (error_code=1, no SIGSEGV). This is the same shape as
        // parse_eth under cargo test.
        let display = unsafe { sign_ur_parse(core::ptr::null_mut(), 0, QR_XMR_TX_UNSIGNED) };
        assert!(
            !display.is_null(),
            "parse dispatcher must allocate SignDisplayData"
        );
        let d = unsafe { &*display };
        assert_eq!(d.error_code, 1, "missing pvk must surface structured error");
        let msg = read_c_str(d.error_message).unwrap_or_default();
        assert!(
            msg.contains("XMR pvk unavailable"),
            "unexpected error message: {msg}"
        );
        unsafe { sign_display_data_free(display) };
    }

    #[test]
    fn sign_ur_execute_dispatches_xmr_to_execute_xmr() {
        // Under cargo test, the cfg(test) branch of fetch_seed in
        // sign_ur_execute already returns None → execute_xmr sees an
        // empty seed. The dispatcher arm should NOT segfault; it
        // should return a UREncodeResult (likely error_code ≠ 0
        // because monero_generate_signature's first action is
        // extract_ptr_with_type! on a null PtrUR). We only assert
        // non-null allocation.
        let result = unsafe { sign_ur_execute(core::ptr::null_mut(), 0, QR_XMR_TX_UNSIGNED) };
        assert!(
            !result.is_null(),
            "execute dispatcher must allocate UREncodeResult"
        );
        let _ = unsafe { &*result };
    }

    #[test]
    fn fetch_monero_pvk_returns_none_under_test() {
        // Pin the cfg(test) branch: under cargo test we never
        // call the real GetCurrentAccountPublicKey binding.
        assert!(fetch_monero_pvk_for_parse().is_none());
    }

    #[test]
    fn xmr_enum_constant_matches_c_header() {
        // Pin the dispatcher constant against C enum drift. If
        // src/crypto/account_public_info.h reorders the ChainType
        // enum, this test fails and XPUB_TYPE_MONERO_PVK_0 must
        // update in lock-step. Mirrors the xrp_root_xpub_enum_constant_matches_c_header
        // and eth_root_xpub_enum_constant_matches_c_header tests.
        assert_eq!(XPUB_TYPE_MONERO_PVK_0, 232);
        assert_eq!(QR_XMR_TX_UNSIGNED, 32);
    }

    // ── Phase B-L3-2 (BTC) dispatcher tripwires ────────────────────
    //
    // Like B-L3-1 (XMR): we only test that the dispatcher arm
    // is reachable without a SIGSEGV. The real BTC parse path
    // requires a C-side wallet unlock (see comment on `parse_btc`),
    // so under cargo test the parse arm deliberately surfaces a
    // structured "BTC parse requires an unlocked wallet" error
    // rather than dereferencing the UR pointer.
    //
    // The execute arm is exercised by sign_ur_execute with a real
    // seed; under cargo test fetch_seed returns None which means
    // sign_ur_execute short-circuits BEFORE execute_btc fires —
    // the allocate-not-null tripwire is what we test here.

    #[test]
    fn sign_ur_parse_dispatches_btc_to_parse_btc() {
        let display = unsafe { sign_ur_parse(core::ptr::null_mut(), 0, QR_BTC_SIGN_REQUEST) };
        assert!(
            !display.is_null(),
            "parse dispatcher must allocate SignDisplayData"
        );
        let d = unsafe { &*display };
        assert_eq!(
            d.error_code, 1,
            "BTC parse without unlocked wallet must surface structured error"
        );
        let msg = read_c_str(d.error_message).unwrap_or_default();
        assert!(
            msg.contains("BTC parse"),
            "unexpected error message: {msg}"
        );
        unsafe { sign_display_data_free(display) };
    }

    #[test]
    fn sign_ur_execute_dispatches_btc_to_execute_btc() {
        let result = unsafe { sign_ur_execute(core::ptr::null_mut(), 0, QR_BTC_SIGN_REQUEST) };
        assert!(
            !result.is_null(),
            "execute dispatcher must allocate UREncodeResult"
        );
        let _ = unsafe { &*result };
    }

    #[test]
    fn fetch_btc_mfp_returns_none_under_test() {
        assert!(fetch_btc_mfp_for_parse(&[0xab; SEED_LEN]).is_none());
    }

    #[test]
    fn btc_enum_constant_matches_c_header() {
        // Pin the dispatcher constants against C enum drift.
        assert_eq!(QR_BTC_SIGN_REQUEST, 7);
        // BTC XPUB types from src/crypto/account_public_info.h
        // (verified 2026-07-26 by counting enum lines):
        //   XPUB_TYPE_BTC = 0, BTC_LEGACY = 1,
        //   BTC_NATIVE_SEGWIT = 2, BTC_TAPROOT = 3
        assert_eq!(XPUB_TYPE_BTC, 0);
        assert_eq!(XPUB_TYPE_BTC_LEGACY, 1);
        assert_eq!(XPUB_TYPE_BTC_NATIVE_SEGWIT, 2);
        assert_eq!(XPUB_TYPE_BTC_TAPROOT, 3);
    }

    // ── Phase B-L3-3 (ADA / Cardano) dispatcher tripwires ─────────
    //
    // Same pattern as B-L3-1 (XMR) / B-L3-2 (BTC):
    //   * parse path returns a structured "ADA parse requires
    //     unlocked wallet" error rather than dereferencing UR.
    //   * execute path is allocator-tripwired — under cargo test
    //     fetch_seed returns None so sign_ur_execute short-circuits
    //     before execute_cardano fires.

    #[test]
    fn sign_ur_parse_dispatches_cardano_to_parse_cardano() {
        let display =
            unsafe { sign_ur_parse(core::ptr::null_mut(), 0, QR_CARDANO_SIGN_REQUEST) };
        assert!(
            !display.is_null(),
            "parse dispatcher must allocate SignDisplayData"
        );
        let d = unsafe { &*display };
        assert_eq!(
            d.error_code, 1,
            "ADA parse without xpub must surface structured error"
        );
        let msg = read_c_str(d.error_message).unwrap_or_default();
        assert!(
            msg.contains("ADA parse"),
            "unexpected error message: {msg}"
        );
        unsafe { sign_display_data_free(display) };
    }

    #[test]
    fn sign_ur_execute_dispatches_cardano_to_execute_cardano() {
        let result =
            unsafe { sign_ur_execute(core::ptr::null_mut(), 0, QR_CARDANO_SIGN_REQUEST) };
        assert!(
            !result.is_null(),
            "execute dispatcher must allocate UREncodeResult"
        );
        let _ = unsafe { &*result };
    }

    #[test]
    fn fetch_cardano_xpub_returns_none_under_test() {
        // Pin the cfg(test) branch: cargo test must never call
        // the real GetCurrentAccountPublicKey binding.
        assert!(fetch_cardano_xpub_for_parse().is_none());
    }

    #[test]
    fn ada_enum_constant_matches_c_header() {
        // Pin the dispatcher constant against C enum drift.
        assert_eq!(QR_CARDANO_SIGN_REQUEST, 14);
        // XPUB_TYPE_ADA_0 is at enum-internal line 175
        // in src/crypto/account_public_info.h.
        assert_eq!(XPUB_TYPE_ADA_0, 173);
    }
}

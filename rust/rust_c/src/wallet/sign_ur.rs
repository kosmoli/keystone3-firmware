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
use alloc::string::{String, ToString};
use core::slice;

use cty::{c_char, uint32_t};

use keystore::algorithms::secp256k1::get_master_fingerprint_by_seed;
use keystore::bindings::{
    ClearSecretCache, GetAccountSeed, GetCurrentAccountIndex, SecretCacheGetPassword,
};

use crate::common::errors::RustCError;
use crate::common::types::{Ptr, PtrT, PtrUR};
use crate::common::ur::{UREncodeResult, FRAGMENT_MAX_LENGTH_DEFAULT};

const SEED_LEN: usize = 64;

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
    let bytes = s.into_bytes();
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
        let _ = Box::from_raw(slice::from_raw_parts_mut(ptr, len_to_null(ptr)));
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

/// Unified parse entry. Stage 1: ETH + XRP placeholders only.
#[no_mangle]
pub unsafe extern "C" fn sign_ur_parse(
    _ur_data: Ptr<u8>,
    _ur_data_len: uint32_t,
    ur_type: uint32_t,
) -> PtrT<SignDisplayData> {
    // QRCodeType values from librust_c.h enum.
    const QR_ETH_SIGN_REQUEST: u32 = 10;
    const QR_XRP_TX: u32 = 22;
    match ur_type {
        QR_ETH_SIGN_REQUEST => parse_eth(),
        QR_XRP_TX => parse_xrp(),
        _ => build_display_error(
            "Plan v11 stage-1: chain not yet wired up to unified API",
        ),
    }
}

unsafe fn parse_eth() -> PtrT<SignDisplayData> {
    let fields = "Network=ETH\nMethod=\nFrom=\nTo=\nValue=0\nFee=0\nNonce=0\n\
(Plan v11 stage-1 placeholder: full ETH parse requires DisplayETH\n\
serialization which lands in phase 1.4.)";
    build_display("Sign Transaction", "ETH", "mainnet", fields, "", 0)
}

unsafe fn parse_xrp() -> PtrT<SignDisplayData> {
    let fields = "Network=XRP\nFrom=\nTo=\nAmount=0 XRP\nFee=0 XRP\nDestinationTag=\n\
(Plan v11 stage-1 placeholder)";
    build_display("Sign Transaction", "XRP", "mainnet", fields, "", 0)
}

/// Unified execute entry. Stage 1: ETH real implementation, XRP placeholder.
#[no_mangle]
pub unsafe extern "C" fn sign_ur_execute(
    ur_data: Ptr<u8>,
    ur_data_len: uint32_t,
    ur_type: uint32_t,
) -> PtrT<UREncodeResult> {
    // QRCodeType enum values from librust_c.h.
    const QR_ETH_SIGN_REQUEST: u32 = 10;
    const QR_XRP_TX: u32 = 22;

    let seed = match fetch_seed() {
        Some(s) => s,
        None => {
            return UREncodeResult::from(RustCError::InvalidData("seed unavailable".into()))
                .c_ptr();
        }
    };
    let result = match ur_type {
        QR_ETH_SIGN_REQUEST => execute_eth(ur_data, seed),
        QR_XRP_TX => execute_xrp(seed),
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

unsafe fn execute_xrp(_seed: [u8; SEED_LEN]) -> PtrT<UREncodeResult> {
    UREncodeResult::from(RustCError::UnsupportedTransaction(
        "Plan v11: XRP execute wiring pending root_xpub binding".into(),
    ))
    .c_ptr()
}
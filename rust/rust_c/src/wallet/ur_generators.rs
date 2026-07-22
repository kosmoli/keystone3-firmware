// KOSMO Plan v10: 通用 UR 生成 API
// 后端只关心 UR 类型，不关心钱包名。钱包→UR 类型映射由前端负责。

use core::slice;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;

use bitcoin::bip32::{DerivationPath, Fingerprint};
use core::str::FromStr;
use cty::uint32_t;

use ur_registry::bytes::Bytes;
use ur_registry::crypto_hd_key::CryptoHDKey;
use ur_registry::crypto_key_path::CryptoKeyPath;
use ur_registry::error::URError;
use ur_registry::traits::RegistryItem;
use ed25519_bip32_core::XPub;

use crate::common::types::{Ptr, PtrBytes, PtrString};
use crate::common::ur::{UREncodeResult, FRAGMENT_MAX_LENGTH_DEFAULT};
use crate::common::utils::recover_c_char;
use crate::extract_array;

// ─── 辅助：密钥类型检测 + CryptoHDKey 构造 ─────────────────────

/// 根据密钥字节自动检测类型（ed25519 / secp256k1 xpub / bip32-ed25519）
/// 返回 None 表示无法识别
fn try_construct_crypto_hd_key(
    mfp: [u8; 4],
    path: &str,
    key_hex: &str,
    name: Option<&str>,
) -> Result<CryptoHDKey, URError> {
    let key_path = CryptoKeyPath::from_path(path.to_string(), Some(mfp))
        .map_err(|e| URError::UrEncodeError(e))?;

    let key_bytes = hex::decode(key_hex)
        .map_err(|e| URError::UrEncodeError(e.to_string()))?;

    if key_bytes.len() >= 78 {
        // secp256k1 xpub (BIP32 extended key)
        let xpub = bitcoin::bip32::Xpub::decode(&key_bytes)
            .map_err(|e| URError::UrEncodeError(e.to_string()))?;
        Ok(CryptoHDKey::new_extended_key(
            None,
            xpub.public_key.serialize().to_vec(),
            Some(xpub.chain_code.as_bytes().to_vec()),
            None,
            Some(key_path),
            None,
            Some(xpub.parent_fingerprint.to_bytes()),
            name.map(|s| s.to_string()),
            None,
        ))
    } else if key_bytes.len() == 32 {
        // ed25519 public key (32 bytes)
        Ok(CryptoHDKey::new_extended_key(
            None,
            key_bytes,
            None,
            None,
            Some(key_path),
            None,
            None,
            name.map(|s| s.to_string()),
            None,
        ))
    } else {
        // Try bip32-ed25519 XPub
        let xpub = ed25519_bip32_core::XPub::from_slice(&key_bytes)
            .map_err(|e| URError::UrEncodeError(e.to_string()))?;
        Ok(CryptoHDKey::new_extended_key(
            None,
            xpub.public_key().to_vec(),
            Some(xpub.chain_code().to_vec()),
            None,
            Some(key_path),
            None,
            None,
            name.map(|s| s.to_string()),
            None,
        ))
    }
}

// ─── FFI API：ur:crypto-hd-key (单 HD 密钥) ──────────────────────

/// 生成 ur:crypto-hd-key QR 码
/// 用于：ETH (MetaMask 标准模式)、ADA、TON (Tonkeeper)
#[no_mangle]
pub unsafe extern "C" fn generate_ur_crypto_hd_key(
    master_fingerprint: PtrBytes,
    master_fingerprint_length: u32,
    key_hex: PtrString,      // xpub 或 ed25519 公钥（hex）
    path: PtrString,         // 派生路径，如 "m/44'/60'/0'"
    key_name: PtrString,     // 密钥名（可选，null 表示无名称）
) -> Ptr<UREncodeResult> {
    if master_fingerprint_length != 4 {
        return UREncodeResult::from(URError::UrEncodeError(
            alloc::format!("master fingerprint length must be 4, current is {master_fingerprint_length}")
        )).c_ptr();
    }

    let mfp = extract_array!(master_fingerprint, u8, master_fingerprint_length);
    let mfp = match <[u8; 4]>::try_from(mfp) {
        Ok(mfp) => mfp,
        Err(e) => return UREncodeResult::from(URError::UrEncodeError(e.to_string())).c_ptr(),
    };

    let key_hex = recover_c_char(key_hex);
    let path = recover_c_char(path);
    let key_name = recover_c_char(key_name);
    let name = if key_name.is_empty() { None } else { Some(key_name.as_str()) };

    let hd_key = match try_construct_crypto_hd_key(mfp, &path, &key_hex, name) {
        Ok(key) => key,
        Err(e) => return UREncodeResult::from(e).c_ptr(),
    };

    match hd_key.try_into() {
        Ok(data) => UREncodeResult::encode(
            data,
            CryptoHDKey::get_registry_type().get_type(),
            FRAGMENT_MAX_LENGTH_DEFAULT,
        ).c_ptr(),
        Err(e) => UREncodeResult::from(e).c_ptr(),
    }
}

// ─── FFI API：ur:bytes (原始字节) ────────────────────────────────

/// 生成 ur:bytes QR 码
/// 用于：XRP (XRP Toolkit)
/// data: 原始 CBOR 字节 (hex)
#[no_mangle]
pub unsafe extern "C" fn generate_ur_bytes(
    data_hex: PtrString,
) -> Ptr<UREncodeResult> {
    let data_hex = recover_c_char(data_hex);
    let data = match hex::decode(&data_hex) {
        Ok(d) => d,
        Err(e) => return UREncodeResult::from(URError::UrEncodeError(e.to_string())).c_ptr(),
    };

    UREncodeResult::encode(
        data,
        Bytes::get_registry_type().get_type(),
        FRAGMENT_MAX_LENGTH_DEFAULT,
    ).c_ptr()
}

// ─── FFI API：ur:arweave-crypto-account (AR RSA 密钥) ────────────

/// 生成 ur:arweave-crypto-account QR 码
/// 用于：AR (Wander, Beacon)
/// xpub_hex: RSA 公钥 (hex)
#[no_mangle]
pub unsafe extern "C" fn generate_ur_arweave_account(
    master_fingerprint: PtrBytes,
    master_fingerprint_length: u32,
    xpub_hex: PtrString,
) -> Ptr<UREncodeResult> {
    let mfp = extract_array!(master_fingerprint, u8, master_fingerprint_length);
    let mfp = match <[u8; 4]>::try_from(mfp) {
        Ok(mfp) => mfp,
        Err(e) => return UREncodeResult::from(URError::UrEncodeError(e.to_string())).c_ptr(),
    };

    let xpub_hex = recover_c_char(xpub_hex);
    let pubkey = match hex::decode(&xpub_hex) {
        Ok(k) => k,
        Err(e) => return UREncodeResult::from(URError::UrEncodeError(e.to_string())).c_ptr(),
    };

    let account = ur_registry::arweave::arweave_crypto_account::ArweaveCryptoAccount::new(
        mfp,
        pubkey,
        None,  // device
    );

    match account.try_into() {
        Ok(data) => UREncodeResult::encode(
            data,
            ur_registry::arweave::arweave_crypto_account::ArweaveCryptoAccount::get_registry_type().get_type(),
            FRAGMENT_MAX_LENGTH_DEFAULT,
        ).c_ptr(),
        Err(e) => UREncodeResult::from(e).c_ptr(),
    }
}

// ─── FFI API：ur:zcash-accounts (Zcash UFVK) ────────────────────

/// 生成 ur:zcash-accounts QR 码
/// 用于：ZEC (ZODL, Vizor)
/// ufvk: Unified Full Viewing Key 字符串
/// key_name: 密钥名（可选）
/// key_index: 账户索引
#[no_mangle]
pub unsafe extern "C" fn generate_ur_zcash_accounts(
    seed_fingerprint: PtrBytes,
    seed_fingerprint_length: u32,
    ufvk: PtrString,
    key_name: PtrString,
    key_index: u32,
) -> Ptr<UREncodeResult> {
    if seed_fingerprint_length != 32 {
        return UREncodeResult::from(URError::UrEncodeError(
            alloc::format!("ZIP-32 seed fingerprint length must be 32, current is {seed_fingerprint_length}")
        )).c_ptr();
    }

    let sfp = extract_array!(seed_fingerprint, u8, seed_fingerprint_length);
    let sfp = match <[u8; 32]>::try_from(sfp) {
        Ok(sfp) => sfp,
        Err(e) => return UREncodeResult::from(URError::UrEncodeError(e.to_string())).c_ptr(),
    };

    let ufvk = recover_c_char(ufvk);
    let key_name = recover_c_char(key_name);

    let ufvk_info = app_wallets::zcash::UFVKInfo::new(
        ufvk,
        key_name,
        key_index,
    );

    let result = app_wallets::zcash::generate_sync_ur(vec![ufvk_info], sfp);
    match result.map(|v| v.try_into()) {
        Ok(v) => match v {
            Ok(data) => UREncodeResult::encode(
                data,
                ur_registry::zcash::zcash_accounts::ZcashAccounts::get_registry_type().get_type(),
                FRAGMENT_MAX_LENGTH_DEFAULT,
            ).c_ptr(),
            Err(e) => UREncodeResult::from(e).c_ptr(),
        },
        Err(e) => UREncodeResult::from(e).c_ptr(),
    }
}

// ─── FFI API：XMR JSON 文本 ─────────────────────────────────────

/// 生成 Monero Feather Wallet 兼容的 JSON QR 码
/// 用于：XMR (Feather Wallet)
#[no_mangle]
pub unsafe extern "C" fn generate_ur_xmr_json(
    pub_spend_key: PtrString,
    private_view_key: PtrString,
) -> Ptr<UREncodeResult> {
    let spend_key = recover_c_char(pub_spend_key);
    let pvk = recover_c_char(private_view_key);

    let pvk_bytes = match hex::decode(&pvk) {
        Ok(b) => b,
        Err(e) => return UREncodeResult::from(URError::UrEncodeError(e.to_string())).c_ptr(),
    };

    let public_key = match app_monero::key::PublicKey::from_str(spend_key.as_str()) {
        Ok(k) => k,
        Err(e) => return UREncodeResult::from(URError::UrEncodeError(
            alloc::format!("Invalid spend key: {}", e)
        )).c_ptr(),
    };

    let view_key = app_monero::key::PrivateKey::from_bytes(&pvk_bytes);
    let primary_address = app_monero::address::Address::new(
        app_monero::structs::Network::Mainnet,
        app_monero::structs::AddressType::Standard,
        public_key,
        view_key.get_public_key(),
    );

    let json_obj = serde_json::json!({
        "version": 0,
        "primaryAddress": primary_address.to_string(),
        "privateViewKey": hex::encode(&pvk_bytes),
        "restoreHeight": 0,
        "encrypted": false,
        "source": "Keystone"
    });

    UREncodeResult::text(json_obj.to_string()).c_ptr()
}

//! Plan v11 §8.6 follow-up: XMR L4 real-value test fixture builder.
//!
//! ## Goal
//!
//! Produce a `XmrTxUnsigned.payload` byte blob that keystone fork
//! dispatcher `sign_ur_execute(_, _, QR_XMR_TX_UNSIGNED)` can consume
//! end-to-end through `app_monero::transfer::sign_tx`. The dispatcher
//! pipeline is:
//!     1. Decode the UR (CBOR) → `XmrTxUnsigned { payload: Vec<u8> }`
//!     2. Pass the payload to `monero_generate_signature`
//!     3. Internally: `decrypt_data_with_pvk(view, payload, UNSIGNED_TX_PREFIX)`
//!     4. → `UnsignedTx::deserialize(decrypted.data)` (keystone fork type)
//!     5. → `unsigned_tx.sign(keypair)` (calls monero-oxide)
//!     6. → `encrypt_data_with_pvk(view, signed, SIGNED_TX_PREFIX)`
//!
//! This binary constructs the **encrypted wire format** (steps 3-4
//! input) and emits the CBOR-wrapped form (step 1-2 input) so that
//! a sign_ur_dispatcher test can feed it back into the dispatcher.
//!
//! ## Limitation
//!
//! Without a running monero-wallet-rpc we cannot construct a real
//! monero-oxide `SignableTransaction` (its inputs are constructed only
//! via the wallet::scan API which needs `ProvidesDecoys`). For the L4
//! fixture we accept that the unsigned tx bytes that go inside the
//! encrypted blob are **structurally empty** (1 `TxConstructionData`
//! with zero sources). sign() will fail inside the dispatcher; the
//! fixture is therefore a **dispatcher-arm-routing** test, not a
//! real-on-chain-signing test. The fully-real fixture is a plan-v12
//! follow-up that requires monero-wallet-rpc integration.
//!
//! ## Inputs
//!
//! Reads a single env var `XMR_MNEMONIC` containing the user's
//! 25-word Polyseed. Emits the CBOR hex of `XmrTxUnsigned` to stdout.

extern crate alloc;

use alloc::vec::Vec;

use rand_core::OsRng;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use app_monero::key::generate_keypair;
use app_monero::utils::constants::UNSIGNED_TX_PREFIX;
use app_monero::utils::encrypt_data_with_pvk;

/// Fixed inner `UnsignedTx` blob (keystone fork's `transfer::UnsignedTx`
/// wire format). The format, per `app_monero::transfer::deserialize`:
///
///     version (varint) | txes_len (varint) | txes...
///     [for each tx]: sources_len | ... | change_dts | splitted_dsts_len | ...
///     [for each source]: outputs_len | [for each output]: 0x02 | index | dest | mask
///     splitted_dsts (each: varint addr_len | addr_bytes | amount_le_u64)
///     + a single `VarInt` exported_transfer_details + raw_data
///
/// The keystone `sign_tx` function reads this format and feeds it
/// into monero-oxide's `SignableTransaction` reconstruction. The
/// fixture below puts a syntactically-valid but semantically-empty
/// 1-tx, 0-source structure; `sign()` will reject zero-input txs but
/// the dispatcher arm-routing path is fully exercised.
const INNER_UNSIGNED_TX_BLOB: &[u8] = &[
    // version
    0x02,
    // txes_len = 1
    0x01,
    // === tx[0] ===
    // sources_len = 0
    0x00,
    // change_dts: varint_addr_len(0) | 0 bytes addr | amount(0)
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // splitted_dsts_len = 0
    0x00,
    // selected_transfers_len = 0
    0x00,
    // extra_len = 0
    0x00,
    // unlock_time = 0
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // use_rct = 0
    0x00,
    // rct_config: (priority u8, bulletproof u8, clsag u8, budget u8)
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // dests_len = 0
    0x00,
    // subaddr_account u32
    0x00, 0x00, 0x00, 0x00,
    // subaddr_indices_len = 0
    0x00,
];

fn main() {
    let mnemonic_phrase = match std::env::var("XMR_MNEMONIC") {
        Ok(s) if !s.is_empty() => s,
        _ => {
            eprintln!(
                "XMR unsigned-tx fixture builder\n\n\
                 usage: XMR_MNEMONIC=\"...25 words...\" gen_xmr_unsigned_tx > /tmp/u.hex\n\n\
                 emits the CBOR-encoded XmrTxUnsigned payload hex to stdout."
            );
            std::process::exit(2);
        }
    };

    let seed = sha256_of_phrase(&mnemonic_phrase);
    let keypair = match generate_keypair(&*seed, 0) {
        Ok(kp) => kp,
        Err(e) => {
            eprintln!("failed to derive Monero keypair from seed: {e}");
            std::process::exit(1);
        }
    };

    // The wire format for `encrypt_data_with_pvk` is
    //     [magic | nonce(8) | ciphertext(chacha20-encrypted) | signature(64)]
    // where ciphertext is the chacha20 encryption of
    //     [for some MAGICS: pk_spend + pk_view] + data.
    // For UNSIGNED_TX_PREFIX the ciphertext is just `data` (no
    // pk_spend/pk_view prefix per the encrypt impl).
    let outer_blob = encrypt_data_with_pvk(
        keypair,
        INNER_UNSIGNED_TX_BLOB.to_vec(),
        UNSIGNED_TX_PREFIX,
        OsRng,
    );

    // The XmrTxUnsigned ur-registry type wraps its payload as a
    // top-level CBOR byte string (see ur-registry's Encode impl —
    // which is intentionally a no-op — and Decode impl which reads
    // `Type::Bytes`). The fixture used by the upstream test is
    // `590002aaff` which is 0x59 (byte string, 2-byte BE length
    // follows) | 0x0002 (length 2) | 0xaaff. We mirror that format
    // here.
    let mut cbor_bytes: Vec<u8> = Vec::new();
    cbor_bytes.push(0x59); // CBOR major type 2, length in 2 bytes
    let len = outer_blob.len() as u16;
    cbor_bytes.extend_from_slice(&len.to_be_bytes());
    cbor_bytes.extend_from_slice(&outer_blob);
    let cbor_hex = hex::encode(&cbor_bytes);

    eprintln!("inner_len = {}", INNER_UNSIGNED_TX_BLOB.len());
    eprintln!("outer_len = {}", cbor_hex.len() / 2);
    eprintln!("cbor_len  = {}", cbor_bytes.len());
    std::io::Write::write_all(&mut std::io::stdout(), cbor_hex.as_bytes())
        .expect("write stdout");
}

fn sha256_of_phrase(phrase: &str) -> Zeroizing<[u8; 32]> {
    let mut h = Sha256::new();
    h.update(phrase.as_bytes());
    let out = h.finalize();
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&out);
    Zeroizing::new(bytes)
}

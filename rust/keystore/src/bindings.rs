#[allow(dead_code)]
extern "C" {
    pub fn GetAccountSeed(account_index: u8, seed: *mut u8, password: *const cty::c_char) -> i32;
    pub fn GetAccountEntropy(
        account_index: u8,
        entropy: *mut u8,
        entropy_len: *mut u8,
        password: *const cty::c_char,
    ) -> i32;

    // Plan v11: needed by sign_ur.rs to obtain the current signing context
    // (account index, cached password, cleared-on-use seed cache).
    pub fn GetCurrentAccountIndex() -> u8;
    pub fn GetMnemonicType() -> u32; // returns MnemonicType (BIP39/SLIP39/TON)
    pub fn SecretCacheGetPassword() -> *const cty::c_char;
    pub fn ClearSecretCache();

    // Plan v11 stage-A.3: needed by sign_ur::execute_xrp to fetch the
    // root xpub that xrp_sign_tx_bytes requires. `chain_type` accepts
    // the ChainType enum from src/crypto/account_public_info.h
    // (XPUB_TYPE_XRP = 29 at the time of writing; verify against the
    // generated header if the enum drifts).
    //
    // Returns a heap-allocated C string the caller owns and must free,
    // or NULL if the chain has no xpub cached.
    pub fn GetCurrentAccountPublicKey(chain_type: u32) -> *mut cty::c_char;

    // Plan v11 stage-B-L2 (AR): sign_ur.rs::fetch_rsa_primes calls
    // this to obtain the RSA-2048 prime factors used to sign Arweave
    // transactions and messages. The pointer is heap-allocated by
    // src/crypto/rsa.c::FlashReadRsaPrimes via SRAM_MALLOC — the
    // caller (Rust side) must zeroize and free it through the matching
    // FreeRsaPrimes entry point below.
    //
    // Returns NULL if the RSA primes slot is empty or the underlying
    // decryption fails.
    pub fn FlashReadRsaPrimes() -> *mut core::ffi::c_void;

    // Companion to FlashReadRsaPrimes. Rust caller invokes this with
    // the pointer returned by FlashReadRsaPrimes to zeroize the
    // buffer (m fp, q are AES-derived session secrets) and free the
    // SRAM_MALLOC allocation. Mirrors the memset_s + SRAM_FREE
    // sequence in src/api/kosmo_api.c::ModelSignArCommon.
    pub fn FreeRsaPrimes(primes: *mut core::ffi::c_void);
}

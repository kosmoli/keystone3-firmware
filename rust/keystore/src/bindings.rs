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
}

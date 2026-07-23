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
}

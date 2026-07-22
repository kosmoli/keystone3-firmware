// Plan v10: Wallet-specific UR generation moved to ur_generators.rs
// These stubs are kept for link compatibility only.
// All new code should use generate_ur_* functions from rust/rust_c/src/wallet/ur_generators.rs

#include "gui_wallet.h"
#include "librust_c.h"
#include "secret_cache.h"
#include "account_public_info.h"
#include "user_memory.h"
#include "gui_chain.h"
#include "kosmo_api.h"
#include "rsa.h"
#include "keystore.h"
#include <string.h>
#include <stdio.h>

// Utility helpers (kept for chain signing code)

// Plan v10 stubs
UREncodeResult *GuiGetStandardBtcData(void) { return NULL; }
UREncodeResult *GuiGetMetamaskData(void) { return NULL; }
UREncodeResult *GetMetamaskDataForAccountType(ETHAccountType accountType) { (void)accountType; return NULL; }
UREncodeResult *GetUnlimitedMetamaskDataForAccountType(ETHAccountType accountType) { (void)accountType; return NULL; }

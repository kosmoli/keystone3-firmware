#ifndef GUI_WALLET_H
#define GUI_WALLET_H

#include "rust.h"
#include "gui_chain.h"
#include "rsa.h"
#include "gui_attention_hintbox.h"

// Plan v10: wallet-specific UR generation moved to ur_generators.rs
// These stubs are kept for USB export_address compatibility only.
// All new code should use generate_ur_* functions directly.

UREncodeResult *GuiGetStandardBtcData(void);
UREncodeResult *GuiGetMetamaskData(void);
UREncodeResult *GetMetamaskDataForAccountType(ETHAccountType accountType);
UREncodeResult *GetUnlimitedMetamaskDataForAccountType(ETHAccountType accountType);

#endif
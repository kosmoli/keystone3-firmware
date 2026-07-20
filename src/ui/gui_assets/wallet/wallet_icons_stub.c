/*
 * wallet_icons_stub.c — Stub definitions for wallet icons
 *
 * These wallet icon assets were removed during Phase 5 cleanup (Connect Wallet
 * feature removal). This file provides 1x1 transparent stub images so that
 * existing references in gui_status_bar.c and gui_resource.h link successfully.
 * Replace with real assets if wallet display is ever needed again.
 */

#if defined(LV_LVGL_H_INCLUDE_SIMPLE)
#include "lvgl.h"
#else
#include "../lvgl/lvgl.h"
#endif

#ifndef LV_ATTRIBUTE_MEM_ALIGN
#define LV_ATTRIBUTE_MEM_ALIGN
#endif

/* 1x1 transparent pixel data (ARGB8888) */
static const LV_ATTRIBUTE_MEM_ALIGN uint8_t wallet_stub_map[] = {
    0x00, 0x00, 0x00, 0x00
};

#define WALLET_STUB_IMG(name)                                   \
    const LV_ATTRIBUTE_MEM_ALIGN uint8_t name##_map[] = {       \
        0x00, 0x00, 0x00, 0x00                                  \
    };                                                          \
    const lv_img_dsc_t name = {                                 \
        .header.always_zero = 0,                                \
        .header.w = 1,                                          \
        .header.h = 1,                                          \
        .data_size = 1 * LV_IMG_PX_SIZE_ALPHA_BYTE,             \
        .header.cf = LV_IMG_CF_TRUE_COLOR_ALPHA,                \
        .data = name##_map,                                     \
    }

WALLET_STUB_IMG(walletKeystone);
WALLET_STUB_IMG(walletMetamask);
WALLET_STUB_IMG(walletOkx);
WALLET_STUB_IMG(walletEternl);
WALLET_STUB_IMG(walletMedusa);
WALLET_STUB_IMG(walletGero);
WALLET_STUB_IMG(walletTyphon);
WALLET_STUB_IMG(walletSubwallet);
WALLET_STUB_IMG(walletZodl);
WALLET_STUB_IMG(walletSolflare);
WALLET_STUB_IMG(walletNufi);
WALLET_STUB_IMG(walletBackpack);
WALLET_STUB_IMG(walletRabby);
WALLET_STUB_IMG(walletNabox);
WALLET_STUB_IMG(walletBitget);
WALLET_STUB_IMG(walletSafe);
WALLET_STUB_IMG(walletUniSat);
WALLET_STUB_IMG(walletImToken);
WALLET_STUB_IMG(walletBlockWallet);
WALLET_STUB_IMG(walletZapper);
WALLET_STUB_IMG(walletHelium);
WALLET_STUB_IMG(walletYearn);
WALLET_STUB_IMG(walletSushi);
WALLET_STUB_IMG(walletKeplr);
WALLET_STUB_IMG(walletMintScan);
WALLET_STUB_IMG(walletWander);
WALLET_STUB_IMG(walletBeacon);
WALLET_STUB_IMG(walletVespr);
WALLET_STUB_IMG(walletXBull);
WALLET_STUB_IMG(walletFewcha);
WALLET_STUB_IMG(walletPetra);
WALLET_STUB_IMG(walletXRPToolkit);
WALLET_STUB_IMG(walletThorWallet);
WALLET_STUB_IMG(walletTonkeeper);
WALLET_STUB_IMG(walletBegin);
WALLET_STUB_IMG(walletNightly);
WALLET_STUB_IMG(walletSuiet);
WALLET_STUB_IMG(walletFeather);
WALLET_STUB_IMG(walletCore);
WALLET_STUB_IMG(walletIota);
WALLET_STUB_IMG(walletBluewallet);
WALLET_STUB_IMG(walletSparrow);
WALLET_STUB_IMG(walletZeus);
WALLET_STUB_IMG(walletBull);
WALLET_STUB_IMG(walletVizor);

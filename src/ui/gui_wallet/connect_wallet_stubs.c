/*
 * connect_wallet_stubs.c — Stub implementations for removed Connect Wallet functions
 *
 * Phase 5 cleanup removed the Connect Wallet feature but some source files
 * still reference the deleted symbols. This file provides minimal stubs so
 * the build succeeds. These stubs should never be called in production.
 */

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "kosmo_types.h"
#include "librust_c.h"
#include "gui.h"

/* Stub: returns default (Bip44Standard=0) ETH account type */
ETHAccountType GetMetamaskAccountType(void)
{
    return (ETHAccountType)0;
}

/* Stub: returns default (0) SOL account type */
SOLAccountType GetSolflareAccountType(void)
{
    return (SOLAccountType)0;
}

/* Stub: returns default (0) SOL account type for Helium */
SOLAccountType GetHeliumAccountType(void)
{
    return (SOLAccountType)0;
}

/* Stub: no-op ArConnect wallet setup */
void GuiSetupArConnectWallet(void)
{
    /* no-op — Connect Wallet feature removed */
}

/* Stub: returns 0 for wallet index */
uint8_t GuiConnectWalletGetWalletIndex(void)
{
    return 0;
}

/* Stub: no-op wallet desc change */
void GuiChangeWalletDesc(bool result)
{
    (void)result;
}

/* Stub: returns NULL for wallet name widget */
void *GuiWalletNameWallet(lv_obj_t *parent, uint8_t tile)
{
    (void)parent;
    (void)tile;
    return NULL;
}

/* Stub: no-op wallet name destruct */
void GuiWalletNameWalletDestruct(void)
{
    /* no-op */
}

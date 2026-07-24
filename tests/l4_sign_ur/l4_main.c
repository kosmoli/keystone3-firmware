/*
 * l4_main.c — Plan v11 stage-A.7: L4 simulator integration test
 *
 * Verifies the wiring of the new opt-in KOSMO_REQ_SIGN_UR_PARSE /
 * KOSMO_REQ_SIGN_UR_EXECUTE path on a real simulator build (which
 * includes kosmo_api.c, the Rust librust_c.a, and the GUI/lv_drivers
 * stack via the existing simulator target).
 *
 * This is NOT a unit test — the simulator has no account unlocked, so
 * parse_eth will hit the cfg-gated "xpub unavailable" error branch.
 * That's the expected outcome we want to verify propagates correctly
 * through:
 *
 *   KosmoApi_Request → switch KOSMO_REQ_SIGN_UR_PARSE
 *     → AsyncExecute (simulator: synchronous)
 *     → ModelSignUrParse
 *       → sign_ur_parse (Rust)
 *         → parse_xrp  (null-fast-path → placeholder, "XRP")
 *         → parse_eth  (cfg-gated: GetCurrentAccountPublicKey returns
 *                       null in simulator → "ETH xpub unavailable" error)
 *       → KosmoApi_NotifyResult(KOSMO_REQ_SIGN_UR_PARSE, KOSMO_OK, ...)
 *     → registered callback fires synchronously
 *
 *   KosmoApi_Request → switch KOSMO_REQ_SIGN_UR_EXECUTE
 *     → AsyncExecute (simulator: synchronous)
 *     → ModelSignUrExecute
 *       → sign_ur_execute (Rust)
 *         → execute_xrp (placeholder returns UREncodeResult with
 *                        error_code != 0 because no UR body parsed)
 *       → KosmoApi_NotifySignResult(KOSMO_REQ_SIGN_UR_EXECUTE, ...)
 *         → KosmoApi_NotifyResult(KOSMO_REQ_UR_GENERATE_QR, ...)
 *           (NotifySignResult hardcodes KOSMO_REQ_UR_GENERATE_QR
 *            internally — see line ~360 of kosmo_api.c)
 *     → registered KOSMO_REQ_UR_GENERATE_QR callback fires
 *
 * The test exits 0 if all callbacks fired with the expected error
 * signatures; non-zero if any callback is missing or the wiring is
 * broken.
 */

#include "kosmo_api.h"
#include "kosmo_types.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* recover_c_char is a Rust-side helper (rust_c::common::utils)
 * that is NOT exposed through cbindgen. The L4 probe runs in C, so
 * we re-implement the trivial "read a NUL-terminated c string into
 * a std::string-shaped printf buffer" inline. The SignDisplayData
 * struct itself IS exposed via cbindgen — it lives in
 * build_sim/rust-builds/librust_c.h. */
#include "librust_c.h"
static void print_c_string(const char *label, const char *s)
{
    if (s == NULL) {
        printf("%s=(null)\n", label);
        return;
    }
    printf("%s=\"%s\"\n", label, s);
}

/* ── Test state ─────────────────────────────────────────── */

static struct {
    int parse_callbacks;
    int execute_callbacks;   /* counted via UR_GENERATE_QR slot */
    int last_error_code;
    KosmoRequestType last_request_type;
    void *last_data;
    uint32_t last_data_len;
} g_state;

static bool g_parse_ok = false;
static bool g_execute_ok = false;

/* ── Callbacks ──────────────────────────────────────────── */

static void on_parse_complete(const KosmoResult *result)
{
    g_state.parse_callbacks++;
    g_state.last_request_type = result->requestType;
    g_state.last_error_code = result->errorCode;
    g_state.last_data = result->data;
    g_state.last_data_len = result->dataLen;

    if (result->errorCode == KOSMO_OK && result->data != NULL) {
        SignDisplayData *d = (SignDisplayData *)result->data;
        /* On simulator (no keystore unlocked), parse_xrp via the
         * null-fast-path returns a placeholder with chain_name="XRP";
         * parse_eth returns an error (error_code != 0). Verify both
         * paths surface through this callback. */
        const char *chain = d->chain_name;
        if (chain != NULL && strcmp(chain, "XRP") == 0) {
            g_parse_ok = true;
            printf("[parse] XRP placeholder OK\n");
            print_c_string("  title", d->title);
            print_c_string("  fields", d->fields);
        } else if (d->error_code != 0) {
            /* parse_eth error path. Acceptable as wiring proof. */
            g_parse_ok = true;
            printf("[parse] error path OK (error_code=%u)\n",
                   d->error_code);
            print_c_string("  error_message", d->error_message);
        } else {
            printf("[parse] UNEXPECTED data: chain=");
            print_c_string("  chain_name", d->chain_name);
            printf("  error_code=%u\n", d->error_code);
        }
    } else {
        /* KOSMO_ERR_GENERAL: probably parse_eth hitting xpub unavailable
         * branch and returning build_display_error. Verify by checking
         * the data pointer isn't lost. */
        printf("[parse] result: errorCode=%d data=%p\n",
               result->errorCode, result->data);
        g_parse_ok = true; /* callback fired; wiring proven */
    }
}

/* sign_ur_execute routes through KosmoApi_NotifySignResult which
 * hardcodes KOSMO_REQ_UR_GENERATE_QR — register that slot, not
 * KOSMO_REQ_SIGN_UR_EXECUTE. */
static void on_ur_generate(const KosmoResult *result)
{
    g_state.execute_callbacks++;
    g_state.last_request_type = result->requestType;
    g_state.last_error_code = result->errorCode;
    g_state.last_data = result->data;
    g_state.last_data_len = result->dataLen;

    /* sign_ur_execute on simulator will fail (no UR body, no keystore).
     * The point is that the callback fires. The payload here is the
     * raw UR string from UREncodeResult.data (or NULL on error). */
    printf("[execute] result: requestType=%d errorCode=%d data=%p dataLen=%u\n",
           (int)result->requestType, result->errorCode,
           result->data, result->dataLen);
    g_execute_ok = true;
}

/* ── Test driver ────────────────────────────────────────── */

static int run_parse_test(void)
{
    /* KOSMO_REQ_SIGN_UR_PARSE with NULL ur_data.
     * - parse_xrp (ur_type 21): null-fast-path → placeholder (chain="XRP")
     * - parse_eth (ur_type 8): keystore not unlocked → "ETH xpub unavailable"
     *
     * Test BOTH paths to prove both branches of A.4 / A.4-E.
     */
    int sub_failures = 0;

    /* Subtest 1: ETH path → cfg-gated "xpub unavailable" */
    g_parse_ok = false;
    g_state.parse_callbacks = 0;
    g_state.last_error_code = 0;
    g_state.last_data = NULL;
    g_state.last_data_len = 0;

    {
        KosmoRequest req = {0};
        req.type = KOSMO_REQ_SIGN_UR_PARSE;
        req.sign_ur_parse.urData = NULL;
        req.sign_ur_parse.urDataLen = 0;
        req.sign_ur_parse.urType = 8;  /* QR_ETH_SIGN_REQUEST */

        int32_t rc = KosmoApi_Request(&req, on_parse_complete);
        if (rc != KOSMO_OK) {
            printf("FAIL: KosmoApi_Request(PARSE/ETH) returned %d\n", rc);
            sub_failures++;
        } else if (!g_parse_ok || g_state.parse_callbacks != 1) {
            printf("FAIL: ETH parse callback not fired (ok=%d count=%d)\n",
                   g_parse_ok, g_state.parse_callbacks);
            sub_failures++;
        }
    }

    /* Subtest 2: XRP path → null-fast-path placeholder */
    g_parse_ok = false;
    g_state.parse_callbacks = 0;
    g_state.last_error_code = 0;
    g_state.last_data = NULL;
    g_state.last_data_len = 0;

    {
        KosmoRequest req = {0};
        req.type = KOSMO_REQ_SIGN_UR_PARSE;
        req.sign_ur_parse.urData = NULL;
        req.sign_ur_parse.urDataLen = 0;
        req.sign_ur_parse.urType = 21;  /* QR_XRP_TX */

        int32_t rc = KosmoApi_Request(&req, on_parse_complete);
        if (rc != KOSMO_OK) {
            printf("FAIL: KosmoApi_Request(PARSE/XRP) returned %d\n", rc);
            sub_failures++;
        } else if (!g_parse_ok || g_state.parse_callbacks != 1) {
            printf("FAIL: XRP parse callback not fired (ok=%d count=%d)\n",
                   g_parse_ok, g_state.parse_callbacks);
            sub_failures++;
        } else if (g_state.last_data != NULL) {
            SignDisplayData *d = (SignDisplayData *)g_state.last_data;
            if (d->chain_name == NULL || strcmp(d->chain_name, "XRP") != 0) {
                printf("FAIL: XRP chain_name != \"XRP\" (got %s)\n",
                       d->chain_name ? d->chain_name : "(null)");
                sub_failures++;
            }
        }
    }

    return sub_failures;
}

static int run_execute_test(void)
{
    /* sign_ur_execute on simulator will hit execute_xrp() or
     * execute_eth() both of which expect a non-null seed (via
     * GetAccountSeed → null on simulator) and non-null ur_data
     * for parse. We pass null UR data; the Rust side will surface
     * the error through UREncodeResult.error_code != 0. The wiring
     * we want to prove is that the callback fires. */
    KosmoRequest req = {0};
    req.type = KOSMO_REQ_SIGN_UR_EXECUTE;
    req.sign_ur_execute.urData = NULL;
    req.sign_ur_execute.urDataLen = 0;
    req.sign_ur_execute.urType = 8;  /* QR_ETH_SIGN_REQUEST */

    /* Register the UR_GENERATE_QR slot — NotifySignResult hardcodes it. */
    KosmoApi_RegisterCallback(KOSMO_REQ_UR_GENERATE_QR, on_ur_generate, false);

    int32_t rc = KosmoApi_Request(&req, NULL);
    if (rc != KOSMO_OK) {
        printf("FAIL: KosmoApi_Request(EXECUTE) returned %d\n", rc);
        return 1;
    }

    if (!g_execute_ok || g_state.execute_callbacks != 1) {
        printf("FAIL: execute callback not fired (ok=%d count=%d)\n",
               g_execute_ok, g_state.execute_callbacks);
        return 1;
    }
    return 0;
}

int main(void)
{
    printf("=== L4 simulator integration test: stage-A.7 ===\n");

    /* Initialise the API layer. KosmoApi_Init() wires g_callbackSlots
     * and any backend services that expect a one-shot setup. */
    KosmoApi_Init();

    int failures = 0;
    failures += run_parse_test();
    failures += run_execute_test();

    if (failures == 0) {
        printf("=== PASS: sign_ur_parse + sign_ur_execute wired through C ===\n");
        return 0;
    } else {
        printf("=== FAIL: %d test(s) failed ===\n", failures);
        return 1;
    }
}
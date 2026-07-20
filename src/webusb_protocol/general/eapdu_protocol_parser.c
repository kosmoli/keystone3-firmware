/**
 * Stub implementation of eapdu_protocol_parser.
 *
 * The full USB data-communication protocol was removed in Phase 4.1.
 * Only the type definitions (in the header) and thin stubs for functions
 * that are still called by surviving service code are kept here.
 */

#include "stdio.h"
#include "stdlib.h"
#include "string.h"
#include "eapdu_protocol_parser.h"
#include "user_memory.h"
#include "user_msg.h"
#include "usb_task.h"

/* ---- stub: SendEApduResponse ---- */
void SendEApduResponse(EAPDUResponsePayload_t *payload)
{
    (void)payload;
    printf("[eapdu_stub] SendEApduResponse called (no-op)\n");
}

/* ---- stub: SendEApduResponseError ---- */
void SendEApduResponseError(uint8_t cla, CommandType ins, uint16_t requestID, StatusEnum status, char *error)
{
    (void)cla; (void)ins; (void)requestID; (void)status; (void)error;
    printf("[eapdu_stub] SendEApduResponseError called (no-op): %s\n", error ? error : "null");
}

/* ---- stub: GotoResultPage ---- */
void GotoResultPage(EAPDUResultPage_t *resultPageParams)
{
    (void)resultPageParams;
    printf("[eapdu_stub] GotoResultPage called (no-op)\n");
}

/* ---- stub: EApduProtocolParse ---- */
static void EApduProtocolParse(const uint8_t *frame, uint32_t len)
{
    (void)frame; (void)len;
    printf("[eapdu_stub] EApduProtocolParse called (no-op)\n");
}

/* ---- stub: RegisterSendFunc ---- */
static void RegisterSendFunc(ProtocolSendCallbackFunc_t sendFunc)
{
    (void)sendFunc;
}

/* ---- stub: GetRcvCount / ResetRcvCount ---- */
static uint32_t g_stubRcvCount = 0;

static uint32_t GetRcvCount(void)
{
    return g_stubRcvCount;
}

static void ResetRcvCount(void)
{
    g_stubRcvCount = 0;
}

/* ---- stub: NewEApduProtocolParser ---- */
const struct ProtocolParser *NewEApduProtocolParser()
{
    static const struct ProtocolParser g_eapduParser = {
        .name = EAPDU_PROTOCOL_PARSER_NAME,
        .parse = EApduProtocolParse,
        .registerSendFunc = RegisterSendFunc,
        .getRcvCount = GetRcvCount,
        .resetRcvCount = ResetRcvCount,
    };
    return &g_eapduParser;
}

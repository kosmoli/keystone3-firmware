/**
 * Stub implementation of internal_protocol_parser.
 *
 * The full internal USB protocol was removed in Phase 4.1.
 * Only a no-op parser is kept for the protocol_parse.c dispatcher.
 */

#include "stdio.h"
#include "internal_protocol_parser.h"

static void InternalProtocol_Parse(const uint8_t *data, uint32_t len)
{
    (void)data; (void)len;
    printf("[internal_stub] InternalProtocol_Parse called (no-op)\n");
}

static void RegisterSendFunc(ProtocolSendCallbackFunc_t sendFunc)
{
    (void)sendFunc;
}

static uint32_t GetRcvCount(void)
{
    return 0;
}

static void ResetRcvCount(void)
{
}

const struct ProtocolParser *NewInternalProtocolParser()
{
    static const struct ProtocolParser g_internalParser = {
        .name = INTERNAL_PROTOCOL_PARSER_NAME,
        .parse = InternalProtocol_Parse,
        .registerSendFunc = RegisterSendFunc,
        .getRcvCount = GetRcvCount,
        .resetRcvCount = ResetRcvCount,
    };
    return &g_internalParser;
}

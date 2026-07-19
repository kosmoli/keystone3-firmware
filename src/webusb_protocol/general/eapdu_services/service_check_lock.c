#include "gui.h"
#include "service_check_lock.h"
#include "user_memory.h"
#include "ui_async.h"

void CheckDeviceLockStatusService(EAPDURequestPayload_t *payload)
{
    EAPDUResponsePayload_t *result = (EAPDUResponsePayload_t *)SRAM_MALLOC(sizeof(EAPDUResponsePayload_t));

    cJSON *root = cJSON_CreateObject();
    cJSON_AddBoolToObject(root, "payload", g_ui_lock_screen_is_top);
    char *json_str = cJSON_PrintBuffered(root, BUFFER_SIZE_1024, false);
    cJSON_Delete(root);
    result->data = (uint8_t *)json_str;
    result->dataLen = strlen((char *)result->data);
    result->status = RSP_SUCCESS_CODE;
    result->cla = EAPDU_PROTOCOL_HEADER;
    result->commandType = CMD_CHECK_LOCK_STATUS;
    result->requestID = payload->requestID;

    SendEApduResponse(result);
    EXT_FREE(json_str);
    SRAM_FREE(result);
}
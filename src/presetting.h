#ifndef _PRESETTING_H
#define _PRESETTING_H

#include "stdint.h"
#include "stdbool.h"

#define SERIAL_NUMBER_MAX_LEN               64
#define UPDATE_PUB_KEY_LEN                  64

int32_t GetSerialNumber(char *serialNumber);
int32_t SetSerialNumber(const char *serialNumber);

int32_t GetUpdatePubKey(uint8_t *pubKey);
int32_t SetUpdatePubKey(const uint8_t *pubKey);

bool GetFactoryResult(void);

void PresettingTest(int argc, char *argv[]);

#endif

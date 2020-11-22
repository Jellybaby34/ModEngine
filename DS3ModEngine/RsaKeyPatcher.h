#pragma once
#include "MinHook\include\MinHook.h"

BOOL PatchRSAKey(wchar_t* rsaPubKeyPath, wchar_t* serverIpAddress);
VOID TinyEncryptionAlgorithm(unsigned int *value);
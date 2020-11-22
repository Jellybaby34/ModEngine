#include "RsaKeyPatcher.h"
#include "AOBScanner.h"
#include <stdio.h>
#include <iostream>
#include <fstream>

BOOL PatchRSAKey( wchar_t* rsaPubKeyPath, wchar_t* serverIpAddress) {
	wprintf(L"[Mod Engine] Attempting to encrypt RSA key and IP address\r\n");

	char encryptedDataArray[520] = {};

	// Read the RSA public key from the file
	FILE *rsaPubKeyFile = nullptr;
	_wfopen_s(&rsaPubKeyFile, rsaPubKeyPath, L"rb");
	fseek(rsaPubKeyFile, 0, SEEK_END);
	size_t size = ftell(rsaPubKeyFile);
	rewind(rsaPubKeyFile);

	// Check its length then read it into our buffer which will encrypt later
	if (size != 426) {
		wprintf(L"[Mod Engine] RSA key file was not the expected size and cannot be injected. Patching has been aborted\r\n");
		return FALSE;
	}
	fread_s(encryptedDataArray, 426, 1, size, rsaPubKeyFile);

	// Check the server IP length and write it in the buffer at the offset where DkS3 expects it
	size = wcslen(serverIpAddress);
	if (size > 20 || size < 1) {
		wprintf(L"[Mod Engine] Server IP address was an invalid size and cannot be injected. Patching has been aborted\r\n");
		return FALSE;
	}
	wcsncpy((LPWSTR)&encryptedDataArray[432], serverIpAddress, size + 1);

	// Time to encrypt our blob
	int dataArrayOffset;
	for (int i = 0; i < 65; i++) {
		dataArrayOffset = i * 8;
		TinyEncryptionAlgorithm((unsigned int*)&encryptedDataArray[dataArrayOffset]);
	}

	// AoB scan to find the encrypted RSA key and DNS data
	unsigned short scanBytes[16] = { 0x40, 0x77, 0x0C, 0x21, 0x6D, 0xF0, 0xE3, 0xF0, 0xD1, 0xD5, 0x61, 0x8A, 0xE2, 0x38, 0x6D, 0x0F};
	void* rsaKeyStorage = AOBScanner::GetSingleton()->Scan(scanBytes, 16);
	if (rsaKeyStorage != NULL) {
		memcpy(rsaKeyStorage, encryptedDataArray, 520);
	}
	else {
		wprintf(L"[Mod Engine] Encrypted RSA key storage memory could not be found. Patching has been aborted\r\n");
		return FALSE;
	}

	return TRUE;
}

// This is the "Tiny Encryption Algorithm"
// The keys are taken from DkS3
// https://en.wikipedia.org/wiki/Tiny_Encryption_Algorithm
void TinyEncryptionAlgorithm(unsigned int *value)
{
	unsigned int v0, v1, delta, sum, k0, k1, k2, k3;
	v0 = value[0];
	v1 = value[1];

	delta = 0x9E3779B9;
	sum = 0;
	k0 = 0X4B694CD6, k1 = 0x96ADA235, k2 = 0xEC91D9D4, k3 = 0x23F562E5;
	for (int j = 0; j < 32; j++) {
		sum += delta;
		v0 += ((v1 << 4) + k0) ^ (v1 + sum) ^ ((v1 >> 5) + k1);
		v1 += ((v0 << 4) + k2) ^ (v0 + sum) ^ ((v0 >> 5) + k3);
	}
	value[0] = v0;
	value[1] = v1;
}

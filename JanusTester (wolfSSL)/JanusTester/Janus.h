#define WIN32_LEAN_AND_MEAN 
#include <Windows.h>
#include <iostream>

#include "wolfssl/openssl/bio.h"
#include "wolfssl/openssl/rsa.h"
#include "wolfssl/openssl/pem.h"

typedef char JANUS;

extern unsigned char* decrypted;

unsigned char* unbase64(const char* input, int length);

CHAR* Deobfuscate(char* cBuffer);
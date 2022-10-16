#pragma once

#define _CRT_SECURE_NO_WARNINGS
#define _CRT_NON_CONFORMING_SWPRINTFS

#include <iostream>
#include "wolfssl/openssl/bio.h"
#include "wolfssl/openssl/rsa.h"
#include "wolfssl/openssl/pem.h"

/*

	Convention of IScramble

*/


class IScramble {

public:

	/*
	
		IScramble Children will provide functions for scrambling WCHAR and CHAR strings

	*/
	IScramble(void){}
	//virtual ~IScramble(void) = 0 {}

	/*
		Args:
			cToScramble[in]: is the buffer containing a char string to scramble
			iNumOfChars[in]: the number of CHARs in the buffer
	*/
	int ScrambleA(unsigned char* cToScramble, unsigned int NumOfChars);


	/*
		Args:
			cVarName[in]: the name of the variable being replaced
			cStringLiteral[in]: the string literal to be added to the insert (after scrambling)
			iNumOfChars[in]: the number of characters in the buffer
			cInsert[out]: the insert to replace CARBLE\BARBLE declaration in the c/cpp file
	*/
	int GenerateInsertA(char* cVarName, char* cStringLiteral, unsigned int iNumOfChars, char*& cInsert);

	/*
		Args:
			cBuffer[in]: is the buffer containing an unsigned char to encode
			iNumOfChars[in]: number of unsigned chars in the provided buffer
	*/
	CHAR* base64(const unsigned char* cBuffer, int iNumOfChars);

	/*
		Loads provided public key into memory passed to "RSA_public_encrypt"
	*/
	BOOL InitializeRSA(VOID);

	WOLFSSL_RSA* pubKey = NULL;
	unsigned char* encrypted = NULL;
};
#pragma once
#include "IScramble.h"

int IScramble::ScrambleA(unsigned char* cToScramble, unsigned int iNumOfChars) {
	
	if (cToScramble == NULL) {
		return 0;
	}

	encrypted = (unsigned char*)calloc(RSA_size(pubKey) + 1, 1);
	printf("[+] Length: %d\n", iNumOfChars);
	int result = RSA_public_encrypt(iNumOfChars, cToScramble, encrypted, pubKey, RSA_PKCS1_OAEP_PADDING);
	if (result == -1) {
		printf("[!] RSA_public_encrypt failed, error: %s\n", ERR_error_string(ERR_get_error(), NULL));
		return 0;
	}
	else {
		return result;
	}
}

char* IScramble::base64(const unsigned char* input, int length) {
	BIO* bmem, * b64;
	BUF_MEM* bptr;

	b64 = BIO_new(BIO_f_base64());
	BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
	bmem = BIO_new(BIO_s_mem());
	b64 = BIO_push(b64, bmem);
	BIO_write(b64, input, length);
	BIO_flush(b64);
	BIO_get_mem_ptr(b64, &bptr);

	char* buff = (char*)calloc(bptr->length + 1, 1);
	memcpy(buff, bptr->data, bptr->length);

	BIO_free_all(b64);

	return buff;
}

int IScramble::GenerateInsertA(char* cVarName, char* cStringLiteral, unsigned int iNumOfChars, char*& cInsert) {
	if (cVarName == NULL || cStringLiteral == NULL) {
		return 0;
	}

	cInsert = NULL;

	char cInsertFormat[] = "char %s[] = \"%s\";"; 
	
	cInsert = (char*)calloc(sizeof(char), strlen(cInsertFormat) + (strlen(cVarName) * 3) + strlen(cStringLiteral) + 50);
	sprintf(cInsert, cInsertFormat, cVarName, cStringLiteral);

	return 1;
}

BOOL IScramble::InitializeRSA(VOID) {
	
	unsigned char publicKey[] = "-----BEGIN PUBLIC KEY-----\n"\
		"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAy8Dbv8prpJ/0kKhlGeJY\n"\
		"ozo2t60EG8L0561g13R29LvMR5hyvGZlGJpmn65+A4xHXInJYiPuKzrKUnApeLZ+\n"\
		"vw1HocOAZtWK0z3r26uA8kQYOKX9Qt/DbCdvsF9wF8gRK0ptx9M6R13NvBxvVQAp\n"\
		"fc9jB9nTzphOgM4JiEYvlV8FLhg9yZovMYd6Wwf3aoXK891VQxTr/kQYoq1Yp+68\n"\
		"i6T4nNq7NWC+UNVjQHxNQMQMzU6lWCX8zyg3yH88OAQkUXIXKfQ+NkvYQ1cxaMoV\n"\
		"PpY72+eVthKzpMeyHkBn7ciumk5qgLTEJAfWZpe4f4eFZj/Rc8Y8Jj2IS5kVPjUy\n"\
		"wQIDAQAB\n"\
		"-----END PUBLIC KEY-----\n";

	BIO* pubBio = BIO_new_mem_buf((void*)publicKey, -1);
	pubKey = PEM_read_bio_RSA_PUBKEY(pubBio, NULL, NULL, NULL);
	BIO_free(pubBio);
	if (pubKey == NULL) {
		printf("[!] PEM_read_bio_RSA_PUBKEY failed, error: %s\n", ERR_error_string(ERR_get_error(), NULL));
		return FALSE;
	}
	else {
		printf("\n\n[+] PEM_read_bio_RSA_PUBKEY was successful (public key)\n");
		return TRUE;
	}
}
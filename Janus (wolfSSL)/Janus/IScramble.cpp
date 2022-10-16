#include "IScramble.h"

int IScramble::ScrambleA(unsigned char* cToScramble, unsigned int iNumOfChars) {
	
	if (cToScramble == NULL) {
		return 0;
	}

	encrypted = (unsigned char*)calloc(wolfSSL_RSA_size(pubKey) + 1, 1);
	printf("[+] Length: %d\n", iNumOfChars);
	int result = wolfSSL_RSA_public_encrypt(iNumOfChars, cToScramble, encrypted, pubKey, 1);
	if (result == -1) {
		printf("[!] wolfSSL_RSA_public_encrypt failed, error: %s\n", wolfSSL_ERR_error_string(wolfSSL_ERR_get_error(), NULL));
		return 0;
	}
	else {
		return result;
	}
}

char* IScramble::base64(const unsigned char* input, int length) {
	WOLFSSL_BIO* bmem, * b64;
	WOLFSSL_BUF_MEM* bptr;

	b64 = wolfSSL_BIO_new(wolfSSL_BIO_f_base64());
	bmem = wolfSSL_BIO_new(wolfSSL_BIO_s_mem());
	b64 = wolfSSL_BIO_push(b64, bmem);
	wolfSSL_BIO_set_flags(b64, WOLFSSL_BIO_FLAG_BASE64_NO_NL);
	wolfSSL_BIO_write(b64, input, length);
	wolfSSL_BIO_flush(b64);
	wolfSSL_BIO_get_mem_ptr(b64, &bptr);

	char* buff = (char*)calloc(bptr->length + 1, 1);
	if (buff == NULL) {
		exit(1);
	}
	memcpy(buff, bptr->data, bptr->length);
	//buff[bptr->length] = 0;

	wolfSSL_BIO_free_all(b64);

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

	WOLFSSL_BIO* pubBio = wolfSSL_BIO_new_mem_buf((void*)publicKey, -1);
	pubKey = wolfSSL_PEM_read_bio_RSA_PUBKEY(pubBio, NULL, NULL, NULL);
	wolfSSL_BIO_free(pubBio);
	if (pubKey == NULL) {
		printf("[!] wolfSSL_PEM_read_bio_RSA_PUBKEY failed, error: %s\n", wolfSSL_ERR_error_string(wolfSSL_ERR_get_error(), NULL));
		return FALSE;
	}
	else {
		printf("\n\n[+] wolfSSL_PEM_read_bio_RSA_PUBKEY was successful (public key)\n");
		return TRUE;
	}
}
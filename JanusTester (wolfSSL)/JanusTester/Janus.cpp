#include "Janus.h"

unsigned char* decrypted = NULL;

unsigned char* unbase64(char* input, int length) {
	WOLFSSL_BIO* bmem, * b64;

	unsigned char* buffer = (unsigned char*)calloc(length + 1, 1);

	b64 = wolfSSL_BIO_new(wolfSSL_BIO_f_base64());
	wolfSSL_BIO_set_flags(b64, WOLFSSL_BIO_FLAG_BASE64_NO_NL);
	bmem = wolfSSL_BIO_new_mem_buf(input, length);
	bmem = wolfSSL_BIO_push(b64, bmem);

	wolfSSL_BIO_read(bmem, buffer, length);
	wolfSSL_BIO_free_all(bmem);

	return buffer;
}

CHAR* Deobfuscate(char* cBuffer) {

	unsigned char privateKey[] = "-----BEGIN RSA PRIVATE KEY-----\n"\
		"MIIEowIBAAKCAQEAy8Dbv8prpJ/0kKhlGeJYozo2t60EG8L0561g13R29LvMR5hy\n"\
		"vGZlGJpmn65+A4xHXInJYiPuKzrKUnApeLZ+vw1HocOAZtWK0z3r26uA8kQYOKX9\n"\
		"Qt/DbCdvsF9wF8gRK0ptx9M6R13NvBxvVQApfc9jB9nTzphOgM4JiEYvlV8FLhg9\n"\
		"yZovMYd6Wwf3aoXK891VQxTr/kQYoq1Yp+68i6T4nNq7NWC+UNVjQHxNQMQMzU6l\n"\
		"WCX8zyg3yH88OAQkUXIXKfQ+NkvYQ1cxaMoVPpY72+eVthKzpMeyHkBn7ciumk5q\n"\
		"gLTEJAfWZpe4f4eFZj/Rc8Y8Jj2IS5kVPjUywQIDAQABAoIBADhg1u1Mv1hAAlX8\n"\
		"omz1Gn2f4AAW2aos2cM5UDCNw1SYmj+9SRIkaxjRsE/C4o9sw1oxrg1/z6kajV0e\n"\
		"N/t008FdlVKHXAIYWF93JMoVvIpMmT8jft6AN/y3NMpivgt2inmmEJZYNioFJKZG\n"\
		"X+/vKYvsVISZm2fw8NfnKvAQK55yu+GRWBZGOeS9K+LbYvOwcrjKhHz66m4bedKd\n"\
		"gVAix6NE5iwmjNXktSQlJMCjbtdNXg/xo1/G4kG2p/MO1HLcKfe1N5FgBiXj3Qjl\n"\
		"vgvjJZkh1as2KTgaPOBqZaP03738VnYg23ISyvfT/teArVGtxrmFP7939EvJFKpF\n"\
		"1wTxuDkCgYEA7t0DR37zt+dEJy+5vm7zSmN97VenwQJFWMiulkHGa0yU3lLasxxu\n"\
		"m0oUtndIjenIvSx6t3Y+agK2F3EPbb0AZ5wZ1p1IXs4vktgeQwSSBdqcM8LZFDvZ\n"\
		"uPboQnJoRdIkd62XnP5ekIEIBAfOp8v2wFpSfE7nNH2u4CpAXNSF9HsCgYEA2l8D\n"\
		"JrDE5m9Kkn+J4l+AdGfeBL1igPF3DnuPoV67BpgiaAgI4h25UJzXiDKKoa706S0D\n"\
		"4XB74zOLX11MaGPMIdhlG+SgeQfNoC5lE4ZWXNyESJH1SVgRGT9nBC2vtL6bxCVV\n"\
		"WBkTeC5D6c/QXcai6yw6OYyNNdp0uznKURe1xvMCgYBVYYcEjWqMuAvyferFGV+5\n"\
		"nWqr5gM+yJMFM2bEqupD/HHSLoeiMm2O8KIKvwSeRYzNohKTdZ7FwgZYxr8fGMoG\n"\
		"PxQ1VK9DxCvZL4tRpVaU5Rmknud9hg9DQG6xIbgIDR+f79sb8QjYWmcFGc1SyWOA\n"\
		"SkjlykZ2yt4xnqi3BfiD9QKBgGqLgRYXmXp1QoVIBRaWUi55nzHg1XbkWZqPXvz1\n"\
		"I3uMLv1jLjJlHk3euKqTPmC05HoApKwSHeA0/gOBmg404xyAYJTDcCidTg6hlF96\n"\
		"ZBja3xApZuxqM62F6dV4FQqzFX0WWhWp5n301N33r0qR6FumMKJzmVJ1TA8tmzEF\n"\
		"yINRAoGBAJqioYs8rK6eXzA8ywYLjqTLu/yQSLBn/4ta36K8DyCoLNlNxSuox+A5\n"\
		"w6z2vEfRVQDq4Hm4vBzjdi3QfYLNkTiTqLcvgWZ+eX44ogXtdTDO7c+GeMKWz4XX\n"\
		"uJSUVL5+CVjKLjZEJ6Qc2WZLl94xSwL71E41H4YciVnSCQxVc4Jw\n"\
		"-----END RSA PRIVATE KEY-----\n";

	WOLFSSL_RSA* privKey = NULL;
	WOLFSSL_BIO* privBio = wolfSSL_BIO_new_mem_buf((void*)privateKey, -1);
	if (privBio == NULL) {
		return 0;
	}
	privKey = PEM_read_bio_RSAPrivateKey(privBio, NULL, NULL, NULL);
	if (privKey == NULL) {
		fprintf(stderr, "[!] PEM_read_bio_RSAPrivateKey failed, error: %s\n", wolfSSL_ERR_error_string(wolfSSL_ERR_get_error(), NULL));
		return 0;
	}
	wolfSSL_BIO_free(privBio);

	unsigned char* unB64 = unbase64(cBuffer, strlen(cBuffer));

	decrypted = (unsigned char*)calloc(wolfSSL_RSA_size(privKey) + 1, 1);
	int decrypted_length = wolfSSL_RSA_private_decrypt(wolfSSL_RSA_size(privKey), unB64, decrypted, privKey, 1);
	if (decrypted_length == -1) {
		fprintf(stderr, "[!] RSA_private_decrypt failed, error: %s\n", wolfSSL_ERR_error_string(wolfSSL_ERR_get_error(), NULL));
		free(unB64);
		free(decrypted);
		wolfSSL_RSA_free(privKey);
		return 0;
	}
	else {
		free(unB64);
		wolfSSL_RSA_free(privKey);
		return (CHAR*)decrypted;
	}
}
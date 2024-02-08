/*
 * Copyright 2016-2018 Ayla Networks, Inc.  All rights reserved.
 *
 * Use of the accompanying software is permitted only in accordance
 * with and subject to the terms of the Software License Agreement
 * with Ayla Networks, Inc., a copy of which can be obtained from
 * Ayla Networks, Inc.
 */
#define _GNU_SOURCE	/* for asprintf() */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <unistd.h>
#include <arpa/inet.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <ayla/utypes.h>
#include <ayla/log.h>
#include <ayla/assert.h>
#include <ayla/hex.h>
#include <ayla/base64.h>
#include <ayla/crc.h>
#include <ayla/file_io.h>
#include <ayla/lan_ota.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/ssl.h>
#include <openssl/aes.h>

#define TEST_BUF_1024 1024
#define TEST_IMG_DATA_READ_BUF_LEN 50

#define TEST_RSA_PUBLIC_KEY_FILE "./files/rsa_public_key.pem"
#define TEST_RSA_PRIVATE_KEY_FILE "./files/rsa_private_key.pem"
#define TEST_KEY_PATH "./files/key"
#define TEST_PLAIN_HEADER_PATH "./files/plain_header"
#define TEST_PLAIN_HEADER_WITH_CRC16_PATH "./files/plain_header_with_crc16"
#define TEST_HEADER_ENCRYPTED_PATH "./files/header_encrypted"

#define TEST_ORG_SMALL_IMAGE_PATH "./files/org_small_image"
#define TEST_ORG_LARGE_IMAGE_PATH "./files/org_large_image"
#define TEST_ORG_IMAGE_WITH_PADDING_PATH "./files/original_image_with_padding"

#define TEST_LANOTA_IMAGE_HEADER \
	"./files/lanota_image_header"
#define TEST_LANOTA_ENCRYPTED_IMAGE_PAYLOAD \
	"./files/lanota_encrypted_image_payload"
#define TEST_LANOTA_IMGAE_HEADER_PAYLOAD \
	"./files/lanota_image_header_payload"

#define TEST_LANOTA_DECRYPTED_IMAGE_PAYLOAD \
	"./files/lanota_decrypted_image_payload"

#define TEST_LAN_OTA_INFO_URL "http://192.168.0.5/lanota_patch.img"
#define TEST_LAN_OTA_INFO_VER "1.0"
#define TEST_LAN_OTA_INFO_TYPE "host_mcu"
#define TEST_LAN_OTA_INFO_PORT 9999

#define TEST_KEY_CONST_STR "901ee78472c89bb623e8faa2e7cf8d99"\
	"9dd64b5425b3d4c9e0078a09c2e4778b"
#define TEST_DSN_CONST_STR "AC000W000520050"

#define TEST_LAN_OTA_INFO_VER_ERR "4.0"
#define TEST_LAN_OTA_INFO_TYPE_ERR "module"
#define TEST_DSN_STR_ERR "AC000W000520051"
#define TEST_ERR_CHAR '6'
#define TEST_ERR_CHAR2 '7'


/* Test image types */
/* All error test types are using large image for test */
enum test_img_type {
	TEST_IMG_SMALL_IMG,
	TEST_IMG_LARGE_IMG,
	TEST_IMG_SIZE_ERR,
	TEST_IMG_TYPE_ERR,
	TEST_IMG_DSN_ERR,
	TEST_IMG_VER_ERR,
	TEST_IMG_KEY_ERR,
	TEST_IMG_SIGN_ERR,
	TEST_IMG_PADDING_LEN_ERR,
	TEST_IMG_PADDING_VAL_ERR,
	TEST_IMG_PAYLOAD_ERR,
	/* Add new error test types before this */
	TEST_IMG_TYPE_MAX
};

struct test_lanota_enc_param {
	/* image CBC iv seed */
	unsigned char img_iv_seed[LAN_OTA_IV_SIZE];
	/* image AES 256 key */
	unsigned char img_enc_key[LAN_OTA_KEY_LEN];
	/* image sha digest*/
	unsigned char sha256_digest[SHA256_DIGEST_LENGTH];
};

static char *cmdname;
static char *test_public_key;
static char *test_private_key;
static struct test_lanota_enc_param lanota_enc_param;
static unsigned char g_iv_seed[LAN_OTA_IV_SIZE];
static struct lan_ota_dec_param lanota_dec_param;

static const char *test_img_type_string[TEST_IMG_TYPE_MAX] = {
	"small image", /* TEST_IMG_SMALL_IMG */
	"large image", /* TEST_IMG_LARGE_IMG */
	"image size error", /* TEST_IMG_SIZE_ERR */
	"image type error", /* TEST_IMG_TYPE_ERR */
	"image dsn error", /* TEST_IMG_DSN_ERR */
	"image ver error", /* TEST_IMG_VER_ERR */
	"image key error", /* TEST_IMG_KEY_ERR */
	"image sign error", /* TEST_IMG_SIGN_ERR */
	"image padding len error", /* TEST_IMG_PADDING_LEN_ERR */
	"image padding val error", /* TEST_IMG_PADDING_VAL_ERR */
	"image payload error", /* TEST_IMG_PAYLOAD_ERR */
};

/* expected result for image header process */
static bool test_header_proc_expected_result[TEST_IMG_TYPE_MAX] = {
	true, /* TEST_IMG_SMALL_IMG */
	true, /* TEST_IMG_LARGE_IMG */
	true, /* TEST_IMG_SIZE_ERR */
	false, /* TEST_IMG_TYPE_ERR */
	false, /* TEST_IMG_DSN_ERR */
	false, /* TEST_IMG_VER_ERR */
	true, /* TEST_IMG_KEY_ERR */
	true, /* TEST_IMG_SIGN_ERR */
	true, /* TEST_IMG_PADDING_LEN_ERR */
	true, /* TEST_IMG_PADDING_VAL_ERR */
	true, /* TEST_IMG_PAYLOAD_ERR */
};

/* expected result for image payload process */
static bool test_payload_proc_expected_result[TEST_IMG_TYPE_MAX] = {
	true, /* TEST_IMG_SMALL_IMG */
	true, /* TEST_IMG_LARGE_IMG */
	false, /* TEST_IMG_SIZE_ERR */
	false, /* TEST_IMG_TYPE_ERR */
	false, /* TEST_IMG_DSN_ERR */
	false, /* TEST_IMG_VER_ERR */
	false, /* TEST_IMG_KEY_ERR */
	false, /* TEST_IMG_SIGN_ERR */
	false, /* TEST_IMG_PADDING_LEN_ERR */
	false, /* TEST_IMG_PADDING_VAL_ERR */
	false, /* TEST_IMG_PAYLOAD_ERR */
};

static bool test_result[TEST_IMG_TYPE_MAX];


/* append new content to a file */
static int test_lanota_append_content_to_file(
	const char *file_name, const char *buf, int buf_len)
{
	int fd;
	int len;

	fd = open(file_name, O_CREAT | O_RDWR | O_APPEND,
		S_IRUSR | S_IWUSR);
	if (fd == -1) {
		log_err("can't open file %s",
			file_name);
		return -1;
	}

	len = write(fd, buf, buf_len);
	if (len < 0 || len != buf_len) {
		log_err("append content to file %s error",
			file_name);
		close(fd);
		return -1;
	}

	close(fd);
	return 0;
}

/*
  * Get data from file
  * Out params:
  *     content_len: the length of file data
  * Return value:
  *     file data: should be freed by the calling function
  */
static char *test_lanota_read_content(const char *file_name,
	size_t *content_len)
{
	int fd;
	ssize_t file_size;
	char *content = NULL;

	fd = open(file_name, O_RDONLY);
	if (fd < 0) {
		log_err("open failed for %s: %m", file_name);
		goto error;
	}
	file_size = lseek(fd, 0, SEEK_END);
	if (file_size <= 0) {
		log_warn("empty file: %s", file_name);
		goto error;
	}
	content = (char *)malloc(file_size + 1);	/* Add room for null */
	if (!content) {
		log_err("malloc failed");
		goto error;
	}
	lseek(fd, 0, SEEK_SET);
	file_size = read(fd, content, file_size);
	if (file_size <= 0) {
		log_err("file read failed: %s", file_name);
		free(content);
		content = NULL;
		goto error;
	}
	content[file_size] = '\0';
	if (content_len) {
		*content_len = file_size;
	}
error:
	close(fd);
	return content;
}

/* Initialize private key */
static void test_lanota_init_private_key()
{
	test_private_key =
		test_lanota_read_content(TEST_RSA_PRIVATE_KEY_FILE, NULL);
	ASSERT(test_private_key != NULL);

	return;
}

/* Initialize public key */
static void test_lanota_init_public_key()
{
	test_public_key =
		test_lanota_read_content(TEST_RSA_PUBLIC_KEY_FILE, NULL);
	ASSERT(test_public_key != NULL);

	return;
}

/* generate random data */
static void test_random_fill(void *buf, size_t len)
{
	srandom((unsigned)time(0));
	while (((long)buf % sizeof(u32)) && len) {
		*(u8 *)buf = random();
		buf++;
		len--;
	}
	while (len > sizeof(u32)) {
		*(u32 *)buf = random();
		buf += sizeof(u32);
		len -= sizeof(u32);
	}
	while (len) {
		*(u8 *)buf = random();
		buf++;
		len--;
	}
}

/* generate random key for aes */
static void test_lanota_enc_aes_key_init()
{
	char key_hex_str[LAN_OTA_KEY_LEN * 2 + 1];

	test_random_fill(lanota_enc_param.img_enc_key,
		sizeof(lanota_enc_param.img_enc_key));
	/*hex_parse(lanota_enc_param.img_enc_key,
		sizeof(lanota_enc_param.img_enc_key),
		TEST_KEY_CONST_STR, NULL);*/

	unlink(TEST_KEY_PATH);
	hex_string(key_hex_str, sizeof(key_hex_str),
		lanota_enc_param.img_enc_key,
		sizeof(lanota_enc_param.img_enc_key),
		0, 0);
	test_lanota_append_content_to_file(TEST_KEY_PATH,
		key_hex_str, strlen(key_hex_str));
}

/* generate iv for aes */
static void test_lanota_enc_aes_iv_init()
{
	unsigned char iv[LAN_OTA_IV_SIZE] = {0};

	log_debug("init aes iv %s", TEST_DSN_CONST_STR);
	memcpy(iv, TEST_DSN_CONST_STR, LAN_OTA_IV_SIZE - 1);
	memcpy(lanota_enc_param.img_iv_seed, iv,
		sizeof(lanota_enc_param.img_iv_seed));
}

/* get image data's sha256 signature */
static void test_lanota_get_img_sha256(const char *file_name)
{
	SHA256_CTX stx;
	unsigned char digest[SHA256_DIGEST_LENGTH];
	char buffer[TEST_BUF_1024];
	size_t len;
	FILE *fp;

	log_debug("get image's sha256 for %s", file_name);

	fp = fopen(file_name, "rb");
	if (fp == NULL) {
		log_err("can't open file %s",
			file_name);
		return;
	}

	SHA256_Init(&stx);
	while ((len = fread(buffer, 1, TEST_BUF_1024, fp)) > 0) {
		SHA256_Update(&stx, buffer, len);
		memset(buffer, 0, sizeof(buffer));
	}
	SHA256_Final(digest, &stx);

	fclose(fp);

	memcpy(lanota_enc_param.sha256_digest, digest,
		SHA256_DIGEST_LENGTH);
	return;
}

/*
{
	"ota":
	{
		"url": "http://<mobile_server_ip_addr>/bc-0.18.1.patch",
		"ver": "0.18.1",
		"size": 12300,
		"type": "host_mcu",
		"port": 8888,
		"head": "<base64-header-from-first-256B-of-image>"
	}
}
*/
static char *test_lanota_gen_ota_img_info_str(
	const char *img_url, const char *img_ver,
	const char *img_type, size_t img_port, size_t img_size,
	void *img_hdr, size_t img_hdr_len)
{
	json_t *root = json_object();
	json_t *ota = json_object();
	char *json_str;
	char *head;

	log_debug("lan ota gen ota img info: img_url: %s, "
		"img_ver: %s, img_type: %s, img_port: %zu, img_size: %zu, "
		"img_hdr_len: %zu",
		img_url, img_ver, img_type, img_port, img_size,
		img_hdr_len);

	head = base64_encode(img_hdr, img_hdr_len, NULL);
	ASSERT(head != NULL);

	json_object_set_new(root, "ota", ota);
	json_object_set_new(ota, "url", json_string(img_url));
	json_object_set_new(ota, "ver", json_string(img_ver));
	json_object_set_new(ota, "size", json_integer(img_size));
	json_object_set_new(ota, "type", json_string(img_type));
	json_object_set_new(ota, "port", json_integer(img_port));
	json_object_set_new(ota, "head", json_string(head));

	json_str = json_dumps(root, JSON_COMPACT);
	json_decref(root);
	free(head);

	return json_str;
}

/* generate image with padding, align to multiples of AES256_BLK_SIZE */
static int test_lanota_gen_img_with_padding(
	const char *org_file_name, enum test_img_type test_type)
{
	ssize_t org_img_size;
	size_t remain_len;
	size_t padding_len;
	int i;
	char padding_buf[AES256_BLK_SIZE + 1];

	unlink(TEST_ORG_IMAGE_WITH_PADDING_PATH);

	org_img_size = file_copy(org_file_name,
		TEST_ORG_IMAGE_WITH_PADDING_PATH);
	if (org_img_size == -1) {
		log_err("gen image with padding error: file copy");
		return -1;
	}

	remain_len = org_img_size % AES256_BLK_SIZE;
	padding_len = AES256_BLK_SIZE - remain_len;

	if (test_type == TEST_IMG_PADDING_VAL_ERR) {
		for (i = 0; i < padding_len; i++) {
			padding_buf[i] = (char)i;
		}
	} else {
		if (test_type == TEST_IMG_PADDING_LEN_ERR) {
			padding_len += 1;
		}

		for (i = 0; i < padding_len; i++) {
			padding_buf[i] = (char)padding_len;
		}
	}

	test_lanota_append_content_to_file(
		TEST_ORG_IMAGE_WITH_PADDING_PATH,
		padding_buf, padding_len);
	return 0;
}

static int test_lanota_gen_ota_img_info_file(
	enum test_img_type test_type)
{
	char *img_url = TEST_LAN_OTA_INFO_URL;
	char *img_ver = TEST_LAN_OTA_INFO_VER;
	char *img_type = TEST_LAN_OTA_INFO_TYPE;
	size_t img_port = TEST_LAN_OTA_INFO_PORT;
	ssize_t img_size;
	char *img_info;
	char *img_hdr;
	size_t img_hdr_len;

	log_debug("generate ota image info file");

	img_size = file_get_size(TEST_ORG_IMAGE_WITH_PADDING_PATH);
	if (img_size <= 0) {
		return -1;
	}

	switch (test_type) {
	case TEST_IMG_SIZE_ERR:
		if (img_size >= 1) {
			img_size -= 1;
		} else {
			img_size += 1;
		}
		break;
	case TEST_IMG_TYPE_ERR:
		img_type = TEST_LAN_OTA_INFO_TYPE_ERR;
		break;
	default:
		break;
	}

	img_hdr = test_lanota_read_content(TEST_HEADER_ENCRYPTED_PATH,
	    &img_hdr_len);
	if (!img_hdr || !img_hdr_len) {
		log_err("could not read encrypted image header: %s",
		    TEST_HEADER_ENCRYPTED_PATH);
		return -1;
	}

	img_info = test_lanota_gen_ota_img_info_str(
		img_url, img_ver, img_type,
		img_port, img_size, img_hdr, img_hdr_len);

	test_lanota_append_content_to_file(TEST_LANOTA_IMAGE_HEADER,
		img_info, strlen(img_info));
	free(img_info);
	free(img_hdr);
	return 0;
}

/*
  * Get image header Json string including dsn,ver,key,sign.
  * return string should be free'd by the calling function
  */
static char *test_lanota_gen_ota_img_hdr_str(
	const char *dsn, const char *ver,
	const char *key, const char *sign)
{
	/*
	J = {
		"dsn": "AC000W000441358",
		"ver": "2.4.1",
		"key": "K",
		"sign": "S"
	}

	H = J || 0x00
	*/
	int header_len;
	char *header_str;

	log_debug("generate ota image header "
		"dsn:%s, ver:%s, key:%s, sign:%s",
		dsn, ver, key, sign);

	header_len = asprintf(&header_str,
		"{" \
		"\"dsn\": \"%s\", " \
		"\"ver\": \"%s\", " \
		"\"key\": \"%s\", " \
		"\"sign\": \"%s\"" \
		"}",
		dsn,
		ver,
		key,
		sign);
	if (header_len == -1) {
		return NULL;
	}

	return header_str;
}

/* generate lan ota image header's plain text */
static int test_lanota_gen_ota_img_hdr_plaintxt(
	enum test_img_type test_type)
{
	char *dsn = TEST_DSN_CONST_STR;
	char *ver = TEST_LAN_OTA_INFO_VER;
	char key_hex_str[LAN_OTA_KEY_LEN * 2 + 1];
	char sig_hex_str[SHA256_DIGEST_LENGTH * 2 + 1];
	char *plain_txt;

	hex_string(key_hex_str, sizeof(key_hex_str),
		lanota_enc_param.img_enc_key,
		sizeof(lanota_enc_param.img_enc_key),
		0, 0);
	hex_string(sig_hex_str, sizeof(sig_hex_str),
		lanota_enc_param.sha256_digest,
		sizeof(lanota_enc_param.sha256_digest),
		0, 0);

	switch (test_type) {
	case TEST_IMG_DSN_ERR:
		dsn = TEST_DSN_STR_ERR;
		break;
	case TEST_IMG_VER_ERR:
		ver = TEST_LAN_OTA_INFO_VER_ERR;
		break;
	case TEST_IMG_KEY_ERR:
		if (key_hex_str[LAN_OTA_KEY_LEN * 2 - 2] != TEST_ERR_CHAR) {
			key_hex_str[LAN_OTA_KEY_LEN * 2 - 2] = TEST_ERR_CHAR;
			key_hex_str[LAN_OTA_KEY_LEN * 2 - 1] = TEST_ERR_CHAR;
		} else {
			key_hex_str[LAN_OTA_KEY_LEN * 2 - 2] = TEST_ERR_CHAR2;
			key_hex_str[LAN_OTA_KEY_LEN * 2 - 1] = TEST_ERR_CHAR2;
		}
		break;
	case TEST_IMG_SIGN_ERR:
		if (sig_hex_str[SHA256_DIGEST_LENGTH * 2 - 2] !=
			TEST_ERR_CHAR) {
			sig_hex_str[SHA256_DIGEST_LENGTH * 2 - 2] =
				TEST_ERR_CHAR;
			sig_hex_str[SHA256_DIGEST_LENGTH * 2 - 1] =
				TEST_ERR_CHAR;
		} else {
			sig_hex_str[SHA256_DIGEST_LENGTH * 2 - 2] =
				TEST_ERR_CHAR2;
			sig_hex_str[SHA256_DIGEST_LENGTH * 2 - 1] =
				TEST_ERR_CHAR2;
		}
		break;
	default:
		break;
	}

	plain_txt = test_lanota_gen_ota_img_hdr_str(dsn,
		ver, key_hex_str, sig_hex_str);
	if (plain_txt == NULL) {
		log_err("generate image header string failed");
		return -1;
	}

	unlink(TEST_PLAIN_HEADER_PATH);
	test_lanota_append_content_to_file(TEST_PLAIN_HEADER_PATH,
		plain_txt, strlen(plain_txt) + 1);
	log_debug("image header plain text: %s", plain_txt);
	free(plain_txt);
	return 0;
}

/* generate image header with crc16, H = J || 0x00 || crc16 */
static int test_lanota_gen_img_hdr_with_crc(const char *file_name)
{
	size_t file_size;
	char *plain_hdr;
	char *plain_hdr_with_crc;
	size_t plain_hdr_with_crc_len;
	unsigned short hdr_crc16;

	plain_hdr = test_lanota_read_content(file_name, &file_size);
	if (!plain_hdr) {
		log_err("read plain header file error: %s", file_name);
		return -1;
	}

	plain_hdr_with_crc_len = file_size + sizeof(unsigned short);
	plain_hdr_with_crc = malloc(plain_hdr_with_crc_len);
	if (!plain_hdr_with_crc) {
		log_err("allocate memory failed for header with crc");
		return -1;
	}
	memcpy(plain_hdr_with_crc, plain_hdr, file_size);

	/* calculate CRC16 of image header Ck = CRC(J || 0x00) */
	hdr_crc16 = crc16((unsigned char *)plain_hdr_with_crc,
		file_size, CRC16_INIT);
	log_debug("image header crc16: 0x%x", hdr_crc16);

	/* transfer to network order */
	hdr_crc16 = htons(hdr_crc16);
	memcpy(plain_hdr_with_crc + file_size,
		&hdr_crc16, sizeof(unsigned short));
	unlink(TEST_PLAIN_HEADER_WITH_CRC16_PATH);
	test_lanota_append_content_to_file(
		TEST_PLAIN_HEADER_WITH_CRC16_PATH,
		plain_hdr_with_crc, plain_hdr_with_crc_len);
	free(plain_hdr);
	free(plain_hdr_with_crc);
	return 0;
}

/*
  * encyrpt image header by RSA
  * encrypted string returned should be freed by the calling function
  */
static char *test_lanota_encrypt_header_by_rsa(const char *head,
	int len, int *enc_len)
{
	RSA *rsa;
	BIO *bp;
	int rsa_len;
	int get;
	char *enc_buf = NULL;

	/*
	J = {
		"dsn": "AC000W000441358",
		"ver": "2.4.1",
		"key": "K",
		"sign": "S"
	}

	H = J || 0x00
	*/
	bp = BIO_new_mem_buf((void *)test_private_key,
		strlen(test_private_key));
	if (bp == NULL) {
		log_err("lan ota image encrypt: cannot alloc BIO");
		return NULL;
	}

	/*
	 * Read key in AFS-preferred format first.  If that fails, use
	 * the more standard RSA format.
	 */
	rsa = PEM_read_bio_RSAPrivateKey(bp, NULL, NULL, NULL);
	if (rsa == NULL) {
		get = ERR_get_error();	/* report first error if both fail */
		log_err("key import failed: "
		    "err %s func %s reason %s",
		    ERR_lib_error_string(get),
		    ERR_func_error_string(get),
		    ERR_reason_error_string(get));
		log_err("key is %s", test_private_key);
		goto err_encrypt;
	}

	rsa_len = RSA_size(rsa);
	enc_buf = (char *)malloc(rsa_len);
	if (enc_buf == NULL) {
		log_err("malloc buff failed");
		goto err_encrypt;
	}
	memset(enc_buf, 0, rsa_len);
	get = RSA_private_encrypt(len, (unsigned char *)head,
	    (unsigned char *)enc_buf, rsa, RSA_PKCS1_PADDING);
	if (get < 0) {
		get = ERR_get_error();	/* report first error if both fail */
		log_err("private enc failed: "
		    "err %s func %s reason %s",
		    ERR_lib_error_string(get),
		    ERR_func_error_string(get),
		    ERR_reason_error_string(get));
		goto err_encrypt;
	}
	log_debug("encrypt header: length %d", get);
	*enc_len = get;

	BIO_vfree(bp);
	RSA_free(rsa);
	return enc_buf;

err_encrypt:
	BIO_vfree(bp);
	if (rsa) {
		RSA_free(rsa);
	}
	free(enc_buf);
	return NULL;
}

/* generate encrypted image header file */
static int test_lanota_encrypt_img_header(const char *file_name)
{
	char *plain_hdr_with_crc;
	size_t plain_hdr_with_crc_len;
	char *encrypted_img_hdr;
	int encrypted_len = 0;

	plain_hdr_with_crc =
		test_lanota_read_content(file_name, &plain_hdr_with_crc_len);
	if (!plain_hdr_with_crc) {
		log_err("read content of %s failed", file_name);
		return -1;
	}

	encrypted_img_hdr = test_lanota_encrypt_header_by_rsa(
		plain_hdr_with_crc, plain_hdr_with_crc_len, &encrypted_len);
	if (encrypted_img_hdr == NULL) {
		log_err("encrypt image header failed");
		free(plain_hdr_with_crc);
		return -1;
	}
	log_debug("image header encrypted len: %d",
		encrypted_len);
	free(plain_hdr_with_crc);

	unlink(TEST_HEADER_ENCRYPTED_PATH);
	test_lanota_append_content_to_file(TEST_HEADER_ENCRYPTED_PATH,
		encrypted_img_hdr, encrypted_len);
	test_lanota_append_content_to_file(TEST_LANOTA_IMGAE_HEADER_PAYLOAD,
		encrypted_img_hdr, encrypted_len);

	free(encrypted_img_hdr);
	return 0;
}

/* image header generate process */
static int test_lanota_gen_img_header(
	enum test_img_type test_type)
{
	char *org_file_name;
	int rc;

	if (test_type == TEST_IMG_SMALL_IMG) {
		org_file_name = TEST_ORG_SMALL_IMAGE_PATH;
	} else {
		org_file_name = TEST_ORG_LARGE_IMAGE_PATH;
	}
	rc = test_lanota_gen_img_with_padding(org_file_name, test_type);
	if (rc) {
		log_err("gen image with padding failed");
		return -1;
	}

	log_debug("get image sha256");
	test_lanota_get_img_sha256(org_file_name);

	/* create plain txt of image header */
	rc = test_lanota_gen_ota_img_hdr_plaintxt(test_type);
	if (rc) {
		log_err("gen image header plain text failed");
		return -1;
	}

	rc = test_lanota_gen_img_hdr_with_crc(TEST_PLAIN_HEADER_PATH);
	if (rc) {
		log_err("gen image header with crc failed");
		return -1;
	}

	/* encrypt image header */
	rc = test_lanota_encrypt_img_header(
		TEST_PLAIN_HEADER_WITH_CRC16_PATH);
	if (rc) {
		log_err("encrypt image header failed");
		return -1;
	}

	unlink(TEST_LANOTA_IMAGE_HEADER);
	rc = test_lanota_gen_ota_img_info_file(test_type);
	if (rc) {
		log_err("gen image info failed");
		return -1;
	}

	log_debug("generate image header success");

	return 0;
}

/* AES IV should be initialized every time before encrypting image data */
static void test_lanota_init_image_aes_iv()
{
	memcpy(g_iv_seed, lanota_enc_param.img_iv_seed, LAN_OTA_IV_SIZE);
}

/* AES encrypt image */
static unsigned char *test_lanota_encrypt_img_piece_by_aes(
	const unsigned char *inbuf, int buf_len, int *out_enc_len)
{
	AES_KEY key;
	int pad;
	int enc_len;
	unsigned char *enc_buf;
	int rc;

	/*
	 * Allocate encryption buffer for the object and copy it.
	 */
	pad = -buf_len & (LAN_OTA_IV_SIZE - 1);
	enc_buf = malloc(buf_len + pad);
	if (!enc_buf) {
		log_err("malloc failed len %d pad %d", buf_len, pad);
		return NULL;
	}
	memcpy(enc_buf, inbuf, buf_len);
	if (pad != 0) {
		memset(enc_buf + buf_len, 0, pad);
	}
	enc_len = buf_len + pad;

	if (pad != 0) {
		log_debug("encrypt img piece by aes buflen %d, enc_len %d",
			buf_len, enc_len);
	}

	/*
	 * Encrypt buffer.
	 */
	rc = AES_set_encrypt_key(lanota_enc_param.img_enc_key,
	    LAN_OTA_KEY_LEN * 8, &key);
	if (rc) {
		log_err("set encrypt key rc %d", rc);
		free(enc_buf);
		return NULL;
	}
	/* iv param will be updated by AES_cbc_encrypt after call
		so tmp aes_iv is used
	*/
	AES_cbc_encrypt(enc_buf, enc_buf, enc_len, &key,
		g_iv_seed, AES_ENCRYPT);
	*out_enc_len = enc_len;
	return enc_buf;
}

/* encrypt image data by aes */
static int test_lanota_gen_img_encrypted_payload(
	enum test_img_type test_type)
{
	FILE *fp;
	int len;
	unsigned char buffer[AES256_BLK_SIZE];
	unsigned char *encrypted_buf;
	int enc_len;

	fp = fopen(TEST_ORG_IMAGE_WITH_PADDING_PATH, "rb");
	if (fp == NULL) {
		log_err("can't open file %s",
			TEST_ORG_IMAGE_WITH_PADDING_PATH);
		return -1;
	}

	unlink(TEST_LANOTA_ENCRYPTED_IMAGE_PAYLOAD);
	test_lanota_init_image_aes_iv();
	while ((len = fread(buffer, 1, sizeof(buffer), fp)) > 0) {
		if (test_type == TEST_IMG_PAYLOAD_ERR) {
			/* generate error payload for test */
			buffer[0] += 1;
		}
		encrypted_buf = test_lanota_encrypt_img_piece_by_aes(
			buffer, len, &enc_len);
		test_lanota_append_content_to_file(
			TEST_LANOTA_ENCRYPTED_IMAGE_PAYLOAD,
			(char *)encrypted_buf, enc_len);
		test_lanota_append_content_to_file(
			TEST_LANOTA_IMGAE_HEADER_PAYLOAD,
			(char *)encrypted_buf, enc_len);
		free(encrypted_buf);
	}
	fclose(fp);
	return 0;
}

/* test the function for lan ota image header process */
static int test_lanota_img_header_proc(const char *file_name,
	struct lan_ota_exec_info *ota_info)
{
	size_t header_size;
	char *header_buf;
	int rc;

	header_buf = test_lanota_read_content(file_name, &header_size);
	if (!header_buf) {
		log_err("failed to read file content");
		return -1;
	}

	rc = lan_ota_header_proc(header_buf,
		header_size, TEST_DSN_CONST_STR,
		test_public_key, ota_info);
	free(header_buf);
	if (rc) {
		log_err("lan ota image header process failed");
		return -1;
	}

	log_debug("ota exec info: type: %s, url: %s, ver: %s, "
		"dsn: %s, key: %s, checksum: %s size: %zu",
		ota_info->ota_type, ota_info->url, ota_info->ver,
		ota_info->dsn, ota_info->key, ota_info->checksum,
		ota_info->size);

	return 0;
}

/* Test the function for lan ota image payload process */
static int test_lanota_img_payload_proc(const char *file_name,
	struct lan_ota_exec_info *ota_info)
{
	FILE *fp;
	size_t read_len;
	char buffer[TEST_IMG_DATA_READ_BUF_LEN];
	char *decrypted_buf = NULL;
	size_t decrypted_len;
	char sha256_dec_hex_str[SHA256_DIGEST_LENGTH * 2 + 1];
	int rc;

	rc = file_get_size(file_name);
	if (rc == -1) {
		log_err("get size for %s error", file_name);
		return -1;
	}

	fp = fopen(file_name, "rb");
	if (fp == NULL) {
		log_err("can't open file %s",
			file_name);
		return -1;
	}

	unlink(TEST_LANOTA_DECRYPTED_IMAGE_PAYLOAD);

	if (lan_ota_img_decrypt_init(&lanota_dec_param,
		ota_info->size, ota_info->key,
		ota_info->dsn) < 0) {
		log_err("decrypt init error");
		fclose(fp);
		return -1;
	}

	while ((read_len = fread(buffer, 1, sizeof(buffer), fp)) > 0) {
		/* decrypt size should be multiples
			of AES256_BLK_SIZE */
		rc = lan_ota_img_decrypt_data(&lanota_dec_param,
			buffer, read_len, &decrypted_buf, &decrypted_len);
		if (rc) {
			log_err("decrypt image payload error");
			lan_ota_img_decrypt_cleanup(&lanota_dec_param);
			fclose(fp);
			return -1;
		}
		/* save decrypted image content */
		if (decrypted_len) {
			test_lanota_append_content_to_file(
				TEST_LANOTA_DECRYPTED_IMAGE_PAYLOAD,
				decrypted_buf, decrypted_len);
		}

		free(decrypted_buf);
	}
	lan_ota_img_decrypt_cleanup(&lanota_dec_param);
	fclose(fp);

	if (lanota_dec_param.aes_remain_len) {
		log_err("remain length is %zu after decrypted, should be 0",
			lanota_dec_param.aes_remain_len);
		return -1;
	}

	rc = lan_ota_sha256_get(&lanota_dec_param.stx,
		sha256_dec_hex_str, sizeof(sha256_dec_hex_str));
	if (rc) {
		log_err("get sha256 error");
		return -1;
	}
	log_debug("image payload's signature digest: %s",
		sha256_dec_hex_str);

	log_debug("image payload's expected signature digest: %s",
		ota_info->checksum);
	if (strcmp(sha256_dec_hex_str, ota_info->checksum)) {
		log_err("siganature is not as expected");
		return -1;
	}

	log_debug("decrypt image payload success");
	return 0;
}

/*
 * Main function
 */
int main(int argc, char **argv)
{
	int rc;
	enum test_img_type test_type;
	struct lan_ota_exec_info ota_info;
	size_t test_success_num = 0;
	size_t test_fail_num = 0;

	cmdname = strrchr(argv[0], '/');
	if (cmdname) {
		cmdname++;
	} else {
		cmdname = argv[0];
	}
	log_init(cmdname, LOG_OPT_NO_SYSLOG |
	    LOG_OPT_FUNC_NAMES | LOG_OPT_DEBUG | LOG_OPT_CONSOLE_OUT);

	/* Initialize */
	log_debug("Initialize");
	test_lanota_init_private_key();
	test_lanota_init_public_key();

	test_lanota_enc_aes_key_init();
	test_lanota_enc_aes_iv_init();

	for (test_type = 0;
		test_type < TEST_IMG_TYPE_MAX; test_type++) {
		log_debug("\n\n\n=========================="
			"=========================="
			"==========================\n");
		log_debug("image test type: %s",
			test_img_type_string[test_type]);

		unlink(TEST_LANOTA_IMGAE_HEADER_PAYLOAD);
		log_debug("generate image header for test type: %s",
			test_img_type_string[test_type]);
		rc = test_lanota_gen_img_header(test_type);
		if (rc) {
			log_err("failed to generate image header");
			continue;
		}

		log_debug("generate image payload for test type: %s",
			test_img_type_string[test_type]);
		/* encrypt image by AES 256 */
		rc = test_lanota_gen_img_encrypted_payload(test_type);
		if (rc) {
			log_err("failed to encrypt image payload");
			continue;
		}

		/* test image header process */
		memset(&ota_info, 0, sizeof(struct lan_ota_exec_info));
		rc = test_lanota_img_header_proc(TEST_LANOTA_IMAGE_HEADER,
			&ota_info);
		/* verify image header test result */
		test_result[test_type] = true;
		if (test_header_proc_expected_result[test_type] !=
			(rc ? false : true)) {
			test_result[test_type] = false;
		}
		if (rc) {
			log_err("test image header process failed for type: %s",
				test_img_type_string[test_type]);
			continue;
		}

		/* test image payload process */
		rc = test_lanota_img_payload_proc(
			TEST_LANOTA_ENCRYPTED_IMAGE_PAYLOAD, &ota_info);
		lan_ota_free_exec_info(&ota_info);
		/* verify image payload test result */
		if (test_payload_proc_expected_result[test_type] !=
			(rc ? false : true)) {
			test_result[test_type] = false;
		}
		if (rc) {
			log_err("test image payload process failed "
				"for type: %s",
				test_img_type_string[test_type]);
			continue;
		}
	}

	/* print unit test results */
	log_debug("\n\n\n=========================="
			"=========================="
			"==========================\n");
	log_debug("%31s", "lan ota test results:");
	for (test_type = 0;
		test_type < TEST_IMG_TYPE_MAX; test_type++) {
		if (test_result[test_type]) {
			test_success_num++;
		} else {
			test_fail_num++;
		}
		log_debug("%25s test: %s", test_img_type_string[test_type],
			test_result[test_type] ? "success" : "fail");
	}
	log_debug("Total: %zu, success: %zu, fail: %zu",
		test_success_num + test_fail_num,
		test_success_num, test_fail_num);

	ASSERT(test_fail_num == 0);

	return 0;
}

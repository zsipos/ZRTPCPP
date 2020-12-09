/*
 * Copyright 2006 - 2018, Werner Dittmann
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * @author  Werner Dittmann <Werner.Dittmann@t-online.de>
 */

#include <string.h>

#include <zrtp/crypto/aesCFB.h>
#include <cryptcommon/aescpp.h>

#ifdef ZSIPOS_HW_AES

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <assert.h>
#include <pthread.h>
#include <sys/mman.h>
#include <arpa/inet.h>


#define OCAES_CTRL_ADDR   0x08
#define OCAES_STATUS_ADDR 0x09
#define OCAES_CONFIG_ADDR 0x0a
#define OCAES_KEY_ADDR    0x10
#define OCAES_I_ADDR      0x20
#define OCAES_O_ADDR      0x30

//control reg
#define OCAES_INIT		(1<<0)
#define OCAES_NEXT		(1<<1)
//config reg
#define OCAES_DECODE	(0<<0)
#define OCAES_ENCODE	(1<<0)
#define OCAES_128BIT	(0<<1)
#define OCAES_256BIT	(1<<1)
//status reg
#define OCAES_READY		(1<<0)
#define OCAES_VALID		(1<<1)

static int                fd = -1;
static volatile uint32_t *ocaes;

static pthread_mutex_t ocaes_mutex = PTHREAD_MUTEX_INITIALIZER;

static int get_addr_len(uint32_t &addr, uint32_t &len)
{
	FILE *f = fopen("/proc/device-tree/soc/aes@0/reg", "rb");

	if (!f) {
		perror("devicetree zsipos_aes");
		return 0;
	}
	fread(&addr, 1, sizeof(uint32_t), f);
	fread(&len, 1, sizeof(uint32_t), f);
	fclose(f);
	addr = ntohl(addr);
	len = ntohl(len);
	return 1;
}

static int ocaes_init(void)
{
	int i, c;
	uint32_t addr, len;

	if (fd > -1)
		return 1;

	fd = open("/dev/zsipos_aes", O_RDWR | O_SYNC);
	if (fd < 0)
	{
		perror("open zsipos_aes");
		return 0;
	}

	if (!get_addr_len(addr, len))
		return 0;

	ocaes = (uint32_t*)mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_SHARED, fd, addr);
	if (ocaes == MAP_FAILED) {
		perror("mmap zsipos_aes");
		return 0;
	}

	assert((uint64_t)ocaes % 4 == 0);

	return 1;
}

static inline void ocaes_copyi(volatile uint32_t *dst, uint32_t *src)
{
	int      i;
	uint32_t h;

	if ((size_t)src % sizeof(uint32_t)) {
		for (i = 4; i; i--) {
			((uint8_t*)&h)[0] = ((uint8_t*)src)[0];
			((uint8_t*)&h)[1] = ((uint8_t*)src)[1];
			((uint8_t*)&h)[2] = ((uint8_t*)src)[2];
			((uint8_t*)&h)[3] = ((uint8_t*)src)[3];
			src++;
			*dst++ = htonl(h);
		}
	} else {
		*dst++ = htonl(*src++);
		*dst++ = htonl(*src++);
		*dst++ = htonl(*src++);
		*dst++ = htonl(*src++);
	}
}

static inline void ocaes_copyo(uint32_t *dst, volatile uint32_t *src)
{
	int      i;
	uint32_t h;

	if ((size_t)dst % sizeof(uint32_t)) {
		for (i = 4; i; i--)  {
			h = ntohl(*src++);
			((uint8_t*)dst)[0] = ((uint8_t*)&h)[0];
			((uint8_t*)dst)[1] = ((uint8_t*)&h)[1];
			((uint8_t*)dst)[2] = ((uint8_t*)&h)[2];
			((uint8_t*)dst)[3] = ((uint8_t*)&h)[3];
			dst++;
		}
	} else {
		*dst++ = ntohl(*src++);
		*dst++ = ntohl(*src++);
		*dst++ = ntohl(*src++);
		*dst++ = ntohl(*src++);
	}
}

extern "C" int aes_encrypt_key128(const unsigned char *key, aes_encrypt_ctx *cx)
{
	memset(cx, 0, sizeof(aes_encrypt_ctx));
	cx->ks[8] = OCAES_128BIT;
	memcpy(&cx->ks, key, 16);
	return 1;
}

extern "C" int aes_encrypt_key256(const unsigned char *key, aes_encrypt_ctx *cx)
{
	memset(cx, 0, sizeof(aes_encrypt_ctx));
	cx->ks[8] = OCAES_256BIT;
	memcpy(&cx->ks, key, 32);
	return 1;
}

extern "C" int aes_encrypt(const unsigned char *in, unsigned char *out, const aes_encrypt_ctx *cx)
{
	pthread_mutex_lock(&ocaes_mutex);

	if (fd == -1)
		ocaes_init();

	ocaes[OCAES_KEY_ADDR+0] = htonl(cx->ks[0]);
	ocaes[OCAES_KEY_ADDR+1] = htonl(cx->ks[1]);
	ocaes[OCAES_KEY_ADDR+2] = htonl(cx->ks[2]);
	ocaes[OCAES_KEY_ADDR+3] = htonl(cx->ks[3]);
	if (cx->ks[8] == OCAES_256BIT) {
		ocaes[OCAES_KEY_ADDR+4] = htonl(cx->ks[4]);
		ocaes[OCAES_KEY_ADDR+5] = htonl(cx->ks[5]);
		ocaes[OCAES_KEY_ADDR+6] = htonl(cx->ks[6]);
		ocaes[OCAES_KEY_ADDR+7] = htonl(cx->ks[7]);
	}
	ocaes[OCAES_CONFIG_ADDR] = cx->ks[8];
	ocaes[OCAES_CTRL_ADDR] = OCAES_INIT;
	while(!(ocaes[OCAES_STATUS_ADDR] & OCAES_READY))
		; // It's so fast, do busy waiting
	ocaes_copyi(&ocaes[OCAES_I_ADDR], (uint32_t*)in);
	ocaes[OCAES_CONFIG_ADDR] = OCAES_ENCODE | cx->ks[8];
	ocaes[OCAES_CTRL_ADDR] = OCAES_NEXT;
	while(!(ocaes[OCAES_STATUS_ADDR] & OCAES_READY))
		; // It's so fast, do busy waiting
	ocaes_copyo((uint32_t*)out, &ocaes[OCAES_O_ADDR]);

	pthread_mutex_unlock(&ocaes_mutex);

	return 1;
}

void aesCfbEncrypt(uint8_t *key, int32_t keyLength, uint8_t* ivec, uint8_t *data, int32_t len)
{
	aes_encrypt_ctx cx;

	if (keyLength == 16)
		aes_encrypt_key128(key, &cx);
	else if (keyLength == 32)
		aes_encrypt_key256(key, &cx);
	else
		return;

	int32_t n = 0;
	int32_t l = 0;

	if (((size_t)data | (size_t)ivec) % sizeof(uint32_t) == 0) {
		while (len >= keyLength) {
			aes_encrypt(ivec, ivec, &cx);
			for (; n < keyLength; n += sizeof(uint32_t)) {
				*(uint32_t *)(data + n) =
						*(uint32_t *)(ivec + n) ^= *(uint32_t *)(data + n);
			}
			len -= keyLength;
			data += keyLength;
			n = 0;
		}
		if (len) {
			aes_encrypt(ivec, ivec, &cx);
			while (len--) {
				data[n] = ivec[n] ^= data[n];
				++n;
			}
		}
		return;
	}
	while (l < len) {
		if (n == 0) {
			aes_encrypt(ivec, ivec, &cx);
		}
		data[l] = ivec[n] ^= data[l];
		++l;
		n = (n + 1) % keyLength;
	}
}

void aesCfbDecrypt(uint8_t *key, int32_t keyLength, uint8_t* ivec, uint8_t *data, int32_t len)
{
	aes_encrypt_ctx cx;

    if (keyLength == 16)
        aes_encrypt_key128(key, &cx);
    else if (keyLength == 32)
        aes_encrypt_key256(key, &cx);
    else
        return;

    int32_t n = 0;
    int32_t l = 0;

    if (((size_t)data | (size_t)ivec) % sizeof(uint32_t) == 0) {
    	while (len >= keyLength) {
    		aes_encrypt(ivec, ivec, &cx);
    		for (; n < keyLength; n += sizeof(uint32_t)) {
    			uint32_t t = *(uint32_t *)(data + n);
    			*(uint32_t *)(data + n) = *(uint32_t *)(ivec + n) ^ t;
    			*(uint32_t *)(ivec + n) = t;
    		}
    		len -= keyLength;
    		data += keyLength;
    		n = 0;
    	}
    	if (len) {
    		aes_encrypt(ivec, ivec, &cx);
    		while (len--) {
    			unsigned char c;
    			data[n] = ivec[n] ^ (c = data[n]);
    			ivec[n] = c;
    			++n;
    		}
    	}
    	return;
    }
    while (l < len) {
        unsigned char c;
        if (n == 0) {
            aes_encrypt(ivec, ivec, &cx);
        }
        data[l] = ivec[n] ^ (c = data[l]);
        ivec[n] = c;
        ++l;
        n = (n + 1) % keyLength;
    }
}

#else

void aesCfbEncrypt(uint8_t *key, int32_t keyLength, uint8_t* IV, uint8_t *data, int32_t dataLength)
{
    auto* saAes = new AESencrypt();

    if (keyLength == 16)
        saAes->key128(key);
    else if (keyLength == 32)
        saAes->key256(key);
    else
        return;

    // Note: maybe copy IV to an internal array if we encounter strange things.
    // the cfb encrypt modifies the IV on return. Same for output data (inplace encryption)
    saAes->cfb_encrypt(data, data, dataLength, IV);
    delete saAes;
}


void aesCfbDecrypt(uint8_t *key, int32_t keyLength, uint8_t* IV, uint8_t *data, int32_t dataLength)
{
    auto* saAes = new AESencrypt();
    if (keyLength == 16)
        saAes->key128(key);
    else if (keyLength == 32)
        saAes->key256(key);
    else
        return;

    // Note: maybe copy IV to an internal array if we encounter strange things.
    // the cfb encrypt modifies the IV on return. Same for output data (inplace encryption)
    saAes->cfb_decrypt(data, data, dataLength, IV);
    delete saAes;
}

#endif

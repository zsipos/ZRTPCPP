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

/*
 * Authors: Werner Dittmann
 */

#include "crypto/hmac.h"
#include <cstring>
#include <cstdio>

#ifdef ZSIPOS_HW_SHA1

#include <string.h>
#include <assert.h>
#include <pthread.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <arpa/inet.h>

static pthread_mutex_t swsha1_mutex = PTHREAD_MUTEX_INITIALIZER;

typedef struct {
	//buffer helpers
	uint8_t   init;
	uint8_t   wordlen;
	uint32_t  blocklen;
	uint32_t  wordbuf;
	//the real data
	uint64_t  len;
	uint32_t  digest[5];
	uint8_t   final[SHA1_DIGEST_SIZE];
} ZSIPOS_SHA1_CTX;

typedef struct {
	ZSIPOS_SHA1_CTX inictx;
	ZSIPOS_SHA1_CTX outctx;
	ZSIPOS_SHA1_CTX shactx;
} ZSIPOS_HMAC_CTX;

static int fd = -1;
static volatile uint32_t *swsha1; // "secureworks sha1"

#define __addr(x)			((x))

#define ADDR_CTRL			__addr(0x08)
#define CTRL_INIT_VALUE		1
#define CTRL_NEXT_VALUE		2
#define ADDR_STATUS			__addr(0x09)
#define ADDR_BLOCK			__addr(0x10)
#define ADDR_DIGEST			__addr(0x20)

static int get_addr_len(uint32_t &addr, uint32_t &len)
{
	FILE *f = fopen("/proc/device-tree/soc/sha@1/reg", "rb");

	if (!f) {
		perror("devicetree zsipos_sha1");
		return 0;
	}
	fread(&addr, 1, sizeof(uint32_t), f);
	fread(&len, 1, sizeof(uint32_t), f);
	fclose(f);
	addr = ntohl(addr);
	len = ntohl(len);
	return 1;
}

static int zsipos_sha1_hw_init(void)
{
	uint32_t addr, len;

	if (fd > -1)
		return 1;

	assert(sizeof(ZSIPOS_HMAC_CTX) <= sizeof(hmacSha1Context));

	fd = open("/dev/zsipos_sha1", O_RDWR | O_SYNC);
	if (fd < 0)
	{
		perror("open zsipos_sha1");
		return 0;
	}

	if (!get_addr_len(addr, len))
		return 0;

	swsha1 = (uint32_t*)mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_SHARED, fd, addr);
	if (swsha1 == MAP_FAILED) {
		perror("mmap zsipos_sha1");
		return 0;
	}

	return 1;
}

static inline void add_byte(ZSIPOS_SHA1_CTX *ctx, uint8_t byte)
{
	ctx->wordbuf = ctx->wordbuf <<  8 | byte;
	ctx->wordlen++;
	if (ctx->wordlen == 4) {
		swsha1[ADDR_BLOCK + ctx->blocklen] = ctx->wordbuf;
		ctx->wordbuf = 0;
		ctx->wordlen = 0;
		ctx->blocklen++;
	}
	if (ctx->blocklen == 16) {
		if (!ctx->init) {
			swsha1[ADDR_CTRL] = CTRL_INIT_VALUE;
			ctx->init = 1;
		} else
			swsha1[ADDR_CTRL] = CTRL_NEXT_VALUE;
		ctx->blocklen = 0;
		// get result
		while (!swsha1[ADDR_STATUS])
			;
	}
}

static inline void zsipos_sha1_init(ZSIPOS_SHA1_CTX *ctx)
{
	memset(ctx, 0, sizeof(ZSIPOS_SHA1_CTX));
}

static inline void zsipos_sha1_update(ZSIPOS_SHA1_CTX *ctx, const uint8_t *data, uint64_t len)
{
	uint64_t i;

	for (i = 0; i < len; i++)
		add_byte(ctx, data[i]);
	ctx->len += len;
}

static inline void zsipos_sha1_final(ZSIPOS_SHA1_CTX *ctx)
{
	uint32_t i;
	uint64_t bits;
	uint32_t shift;

	add_byte(ctx, 0x80);
	while ((ctx->wordlen + (ctx->blocklen * 4)) != 56)
		add_byte(ctx, 0x00);
	bits = ctx->len * 8;
	shift = 56;
	for (i = 0; i < 8; i++) {
		add_byte(ctx, (bits >> shift) & 0xff);
		shift -= 8;
	}
	for (i = 0; i < 5; i++) {
		ctx->digest[i] = swsha1[ADDR_DIGEST+i];
		int o = 4 * i;
		ctx->final[o+0] = (ctx->digest[i] >> 24) & 0xff;
		ctx->final[o+1] = (ctx->digest[i] >> 16) & 0xff;
		ctx->final[o+2] = (ctx->digest[i] >>  8) & 0xff;
		ctx->final[o+3] = ctx->digest[i] & 0xff;
	}
}

static int32_t hmacSha1Init(hmacSha1Context *ctx, const uint8_t *key, uint64_t kLength)
{
    ZSIPOS_HMAC_CTX *pctx = (ZSIPOS_HMAC_CTX*)ctx;
    uint32_t         i;
    uint8_t          localKey[SHA1_BLOCK_SIZE] = {0};
    uint8_t          localPad[SHA1_BLOCK_SIZE] = {0};

    if (!zsipos_sha1_hw_init())
    	return 0;

    memset(pctx, 0, sizeof(ZSIPOS_HMAC_CTX));

    if (kLength > SHA1_BLOCK_SIZE) {
    	zsipos_sha1_init(&pctx->shactx);
    	zsipos_sha1_update(&pctx->shactx, key, kLength);
    	zsipos_sha1_final(&pctx->shactx);
    	memcpy(localKey, pctx->shactx.final, SHA1_DIGEST_SIZE);
    } else {
    	memcpy(localKey, key, kLength);
    }
    /* prepare outer hash and hold the context */
	for (i = 0; i < SHA1_BLOCK_SIZE; i++)
		localPad[i] = 0x5c ^ localKey[i];
    zsipos_sha1_init(&pctx->outctx);
    zsipos_sha1_update(&pctx->outctx, localPad, SHA1_BLOCK_SIZE);
    for (i = 0; i < 5; i++)
    	pctx->outctx.digest[i] = swsha1[ADDR_DIGEST+i];

    /* prepare inner hash and hold the context */
    for (i = 0; i < SHA1_BLOCK_SIZE; i++)
    	localPad[i] = 0x36 ^ localKey[i];
    zsipos_sha1_init(&pctx->shactx);
    zsipos_sha1_update(&pctx->shactx, localPad, SHA1_BLOCK_SIZE);
    for (i = 0; i < 5; i++)
    	pctx->shactx.digest[i] = swsha1[ADDR_DIGEST+i];
    pctx->inictx = pctx->shactx;

	return 1;
}

static void hmacSha1Reset(hmacSha1Context *ctx)
{
    ZSIPOS_HMAC_CTX *pctx = (ZSIPOS_HMAC_CTX*)ctx;
    int              i;

    /* copy prepared inner hash to work hash context */
    pctx->shactx = pctx->inictx;
	for (i = 0; i < 5; i++)
		swsha1[ADDR_DIGEST+i] = pctx->shactx.digest[i];
}

static void hmacSha1Update(hmacSha1Context *ctx, const uint8_t *data, uint64_t dLength)
{
    ZSIPOS_HMAC_CTX *pctx = (ZSIPOS_HMAC_CTX*)ctx;

    /* hash new data to work hash context */
    zsipos_sha1_update(&pctx->shactx, data, dLength);
}

static void hmacSha1Final(hmacSha1Context *ctx, uint8_t *mac)
{
    ZSIPOS_HMAC_CTX *pctx = (ZSIPOS_HMAC_CTX*)ctx;
    uint8_t          tmpDigest[SHA1_DIGEST_SIZE];
    int              i;

    /* finalize work hash context */
    zsipos_sha1_final(&pctx->shactx);
    memcpy(tmpDigest, pctx->shactx.final, SHA1_DIGEST_SIZE);

    /* copy prepared outer hash to work hash */
    pctx->shactx = pctx->outctx;
	for (i = 0; i < 5; i++)
		swsha1[ADDR_DIGEST+i] = pctx->shactx.digest[i];

    /* hash inner digest to work (outer) hash context */
    zsipos_sha1_update(&pctx->shactx, (uint8_t*)tmpDigest, SHA1_DIGEST_SIZE);

    /* finalize work hash context to get the hmac*/
    zsipos_sha1_final(&pctx->shactx);
    memcpy(mac, pctx->shactx.final, SHA1_DIGEST_SIZE);
}

void hmac_sha1(const uint8_t *key, uint64_t keyLength, const uint8_t* data, uint32_t dataLength, uint8_t* mac, int32_t* macLength)
{
    hmacSha1Context ctx = {};

    pthread_mutex_lock(&swsha1_mutex);

    hmacSha1Init(&ctx, key, keyLength);
    hmacSha1Update(&ctx, data, dataLength);
    hmacSha1Final(&ctx, mac);
    *macLength = SHA1_BLOCK_SIZE;

    pthread_mutex_unlock(&swsha1_mutex);
}

void hmac_sha1(const uint8_t* key, uint64_t keyLength,
               const std::vector<const uint8_t*>& data,
               const std::vector<uint64_t>& dataLength,
               uint8_t* mac, uint32_t* macLength )
{
    hmacSha1Context ctx = {};

    pthread_mutex_lock(&swsha1_mutex);

    hmacSha1Init(&ctx, key, keyLength);

    for (size_t i = 0, size = data.size(); i < size; i++) {
        hmacSha1Update(&ctx, data[i], dataLength[i]);
    }
    hmacSha1Final(&ctx, mac);
    *macLength = SHA1_BLOCK_SIZE;

    pthread_mutex_unlock(&swsha1_mutex);
}

void* createSha1HmacContext(const uint8_t* key, uint64_t keyLength)
{
    auto *ctx = reinterpret_cast<hmacSha1Context*>(malloc(sizeof(hmacSha1Context)));
    if (ctx == nullptr)
        return nullptr;

    pthread_mutex_lock(&swsha1_mutex);

    hmacSha1Init(ctx, key, keyLength);

    pthread_mutex_unlock(&swsha1_mutex);

    return ctx;
}

void* initializeSha1HmacContext(void* ctx, uint8_t* key, uint64_t keyLength)
{
    auto *pctx = (hmacSha1Context*)ctx;

    pthread_mutex_lock(&swsha1_mutex);

    hmacSha1Init(pctx, key, keyLength);

    pthread_mutex_unlock(&swsha1_mutex);

    return pctx;
}

void hmacSha1Ctx(void* ctx, const uint8_t* data, uint64_t dataLength,
                uint8_t* mac, uint32_t* macLength)
{
    auto *pctx = (hmacSha1Context*)ctx;

    pthread_mutex_lock(&swsha1_mutex);

    hmacSha1Reset(pctx);
    hmacSha1Update(pctx, data, dataLength);
    hmacSha1Final(pctx, mac);
    *macLength = SHA1_BLOCK_SIZE;

    pthread_mutex_unlock(&swsha1_mutex);
}

void hmacSha1Ctx(void* ctx,
                 const std::vector<const uint8_t*>& data,
                 const std::vector<uint64_t>& dataLength,
                 uint8_t* mac, uint32_t* macLength )
{
    auto *pctx = (hmacSha1Context*)ctx;

    pthread_mutex_lock(&swsha1_mutex);

    hmacSha1Reset(pctx);
    for (size_t i = 0, size = data.size(); i < size; i++) {
        hmacSha1Update(pctx, data[i], dataLength[i]);
    }
    hmacSha1Final(pctx, mac);
    *macLength = SHA1_BLOCK_SIZE;

    pthread_mutex_unlock(&swsha1_mutex);
}

void freeSha1HmacContext(void* ctx)
{
    if (ctx) {
        memset(ctx, 0, sizeof(hmacSha1Context));
        free(ctx);
    }
}

#else

static int32_t hmacSha1Init(hmacSha1Context *ctx, const uint8_t *key, uint64_t kLength)
{
    int32_t i;
    uint8_t localPad[SHA1_BLOCK_SIZE] = {0};
    uint8_t localKey[SHA1_BLOCK_SIZE] = {0};

    if (key == nullptr)
        return 0;

    memset(ctx, 0, sizeof(hmacSha1Context));

    /* check key length and reduce it if necessary */
    if (kLength > SHA1_BLOCK_SIZE) {
        sha1_begin(&ctx->ctx);
        sha1_hash(key, kLength, &ctx->ctx);
        sha1_end(localKey, &ctx->ctx);
    }
    else {
        memcpy(localKey, key, kLength);
    }
    /* prepare inner hash and hold the context */
    for (i = 0; i < SHA1_BLOCK_SIZE; i++)
        localPad[i] = static_cast<uint_8t >(localKey[i] ^ 0x36);

    sha1_begin(&ctx->innerCtx);
    sha1_hash(localPad, SHA1_BLOCK_SIZE, &ctx->innerCtx);

    /* prepare outer hash and hold the context */
    for (i = 0; i < SHA1_BLOCK_SIZE; i++)
        localPad[i] = static_cast<uint_8t >(localKey[i] ^ 0x5c);

    sha1_begin(&ctx->outerCtx);
    sha1_hash(localPad, SHA1_BLOCK_SIZE, &ctx->outerCtx);

    /* copy prepared inner hash to work hash - ready to process data */
    memcpy(&ctx->ctx, &ctx->innerCtx, sizeof(sha1_ctx));

    memset(localKey, 0, sizeof(localKey));

    return 1;
}

static void hmacSha1Reset(hmacSha1Context *ctx)
{
    /* copy prepared inner hash to work hash context */
    memcpy(&ctx->ctx, &ctx->innerCtx, sizeof(sha1_ctx));
}

static void hmacSha1Update(hmacSha1Context *ctx, const uint8_t *data, uint64_t dLength)
{
    /* hash new data to work hash context */
    sha1_hash(data, dLength, &ctx->ctx);
}

static void hmacSha1Final(hmacSha1Context *ctx, uint8_t *mac)
{
    uint8_t tmpDigest[SHA1_DIGEST_SIZE];

    /* finalize work hash context */
    sha1_end(tmpDigest, &ctx->ctx);

    /* copy prepared outer hash to work hash */
    memcpy(&ctx->ctx, &ctx->outerCtx, sizeof(sha1_ctx));

    /* hash inner digest to work (outer) hash context */
    sha1_hash(tmpDigest, SHA1_DIGEST_SIZE, &ctx->ctx);

    /* finalize work hash context to get the hmac*/
    sha1_end(mac, &ctx->ctx);
}

void hmac_sha1(const uint8_t *key, uint64_t keyLength, const uint8_t* data, uint32_t dataLength, uint8_t* mac, int32_t* macLength)
{
    hmacSha1Context ctx = {};

    hmacSha1Init(&ctx, key, keyLength);
    hmacSha1Update(&ctx, data, dataLength);
    hmacSha1Final(&ctx, mac);
    *macLength = SHA1_BLOCK_SIZE;
}

void hmac_sha1(const uint8_t* key, uint64_t keyLength,
               const std::vector<const uint8_t*>& data,
               const std::vector<uint64_t>& dataLength,
               uint8_t* mac, uint32_t* macLength )
{
    hmacSha1Context ctx = {};

    hmacSha1Init(&ctx, key, keyLength);

    for (size_t i = 0, size = data.size(); i < size; i++) {
        hmacSha1Update(&ctx, data[i], dataLength[i]);
    }
    hmacSha1Final(&ctx, mac);
    *macLength = SHA1_BLOCK_SIZE;
}

void* createSha1HmacContext(const uint8_t* key, uint64_t keyLength)
{
    auto *ctx = reinterpret_cast<hmacSha1Context*>(malloc(sizeof(hmacSha1Context)));
    if (ctx == nullptr)
        return nullptr;

    hmacSha1Init(ctx, key, keyLength);
    return ctx;
}

void* initializeSha1HmacContext(void* ctx, uint8_t* key, uint64_t keyLength)
{
    auto *pctx = (hmacSha1Context*)ctx;

    hmacSha1Init(pctx, key, keyLength);
    return pctx;
}

void hmacSha1Ctx(void* ctx, const uint8_t* data, uint64_t dataLength,
                uint8_t* mac, uint32_t* macLength)
{
    auto *pctx = (hmacSha1Context*)ctx;

    hmacSha1Reset(pctx);
    hmacSha1Update(pctx, data, dataLength);
    hmacSha1Final(pctx, mac);
    *macLength = SHA1_BLOCK_SIZE;
}

void hmacSha1Ctx(void* ctx,
                 const std::vector<const uint8_t*>& data,
                 const std::vector<uint64_t>& dataLength,
                 uint8_t* mac, uint32_t* macLength )
{
    auto *pctx = (hmacSha1Context*)ctx;

    hmacSha1Reset(pctx);
    for (size_t i = 0, size = data.size(); i < size; i++) {
        hmacSha1Update(pctx, data[i], dataLength[i]);
    }
    hmacSha1Final(pctx, mac);
    *macLength = SHA1_BLOCK_SIZE;
}

void freeSha1HmacContext(void* ctx)
{
    if (ctx) {
        memset(ctx, 0, sizeof(hmacSha1Context));
        free(ctx);
    }
}

#endif

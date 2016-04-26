/* The MIT License

   Copyright (C) 2011 Zilong Tan (tzlloch@gmail.com)
   Copyright (C) 2016 Matthias Schiffer (mschiffer@universe-factory.net)

   Permission is hereby granted, free of charge, to any person obtaining
   a copy of this software and associated documentation files (the
   "Software"), to deal in the Software without restriction, including
   without limitation the rights to use, copy, modify, merge, publish,
   distribute, sublicense, and/or sell copies of the Software, and to
   permit persons to whom the Software is furnished to do so, subject to
   the following conditions:

   The above copyright notice and this permission notice shall be
   included in all copies or substantial portions of the Software.

   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
   EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
   MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
   NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
   BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
   ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
   CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
   SOFTWARE.
*/
#pragma once

#include <stddef.h>
#include <stdint.h>

/** The number of bytes in a SHA256 hash */
#define ECDSA_SHA256_HASH_SIZE 32	/* 256 bit */

/** The number of bytes in a HMAC-SHA256 key */
#define ECDSA_HMAC_SHA256_KEY_SIZE 32

/** SHA256 computation context */
typedef struct _ecdsa_sha256_context {
	uint64_t totalLength;
	uint32_t hash[ECDSA_SHA256_HASH_SIZE/4];
	uint32_t bufferLength;
	union {
		uint32_t words[16];
		uint8_t bytes[64];
	} buffer;
} ecdsa_sha256_context_t;

/** Initializes a \ref ecdsa_sha256_context_t */
void ecdsa_sha256_init(ecdsa_sha256_context_t *sc);

/** Adds data to the given \ref ecdsa_sha256_context_t */
void ecdsa_sha256_update(ecdsa_sha256_context_t *sc, const void *data, size_t len);

/** Finalizes and outputs a SHA256 hash */
void ecdsa_sha256_final(ecdsa_sha256_context_t *sc, uint8_t hash[ECDSA_SHA256_HASH_SIZE]);


/** Computes the HMAC-SHA256 for a block of data */
void ecdsa_sha256_hmac(uint8_t mac[ECDSA_SHA256_HASH_SIZE], const uint8_t key[ECDSA_HMAC_SHA256_KEY_SIZE], const void *data, size_t len);

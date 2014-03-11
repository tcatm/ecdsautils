/*
  Copyright (c) 2014, Matthias Schiffer <mschiffer@universe-factory.net>
  All rights reserved.

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions are met:

    1. Redistributions of source code must retain the above copyright notice,
       this list of conditions and the following disclaimer.
    2. Redistributions in binary form must reproduce the above copyright notice,
       this list of conditions and the following disclaimer in the documentation
       and/or other materials provided with the distribution.

  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
  DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
  FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
  DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
  CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
  OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include "hmac_sha256.h"


#define BLOCKSIZE 64


void hmac_sha256(uint8_t mac[SHA256_HASH_SIZE], const uint8_t key[HMAC_SHA256_KEY_SIZE], const void *data, size_t len) {
  uint8_t okey[BLOCKSIZE], ikey[BLOCKSIZE];
  uint8_t tmp[SHA256_HASH_SIZE];
  SHA256Context ctx;
  size_t i;

  for (i = 0; i < HMAC_SHA256_KEY_SIZE; i++) {
    okey[i] = key[i] ^ 0x5c;
    ikey[i] = key[i] ^ 0x36;
  }
  for (i = HMAC_SHA256_KEY_SIZE; i < BLOCKSIZE; i++) {
    okey[i] = 0x5c;
    ikey[i] = 0x36;
  }

  SHA256Init(&ctx);
  SHA256Update(&ctx, ikey, BLOCKSIZE);
  SHA256Update(&ctx, data, len);
  SHA256Final(&ctx, tmp);

  SHA256Init(&ctx);
  SHA256Update(&ctx, okey, BLOCKSIZE);
  SHA256Update(&ctx, tmp, SHA256_HASH_SIZE);
  SHA256Final(&ctx, mac);
}

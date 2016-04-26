/*
  Copyright (c) 2012, Nils Schneider <nils@nilsschneider.net>
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

#include <string.h>
#include <libuecc/ecc.h>

#include "random.h"
#include "ecdsa.h"

int ecdsa_new_secret(ecc_int256_t *secret) {
  if (!random_bytes(secret->p, 32))
    return 0;

  ecc_25519_gf_sanitize_secret(secret, secret);

  return 1;
}

void ecdsa_public_from_secret(ecc_int256_t *pub, const ecc_int256_t *secret) {
  ecc_25519_work_t work;
  ecc_25519_scalarmult_base(&work, secret);
  ecc_25519_store_packed_legacy(pub, &work);
}

int ecdsa_is_valid_pubkey(const ecc_25519_work_t *pubkey) {
  ecc_25519_work_t work;

  // q * pubkey should be identity element
  ecc_25519_scalarmult(&work, &ecc_25519_gf_order, pubkey);

  return ecc_25519_is_identity(&work) && !ecc_25519_is_identity(pubkey);
}

void ecdsa_split_signature(ecc_int256_t *r, ecc_int256_t *s, const unsigned char *signature) {
  memcpy(r->p, signature, 32);
  memcpy(s->p, signature+32, 32);
}

void ecdsa_verify_prepare(ecdsa_verify_context *ctx, const ecc_int256_t *hash, const unsigned char *signature) {
  ecc_int256_t tmp, w, u1;

  ecdsa_split_signature(&ctx->r, &tmp, signature);
  ecc_25519_gf_recip(&w, &tmp);

  ecc_25519_gf_reduce(&tmp, hash);

  ecc_25519_gf_mult(&u1, &tmp, &w);
  ecc_25519_gf_mult(&ctx->u2, &ctx->r, &w);

  ecc_25519_scalarmult_base(&ctx->s1, &u1);
}

int ecdsa_verify_with_pubkey(const ecdsa_verify_context *ctx, const ecc_25519_work_t *pubkey) {
  ecc_25519_work_t s2, work;
  ecc_int256_t w, tmp;

  ecc_25519_scalarmult(&s2, &ctx->u2, pubkey);
  ecc_25519_add(&work, &ctx->s1, &s2);
  ecc_25519_store_xy_legacy(&w, NULL, &work);
  ecc_25519_gf_sub(&tmp, &ctx->r, &w);

  return ecc_25519_gf_is_zero(&tmp);
}

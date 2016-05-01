/*
  Copyright (c) 2012, Nils Schneider <nils@nilsschneider.net>
  Copyright (c) 2016, Matthias Schiffer <mschiffer@universe-factory.net>
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

#pragma once


#include <libuecc/ecc.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>


/** Canonical representation of a ECDSA signature */
typedef struct _ecdsa_signature {
  ecc_int256_t r;
  ecc_int256_t s;
} ecdsa_signature_t;

/** Representation of a hash and signature for efficient checking against multiple public keys */
typedef struct _ecdsa_verify_context {
  ecc_25519_work_t s1;
  ecc_int256_t u2;
  ecc_int256_t r;
} ecdsa_verify_context_t;


/** Checks if a unpacked public key is valid */
bool ecdsa_is_valid_pubkey(const ecc_25519_work_t *pubkey);

/**
 * Signs a hash value using a given secret key
 *
 * The signature is deterministic, so using the same secret key to sign the same hash will always
 * yield the same value (using the same libecdsautil version).
 *
 * This function uses libuecc's legacy curve representation.
 */
void ecdsa_sign_legacy(ecdsa_signature_t *signature, const ecc_int256_t *hash, const ecc_int256_t *secret);


/**
 * Prepares a signature for a given hash for efficient validation
 *
 * This function uses libuecc's legacy curve representation.
 */
void ecdsa_verify_prepare_legacy(ecdsa_verify_context_t *ctx, const ecc_int256_t *hash, const ecdsa_signature_t *signature);

/**
 * Verifies a signature against a given public key
 *
 * This function uses libuecc's legacy curve representation.
 */
bool ecdsa_verify_legacy(const ecdsa_verify_context_t *ctx, const ecc_25519_work_t *pubkey);

/**
 * Verifies multiple signatures against a list of public keys and returns the number of valid signatures for distinct keys
 *
 * The caller must ensure that the given list of public keys does not contain duplicates.
 *
 * This function uses libuecc's legacy curve representation.
 */
size_t ecdsa_verify_list_legacy(const ecdsa_verify_context_t *ctxs, size_t n_ctxs, const ecc_25519_work_t *pubkeys, size_t n_pubkeys);

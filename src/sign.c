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

#include <error.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <libuecc/ecc.h>

#include "hexutil.h"
#include "ecdsa.h"
#include "hmac_sha256.h"
#include "sha256_file.h"

/**
 * Performs the first expansion step of HKDF-SHA256 (RFC 5869)
 * (the extraction step is skipped as the secret key is already
 * a uniformly random string, with the exception of the five bits
 * ecc_25519_gf_sanitize_secret sets and clears)
 */
static void generate_k(uint8_t *k, const uint8_t prk[32], const uint8_t info[32]) {
  uint8_t input[33];
  memcpy(input, info, 32);
  input[32] = 0x01;

  hmac_sha256(k, prk, input, sizeof(input));
}

int main(int argc, char *argv[]) {
  ecc_int256_t secret, hash, k, krecip, r, s, tmp;
  ecc_25519_work_t kG;

  if (argc != 2)
    error(1, 0, "Usage: %s file (secret is read from stdin)", argv[0]);

  if (!sha256_file(argv[1], tmp.p))
    error(1, 0, "Error while hashing file");

  char secret_string[65];

  if (fgets(secret_string, sizeof(secret_string), stdin) == NULL)
    error(1, 0, "Error reading secret");

  if (!parsehex(secret.p, secret_string, 32))
    error(1, 0, "Error reading secret");

  // Reduce hash (instead of clearing 3 bits)
  ecc_25519_gf_reduce(&hash, &tmp);

  // Generate k
  generate_k(k.p, secret.p, tmp.p);
  ecc_25519_gf_sanitize_secret(&k, &k);

  // calculate k^(-1)
  ecc_25519_gf_recip(&krecip, &k);

  // calculate kG = k * base point
  ecc_25519_scalarmult_base(&kG, &k);

  // store x coordinate of kG in r
  ecc_25519_store_xy(&tmp, NULL, &kG);
  ecc_25519_gf_reduce(&r, &tmp);

  if (ecc_25519_gf_is_zero(&r))
    error(1, 0, "Error: r is zero (this should never happen)");

  // tmp = r * secret
  ecc_25519_gf_mult(&tmp, &r, &secret);

  // s = hash + tmp = hash + r * secret
  ecc_25519_gf_add(&s, &hash, &tmp);

  // tmp = krecip * s = k^(-1) * s
  ecc_25519_gf_mult(&tmp, &krecip, &s);

  // mod n (order of G)
  ecc_25519_gf_reduce(&s, &tmp);

  if (ecc_25519_gf_is_zero(&s))
    error(1, 0, "Error: s is zero (this should never happen)");

  hexdump(stdout, r.p, 32);
  hexdump(stdout, s.p, 32);
  puts("");

  return 0;
}

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

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <libuecc/ecc.h>

#include "sign.h"
#include "error.h"
#include "hexutil.h"
#include "ecdsa.h"
#include "hmac_sha256.h"
#include "sha256_file.h"


// Generate k according to RFC6979 (Deterministic DSA/ECDSA)

static void generate_k_prepare(uint8_t V[32], uint8_t K[32], const uint8_t x[32], const uint8_t m[32]) {
  memset(V, 0x01, 32); // b.
  memset(K, 0x00, 32); // c.

  {
    uint8_t input[32+1+32+32];
    memcpy(input, V, 32);
    input[32] = 0x00;
    memcpy(input+32+1, x, 32);
    memcpy(input+32+1+32, m, 32);
    hmac_sha256(K, K, input, sizeof(input)); // d.
  }

  hmac_sha256(V, K, V, 32); // e.

  {
    uint8_t input[32+1+32+32];
    memcpy(input, V, 32);
    input[32] = 0x01;
    memcpy(input+32+1, x, 32);
    memcpy(input+32+1+32, m, 32);
    hmac_sha256(K, K, input, sizeof(input)); // f.
  }

  hmac_sha256(V, K, V, 32); // g.
}

static void generate_k(uint8_t k[32], uint8_t V[32], uint8_t K[32]) {
  // h.
  // Note that T = V, as qlen = hlen
  hmac_sha256(V, K, V, 32);
  memcpy(k, V, 32);

  // The following steps are preparation for the next iteration (in case the generated k is invalid)
  {
    uint8_t input[32+1];
    memcpy(input, V, 32);
    input[32] = 0x00;
    hmac_sha256(K, K, input, sizeof(input));
  }
  hmac_sha256(V, K, V, 32);
}

void sign(const char *command, int argc, char **argv) {
  ecc_int256_t secret, hash, k, krecip, r, s, tmp;
  ecc_25519_work_t kG;
  uint8_t V[32], K[32];

  if (argc != 2)
    exit_error(1, 0, "Usage: %s file (secret is read from stdin)", command);

  if (!sha256_file(argv[1], tmp.p))
    exit_error(1, 0, "Error while hashing file");

  char secret_string[65];

  if (fgets(secret_string, sizeof(secret_string), stdin) == NULL)
    exit_error(1, 0, "Error reading secret");

  if (!parsehex(secret.p, secret_string, 32))
    exit_error(1, 0, "Error reading secret");

  // Reduce hash (instead of clearing 3 bits)
  ecc_25519_gf_reduce(&hash, &tmp);

  // Generate k
  generate_k_prepare(V, K, secret.p, tmp.p);

regenerate:
  generate_k(k.p, V, K);
  ecc_25519_gf_sanitize_secret(&k, &k);

  // calculate k^(-1)
  ecc_25519_gf_recip(&krecip, &k);

  // calculate kG = k * base point
  ecc_25519_scalarmult(&kG, &k, &ecc_25519_work_base_legacy);

  // store x coordinate of kG in r
  ecc_25519_store_xy_legacy(&tmp, NULL, &kG);
  ecc_25519_gf_reduce(&r, &tmp);

  if (ecc_25519_gf_is_zero(&r))
    goto regenerate;

  // tmp = r * secret
  ecc_25519_gf_mult(&tmp, &r, &secret);

  // s = hash + tmp = hash + r * secret
  ecc_25519_gf_add(&s, &hash, &tmp);

  // tmp = krecip * s = k^(-1) * s
  ecc_25519_gf_mult(&tmp, &krecip, &s);

  // mod n (order of G)
  ecc_25519_gf_reduce(&s, &tmp);

  if (ecc_25519_gf_is_zero(&s))
    goto regenerate;

  hexdump(stdout, r.p, 32);
  hexdump(stdout, s.p, 32);
  puts("");
}

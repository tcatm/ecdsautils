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
#include <string.h>
#include <stdlib.h>
#include <libuecc/ecc.h>

#include "hexutil.h"

int is_valid_pubkey(ecc_25519_work *pubkey) {
  ecc_25519_work work;

  // q * pubkey should be identity element
  ecc_25519_scalarmult(&work, &ecc_25519_gf_order, pubkey);

  // FIXME: Check whether pubkey lies on curve?
  //        If the point was unpacked, it is guaranteed to
  //        lie on the curve.
  return ecc_25519_is_identity(&work) && !ecc_25519_is_identity(pubkey);
}

int main(int argc, char *argv[]) {
  unsigned char signature[64];
  ecc_int_256 pubkey_packed, r, s, hash, tmp, w, u1, u2;
  ecc_25519_work pubkey, work, s1, s2;

  if (argc != 4)
    error(1, 0, "Usage: %s pubkey signature hash", argv[0]);

  if (!parsehex(pubkey_packed.p, argv[1], 32))
    error(1, 0, "Error while reading pubkey");

  if (!parsehex(signature, argv[2], 64))
    error(1, 0, "Error while reading signature");

  if (!parsehex(hash.p, argv[3], 32))
    error(1, 0, "Error while reading hash");

  memcpy(r.p, signature, 32);
  memcpy(s.p, signature+32, 32);

  // hash must have only 253 significant bits!
  hash.p[31] &= 0x1f;

  ecc_25519_load_packed(&pubkey, &pubkey_packed);

  if (!is_valid_pubkey(&pubkey))
    error(1, 0, "Invalid pubkey");

  ecc_25519_gf_recip(&w, &s);
  ecc_25519_gf_mult(&u1, &hash, &w);
  ecc_25519_gf_mult(&u2, &r, &w);

  ecc_25519_scalarmult_base(&s1, &u1);
  ecc_25519_scalarmult(&s2, &u2, &pubkey);

  ecc_25519_add(&work, &s1, &s2);

  ecc_25519_store_xy(&w, NULL, &work);

  ecc_25519_gf_sub(&tmp, &r, &w);

  if (!ecc_25519_gf_is_zero(&tmp))
    error(1, 0, "Invalid signature");

  puts("Signature is valid");

  return 0;
}

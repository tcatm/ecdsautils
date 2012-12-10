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

#include <libuecc/ecc.h>

#include "random.h"

int ecdsa_new_secret(ecc_int_256 *secret) {
  if (!random_bytes(secret->p, 32))
    return 0;

  ecc_25519_gf_sanitize_secret(secret, secret);

  return 1;
}

void ecdsa_public_from_secret(ecc_int_256 *pub, ecc_int_256 *secret) {
  ecc_25519_work work;
  ecc_25519_scalarmult_base(&work, secret);
  ecc_25519_store_packed(pub, &work);
}

int is_valid_pubkey(ecc_25519_work *pubkey) {
  ecc_25519_work work;

  // q * pubkey should be identity element
  ecc_25519_scalarmult(&work, &ecc_25519_gf_order, pubkey);

  // FIXME: Check whether pubkey lies on curve?
  //        If the point was unpacked, it is guaranteed to
  //        lie on the curve.
  return ecc_25519_is_identity(&work) && !ecc_25519_is_identity(pubkey);
}

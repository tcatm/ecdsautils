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
#include "sha256_file.h"
#include "ecdsa.h"

int main(int argc, char *argv[]) {
  unsigned char signature[64];
  ecdsa_verify_context ctx;
  ecc_int_256 pubkey_packed, tmp;
  ecc_25519_work pubkey;

  if (argc < 4)
    error(1, 0, "Usage: %s file signature pubkey1 [pubkey2 ...]", argv[0]);

  if (!sha256_file(argv[1], tmp.p))
    error(1, 0, "Error while hashing file");

  if (!parsehex(signature, argv[2], 64))
    error(1, 0, "Error while reading signature");


  ecdsa_verify_prepare(&ctx, &tmp, signature);

  for (int i = 3; i < argc; i++) {
    char *pubkey_string = argv[i];

    if (!parsehex(pubkey_packed.p, pubkey_string, 32)) {
      fprintf(stderr, "Error while reading pubkey %s\n", pubkey_string);
      continue;
    }

    ecc_25519_load_packed(&pubkey, &pubkey_packed);

    if (!ecdsa_is_valid_pubkey(&pubkey)) {
      fprintf(stderr, "Invalid pubkey %s\n", pubkey_string);
      continue;
    }

    if (ecdsa_verify_with_pubkey(&ctx, &pubkey)) {
      printf("Signature verified by %s\n", pubkey_string);
      exit(0);
    }
  }

  fprintf(stderr, "None of the supplied public keys could be used to verify the signature\n");

  return 1;
}

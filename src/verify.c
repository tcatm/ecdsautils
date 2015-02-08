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
#include <string.h>
#include <stdlib.h>
#include <getopt.h>
#include <assert.h>
#include <libuecc/ecc.h>

#include "hexutil.h"
#include "sha256_file.h"
#include "ecdsa.h"
#include "array.h"

int main(int argc, char *argv[]) {
  unsigned char signature[64];

  array pubkeys, signatures;
  array_init(&pubkeys, sizeof(ecc_25519_work_t), 5);
  array_init(&signatures, sizeof(signature), 5);

  int min_good_signatures = 1;

  int opt;
  while ((opt = getopt(argc, argv, "s:p:n:")) != -1) {
    ecc_int256_t pubkey_packed;
    ecc_25519_work_t pubkey;

    switch (opt) {
      case 's':
        if (!parsehex(signature, optarg, 64)) {
          fprintf(stderr, "Error while reading signature %s\n", optarg);
          break;
        }

        if (!array_add(&signatures, signature, sizeof(signature))) {
          fprintf(stderr, "Error in array_add\n");
          goto error_out;
        }
        break;
      case 'p':
        if (!parsehex(pubkey_packed.p, optarg, 32)) {
          fprintf(stderr, "Error while reading pubkey %s\n", optarg);
          break;
        }

        int ret;

        ret = ecc_25519_load_packed(&pubkey, &pubkey_packed);

        if (!ret || !ecdsa_is_valid_pubkey(&pubkey)) {
          fprintf(stderr, "Invalid pubkey %s\n", optarg);
          break;
        }

        if (!array_add(&pubkeys, &pubkey, sizeof(ecc_25519_work_t))) {
          fprintf(stderr, "Error in array_add\n");
          goto error_out;
        }
        break;
      case 'n':
        min_good_signatures = atoi(optarg);
    }
  }

  if (optind > argc) {
    fprintf(stderr, "Usage: %s [-s signature ...] [-p pubkey ...] [-n num] file\n", argv[0]);
    goto error_out;
  }

  ecc_int256_t hash;

  if (!sha256_file((optind <= argc) ? argv[optind] : NULL, hash.p)) {
    fprintf(stderr, "Error while hashing file\n");
    goto error_out;
  }

  int good_signatures = 0;

  array_nub(&pubkeys);
  array_nub(&signatures);

  for (int i = 0; i < signatures.size; i++) {
    unsigned char *signature;
    ecdsa_verify_context ctx;

    signature = ARRAY_INDEX(signatures, i);

    ecdsa_verify_prepare(&ctx, &hash, signature);

    for (int i = 0; i < pubkeys.size; i++) {
      ecc_25519_work_t *pubkey;
      pubkey = ARRAY_INDEX(pubkeys, i);

      if (ecdsa_verify_with_pubkey(&ctx, pubkey)) {
        good_signatures++;
        array_rm(&pubkeys, i);
        break;
      }
    }
  }

  array_destroy(&pubkeys);
  array_destroy(&signatures);

  if (good_signatures >= min_good_signatures)
    return 0;

  return 1;

error_out:
  array_destroy(&pubkeys);
  array_destroy(&signatures);
  return 1;
}

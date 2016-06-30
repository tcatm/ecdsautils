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

#include "hexutil.h"
#include "set.h"
#include "sha256_file.h"
#include "verify.h"

#include <ecdsautil/ecdsa.h>

#include <stdio.h>
#include <getopt.h>


int verify(const char *command, int argc, char **argv) {
  int ret = 1;
  unsigned char signature[sizeof(ecdsa_signature_t)];

  set pubkeys, signatures;
  set_init(&pubkeys, sizeof(ecc_25519_work_t), 5);
  set_init(&signatures, sizeof(signature), 5);

  size_t min_good_signatures = 1;

  int opt;
  while ((opt = getopt(argc, argv, "s:p:n:")) != -1) {
    ecc_int256_t pubkey_packed;
    ecc_25519_work_t pubkey;

    switch (opt) {
      case 's':
        if (!parsehex(signature, optarg, sizeof(signature))) {
          fprintf(stderr, "Error while reading signature %s\n", optarg);
          break;
        }

        if (!set_add(&signatures, signature)) {
          fprintf(stderr, "Error in array_add\n");
          goto out;
        }
        break;
      case 'p':
        if (!parsehex(pubkey_packed.p, optarg, 32)) {
          fprintf(stderr, "Error while reading pubkey %s\n", optarg);
          break;
        }

        int ok = ecc_25519_load_packed_legacy(&pubkey, &pubkey_packed);
        if (!ok || !ecdsa_is_valid_pubkey(&pubkey)) {
          fprintf(stderr, "Invalid pubkey %s\n", optarg);
          break;
        }

        if (!set_add(&pubkeys, &pubkey)) {
          fprintf(stderr, "Error in array_add\n");
          goto out;
        }
        break;
      case 'n':
        min_good_signatures = atoi(optarg);
    }
  }

  if (optind > argc || pubkeys.size == 0 || signatures.size == 0) {
    fprintf(stderr, "Usage: %s [-s signature ...] [-p pubkey ...] [-n num] file\n", command);
    goto out;
  }

  ecc_int256_t hash;

  if (!sha256_file((optind <= argc) ? argv[optind] : NULL, hash.p)) {
    fprintf(stderr, "Error while hashing file\n");
    goto out;
  }

  {
    ecdsa_verify_context_t ctxs[signatures.size];
    for (size_t i = 0; i < signatures.size; i++)
      ecdsa_verify_prepare_legacy(&ctxs[i], &hash, SET_INDEX(signatures, i));

    size_t good_signatures = ecdsa_verify_list_legacy(ctxs, signatures.size, pubkeys.content, pubkeys.size);

    if (good_signatures >= min_good_signatures)
      ret = 0;
  }

out:
  set_destroy(&pubkeys);
  set_destroy(&signatures);
  return ret;
}

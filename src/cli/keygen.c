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

#include "error.h"
#include "hexutil.h"
#include "keygen.h"
#include "random.h"
#include "version.h"

#include <libuecc/ecc.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>


static int new_secret(ecc_int256_t *secret) {
  if (!random_bytes(secret->p, 32))
    return 0;

  ecc_25519_gf_sanitize_secret(secret, secret);

  return 1;
}

static void public_from_secret(ecc_int256_t *pub, const ecc_int256_t *secret) {
  ecc_25519_work_t work;
  ecc_25519_scalarmult_base(&work, secret);
  ecc_25519_store_packed_legacy(pub, &work);
}

static void output_key(ecc_int256_t *key) {
  hexdump(stdout, key->p, 32); puts("");
}

void show_key(void) {
  char secret_string[65];
  ecc_int256_t pubkey, secret;

  if (fgets(secret_string, sizeof(secret_string), stdin) == NULL)
    goto secret_error;

  if (!parsehex(secret.p, secret_string, 32))
    goto secret_error;

  public_from_secret(&pubkey, &secret);

  output_key(&pubkey);
  return;

secret_error:
  exit_error(1, 0, "Error reading secret");
}

void generate_key(void) {
  ecc_int256_t secret;

  if (!new_secret(&secret))
    exit_error(1, 0, "Unable to read random bytes");

  output_key(&secret);
}

static inline void usage(const char *command) {
  fprintf(stderr, "Usage: %s { -s | -p | -h }\n", command);
}

void keygen(const char *command, int argc, char **argv) {
  char c;

  while ((c = getopt(argc, argv, "sph")) != -1) {
    switch (c) {
      case 's':
        generate_key();
        return;

      case 'p':
        show_key();
        return;

      case 'h':
        usage(command);
        return;
    }
  }

  usage(command);
  exit(1);
}

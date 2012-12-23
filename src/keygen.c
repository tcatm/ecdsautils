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
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <libuecc/ecc.h>

#include "hexutil.h"
#include "ecdsa.h"

void output_key(ecc_int256_t *key) {
  hexdump(stdout, key->p, 32); puts("");
}

void show_pubkey() {
  char secret_string[65];
  ecc_int256_t pubkey, secret;

  if (fgets(secret_string, sizeof(secret_string), stdin) == NULL)
    goto secret_error;

  if (!parsehex(secret.p, secret_string, 32))
    goto secret_error;

  ecdsa_public_from_secret(&pubkey, &secret);

  output_key(&pubkey);
  return;

secret_error:
  error(1, 0, "Error reading secret");
  return;
}

void new_secret() {
  ecc_int256_t secret;

  if (!ecdsa_new_secret(&secret))
    error(1, 0, "Unable to read random bytes");

  output_key(&secret);
}

void usage(char *cmdname) {
  printf("Usage: %s [-s] [-p] [-h]\n", cmdname);
}

void help(char *cmdname) {
  usage(cmdname);
  puts("\t-s\tgenerate a new secret on stdout");
  puts("\t-p\toutput public key of secret read from stdin");
  puts("\t-h\tdisplay this short help and exit");
}

int main(int argc, char **argv) {
  char c;

  while ((c = getopt(argc, argv, "sph")) != -1) {
    switch (c) {
      case 's':
        new_secret();
        return 0;
      case 'p':
        show_pubkey();
        return 0;
      case 'h':
        help(argv[0]);
        return 0;
    }
  }

  usage(argv[0]);
  return 1;
}

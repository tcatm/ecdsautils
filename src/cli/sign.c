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

#include "sign.h"
#include "error.h"
#include "hexutil.h"
#include "sha256_file.h"

#include <ecdsautil/ecdsa.h>

#include <stdio.h>
#include <stdint.h>
#include <string.h>


void sign(const char *command, int argc, char **argv) {
  ecdsa_signature_t sig;
  ecc_int256_t secret, hash;

  if (argc != 2)
    exit_error(1, 0, "Usage: %s file (secret is read from stdin)", command);

  if (!sha256_file(argv[1], hash.p))
    exit_error(1, 0, "Error while hashing file");

  char secret_string[65];

  if (fgets(secret_string, sizeof(secret_string), stdin) == NULL)
    exit_error(1, 0, "Error reading secret");

  if (!parsehex(secret.p, secret_string, 32))
    exit_error(1, 0, "Error reading secret");

  ecdsa_sign_legacy(&sig, &hash, &secret);

  hexdump(stdout, sig.r.p, 32);
  hexdump(stdout, sig.s.p, 32);
  puts("");
}

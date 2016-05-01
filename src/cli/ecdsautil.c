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
#include "version.h"
#include "keygen.h"
#include "sign.h"
#include "verify.h"

#include <libgen.h>
#include <stdio.h>
#include <string.h>


void help(void) {
  print_version();
  puts("Usage: ecdsautil [help | generate-key | show-key | sign | verify]\n");
  puts("  help        \tshow this help");
  puts("  generate-key\tgenerate a new secret on stdout");
  puts("  show-key    \toutput public key of secret read from stdin");
  puts("  sign        \tsign file");
  puts("  verify      \tverify signature of file");
}

int main(int argc, char **argv) {
  if (argc >= 2) {
    if (strcmp(argv[1], "help") == 0) {
      help();
      return 0;
    } else if (strcmp(argv[1], "generate-key") == 0) {
      generate_key();
      return 0;
    } else if (strcmp(argv[1], "show-key") == 0) {
      show_key();
      return 0;
    } else if (strcmp(argv[1], "sign") == 0) {
      sign("ecdsautil sign", argc - 1, argv + 1);
      return 0;
    } else if (strcmp(argv[1], "verify") == 0) {
      return verify("ecdsautil verify", argc - 1, argv + 1);
    }
  }

  const char *command = basename(argv[0]);
  if (strcmp(command, "ecdsakeygen") == 0) {
    keygen("ecdsakeygen", argc, argv);
    return 0;
  } else if (strcmp(command, "ecdsasign") == 0) {
    sign("ecdsasign", argc, argv);
    return 0;
  } else if (strcmp(command, "ecdsaverify") == 0) {
    return verify("ecdsaverify", argc, argv);
  } else {
    help();
    return 1;
  }
}

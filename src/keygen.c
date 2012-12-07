/*
  Copyright (c) 2012, Nils Schneider <nils@nilsschneider.net>
  and Matthias Schiffer <mschiffer@universe-factory.net>
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
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>
#include <libuecc/ecc.h>

#include "hexutil.h"

void random_bytes(char *buffer, size_t len) {
  int fd;
  size_t read_bytes = 0;

  fd = open("/dev/random", O_RDONLY);

  if (fd < 0) {
    error(1, errno, "Can't open /dev/random");
  }

  while (read_bytes < len) {
    ssize_t ret = read(fd, buffer + read_bytes, len - read_bytes);

    if (ret < 0) {
      if (errno == EINTR)
        continue;

      error(1, errno, "Error while reading random bytes");
    }

    read_bytes += ret;
  }

  close(fd);
}

void main(void) {
  ecc_int_256 secret_key;
  ecc_int_256 public_key;

  random_bytes(secret_key.p, 32);

  ecc_25519_gf_sanitize_secret(&secret_key, &secret_key);

  ecc_25519_work work;
  ecc_25519_scalarmult_base(&work, &secret_key);
  ecc_25519_store(&public_key, &work);

  printf("Secret: "); hexdump(stdout, secret_key.p, 32); puts("");
  printf("Public: "); hexdump(stdout, public_key.p, 32); puts("");
}

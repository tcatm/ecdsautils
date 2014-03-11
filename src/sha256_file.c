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
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

#include "sha256sum.h"

#define BLOCKSIZE 64

int sha256_file(const char *fname, unsigned char *hash) {
  int fd;

  fd = open(fname, O_RDONLY);

  if (fd < 0) {
    fprintf(stderr, "Can't open file: %s\n", strerror(errno));
    goto out_error;
  }

  ssize_t ret;
  unsigned char buffer[BLOCKSIZE];
  SHA256Context ctx;

  SHA256Init(&ctx);

  while (1) {
    ret = read(fd, buffer, BLOCKSIZE);

    if (ret < 0) {
      if (errno == EINTR)
        continue;

      fprintf(stderr, "Unable to read file: %s\n", strerror(errno));
      goto out_error;
    }

    if (ret == 0)
      break;

    SHA256Update(&ctx, buffer, ret);
  }

  SHA256Final(&ctx, hash);

  close(fd);
  return 1;

out_error:
  close(fd);
  return 0;
}


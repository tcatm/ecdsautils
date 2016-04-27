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

#include "array.h"

#include <assert.h>
#include <stdlib.h>


static void *array_index(array *array, size_t i) {
  return array->content + array->el_size * i;
}

int array_init(array *array, size_t size, size_t n) {
  array->content = malloc(size * n);
  if (array->content == NULL)
    return 0;

  array->el_size = size;
  array->limit = n;
  array->size = 0;

  return 1;
}

void array_destroy(array *array) {
  assert(array != NULL);

  free(array->content);
}

int array_resize(array *array, size_t n) {
  assert(array != NULL);

  void *p;
  p = realloc(array->content, array->el_size * n);

  if (p == NULL)
    return 0;

  array->content = p;
  array->limit = n;

  return 1;
}

int array_add(array *array, void *el, size_t len) {
  assert(array != NULL);

  if (array->limit < array->size + 1) {
    int ret = array_resize(array, array->limit * 2);
    if (!ret)
      return 0;
  }

  memcpy(array_index(array, array->size), el, len);
  array->size++;

  return 1;
}

#if defined(LINUX_QSORT_R)

static int cmparray(const void *p1, const void *p2, void *size) {
  return memcmp(p1, p2, *(size_t*)size);
}

void array_sort(array *array) {
  assert(array != NULL);

  qsort_r(array->content, array->size, array->el_size, cmparray, &array->el_size);
}

#elif defined(BSD_QSORT_R)

static int cmparray(void *size, const void *p1, const void *p2) {
  return memcmp(p1, p2, *(size_t*)size);
}

void array_sort(array *array) {
  assert(array != NULL);

  qsort_r(array->content, array->size, array->el_size, &array->el_size, cmparray);
}

#else

#error Unknown qsort_r definition

#endif

void array_nub(array *array) {
  assert(array != NULL);

  array_sort(array);

  if (array->size < 2)
    return;

  for (int i = 1; i < array->size; i++) {
    void *e, *p;
    e = array_index(array, i);
    p = e - array->el_size;

    if (memcmp(p, e, array->el_size) == 0) {
      array->size--;

      if (i != array->size) {
        memmove(e, e + array->el_size, array->el_size * (array->size - i));
        i--;
      }
    }
  }
}

void array_rm(array *array, size_t i) {
  assert(array != NULL);

  if (i >= array->size)
    return;

  array->size--;

  void *e = array_index(array, i);
  if (i != array->size) {
    memmove(e, e + array->el_size, array->el_size * (array->size - i));
  }
}

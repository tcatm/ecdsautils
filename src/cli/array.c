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


static inline bool add_check(size_t *c, size_t a, size_t b) {
  *c = a + b;
  return *c >= a;
}

static bool mul_check(size_t *c, size_t a, size_t b) {
  const int shift = 4 * sizeof(size_t);
  const size_t mask = (((size_t)1) << shift) - 1;

  size_t a1 = (a>>shift)&mask, a0 = a&mask;
  size_t b1 = (b>>shift)&mask, b0 = b&mask;

  if (a1 && b1)
    return false;

  size_t c1, c0 = a0*b0;

  if (!add_check(&c1, a1*b0, b1*a0))
    return false;

  if (c1 & (~mask))
    return false;

  return add_check(c, c1<<shift, c0);
}


static void *array_index(array *array, size_t i) {
  return array->content + array->el_size * i;
}

bool array_init(array *array, size_t size, size_t n) {
  size_t alloc_size;
  if (!mul_check(&alloc_size, size, n))
    return false;
  array->content = malloc(alloc_size);
  if (array->content == NULL)
    return false;

  array->el_size = size;
  array->limit = n;
  array->size = 0;

  return true;
}

void array_destroy(array *array) {
  assert(array != NULL);

  free(array->content);
}

bool array_resize(array *array, size_t n) {
  assert(array != NULL);

  size_t alloc_size;
  if (!mul_check(&alloc_size, array->el_size, n))
    return false;

  void *p;
  p = realloc(array->content, alloc_size);

  if (p == NULL)
    return false;

  array->content = p;
  array->limit = n;

  return true;
}

bool array_add(array *array, void *el) {
  assert(array != NULL);

  size_t new_size;
  if (!add_check(&new_size, array->size, 1))
    return false;

  if (array->limit < new_size) {
    size_t new_limit;
    if (!mul_check(&new_limit, array->limit, 2))
      return false;

    int ret = array_resize(array, new_limit);
    if (!ret)
      return false;
  }

  memcpy(array_index(array, array->size), el, array->el_size);
  array->size = new_size;

  return true;
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

  for (size_t i = 1; i < array->size; i++) {
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
  assert(i < array->size);

  array->size--;

  void *e = array_index(array, i);
  if (i != array->size) {
    memmove(e, e + array->el_size, array->el_size * (array->size - i));
  }
}

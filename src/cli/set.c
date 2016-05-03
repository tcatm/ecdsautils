/*
  Copyright (c) 2012, Nils Schneider <nils@nilsschneider.net>
  Copyright (c) 2016, Matthias Schiffer <mschiffer@universe-factory.net>
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

#include "set.h"

#include <assert.h>
#include <string.h>


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


static void *set_index(set *set, size_t i) {
  return set->content + set->el_size * i;
}


bool set_init(set *set, size_t size, size_t n) {
  size_t alloc_size;
  if (!mul_check(&alloc_size, size, n))
    return false;
  set->content = malloc(alloc_size);
  if (set->content == NULL)
    return false;

  set->el_size = size;
  set->limit = n;
  set->size = 0;

  return true;
}


void set_destroy(set *set) {
  assert(set != NULL);

  free(set->content);
}


bool set_resize(set *set, size_t n) {
  assert(set != NULL);

  size_t alloc_size;
  if (!mul_check(&alloc_size, set->el_size, n))
    return false;

  void *p;
  p = realloc(set->content, alloc_size);

  if (p == NULL)
    return false;

  set->content = p;
  set->limit = n;

  return true;
}


static bool set_increment_size(set *set) {
  size_t new_size;
  if (!add_check(&new_size, set->size, 1))
    return false;

  if (set->limit < new_size) {
    size_t new_limit;
    if (!mul_check(&new_limit, set->limit, 2))
      return false;

    if (!set_resize(set, new_limit))
      return false;
  }

  set->size = new_size;

  return true;
}

/*
  Treats the set as a set, meaning that duplicate elements won't be added.
  As a side effect, the set is kept sorted.
*/
bool set_add(set *set, void *el) {
  assert(set != NULL);

  size_t min = 0, max = set->size;

  /* Simple binary search */
	while (max > min) {
		size_t cur = min + (max - min)/2;
		int cmp = memcmp(set_index(set, cur), el, set->el_size);

		if (cmp == 0)
			return true; /* We're done here: the element already exists */
		else if (cmp < 0)
			max = cur;
		else
			min = cur+1;
	}

  /* min now holds the place to insert the new value */

  size_t rest = set->size - min;

  if (!set_increment_size(set))
    return false;

  memmove(set_index(set, min+1), set_index(set, min), rest * set->el_size);
  memcpy(set_index(set, min), el, set->el_size);

  return true;
}

/* Copyright (c) 2014, Google Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE. */

#include <openssl/mem.h>
#include <openssl/bytestring.h>

#include <assert.h>
#include <string.h>

#include "internal.h"


void CBS_init(CBS *cbs, const uint8_t *data, size_t len) {
  cbs->data = data;
  cbs->len = len;
}

static int cbs_get(CBS *cbs, const uint8_t **p, size_t n) {
  if (cbs->len < n) {
    return 0;
  }

  *p = cbs->data;
  cbs->data += n;
  cbs->len -= n;
  return 1;
}

static int cbs_skip(CBS *cbs, size_t len) {
  const uint8_t *dummy;
  return cbs_get(cbs, &dummy, len);
}

const uint8_t *CBS_data(const CBS *cbs) {
  return cbs->data;
}

size_t CBS_len(const CBS *cbs) {
  return cbs->len;
}

static int cbs_get_u(CBS *cbs, uint32_t *out, size_t len) {
  uint32_t result = 0;
  size_t i;
  const uint8_t *data;

  if (!cbs_get(cbs, &data, len)) {
    return 0;
  }
  for (i = 0; i < len; i++) {
    result <<= 8;
    result |= data[i];
  }
  *out = result;
  return 1;
}

static int cbs_get_u8(CBS *cbs, uint8_t *out) {
  const uint8_t *v;
  if (!cbs_get(cbs, &v, 1)) {
    return 0;
  }
  *out = *v;
  return 1;
}

static int cbs_get_bytes(CBS *cbs, CBS *out, size_t len) {
  const uint8_t *v;
  if (!cbs_get(cbs, &v, len)) {
    return 0;
  }
  CBS_init(out, v, len);
  return 1;
}

static int cbs_get_any_asn1_element(CBS *cbs, CBS *out, unsigned *out_tag,
                                    size_t *out_header_len) {
  uint8_t tag, length_byte;
  CBS header = *cbs;
  CBS throwaway;

  if (out == NULL) {
    out = &throwaway;
  }

  if (!cbs_get_u8(&header, &tag) ||
      !cbs_get_u8(&header, &length_byte)) {
    return 0;
  }

  if ((tag & 0x1f) == 0x1f) {
    /* Long form tags are not supported. */
    return 0;
  }

  if (out_tag != NULL) {
    *out_tag = tag;
  }

  size_t len;
  if ((length_byte & 0x80) == 0) {
    /* Short form length. */
    len = ((size_t) length_byte) + 2;
    if (out_header_len != NULL) {
      *out_header_len = 2;
    }
  } else {
    /* Long form length. */
    const size_t num_bytes = length_byte & 0x7f;
    uint32_t len32;

    if (num_bytes == 0 || num_bytes > 4) {
      return 0;
    }
    if (!cbs_get_u(&header, &len32, num_bytes)) {
      return 0;
    }
    if (len32 < 128) {
      /* Length should have used short-form encoding. */
      return 0;
    }
    if ((len32 >> ((num_bytes-1)*8)) == 0) {
      /* Length should have been at least one byte shorter. */
      return 0;
    }
    len = len32;
    if (len + 2 + num_bytes < len) {
      /* Overflow. */
      return 0;
    }
    len += 2 + num_bytes;
    if (out_header_len != NULL) {
      *out_header_len = 2 + num_bytes;
    }
  }

  return cbs_get_bytes(cbs, out, len);
}

static int cbs_get_asn1(CBS *cbs, CBS *out, unsigned tag_value,
                        int skip_header) {
  size_t header_len;
  unsigned tag;
  CBS throwaway;

  if (out == NULL) {
    out = &throwaway;
  }

  if (!cbs_get_any_asn1_element(cbs, out, &tag, &header_len) ||
      tag != tag_value) {
    return 0;
  }

  if (skip_header && !cbs_skip(out, header_len)) {
    assert(0);
    return 0;
  }

  return 1;
}

int CBS_get_asn1(CBS *cbs, CBS *out, unsigned tag_value) {
  return cbs_get_asn1(cbs, out, tag_value, 1 /* skip header */);
}

int CBS_get_asn1_element(CBS *cbs, CBS *out, unsigned tag_value) {
  return cbs_get_asn1(cbs, out, tag_value, 0 /* include header */);
}

int CBS_peek_asn1_tag(const CBS *cbs, unsigned tag_value) {
  if (CBS_len(cbs) < 1) {
    return 0;
  }
  return CBS_data(cbs)[0] == tag_value;
}

int CBS_get_asn1_uint64(CBS *cbs, uint64_t *out) {
  CBS bytes;
  const uint8_t *data;
  size_t i, len;

  if (!CBS_get_asn1(cbs, &bytes, CBS_ASN1_INTEGER)) {
    return 0;
  }

  *out = 0;
  data = CBS_data(&bytes);
  len = CBS_len(&bytes);

  if (len == 0) {
    /* An INTEGER is encoded with at least one octet. */
    return 0;
  }

  if ((data[0] & 0x80) != 0) {
    /* Negative number. */
    return 0;
  }

  if (data[0] == 0 && len > 1 && (data[1] & 0x80) == 0) {
    /* Extra leading zeros. */
    return 0;
  }

  for (i = 0; i < len; i++) {
    if ((*out >> 56) != 0) {
      /* Too large to represent as a uint64_t. */
      return 0;
    }
    *out <<= 8;
    *out |= data[i];
  }

  return 1;
}

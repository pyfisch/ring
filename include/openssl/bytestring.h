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

#ifndef OPENSSL_HEADER_BYTESTRING_H
#define OPENSSL_HEADER_BYTESTRING_H

#include <openssl/base.h>

#if defined(__cplusplus)
extern "C" {
#endif


/* Bytestrings are used for parsing and building TLS and ASN.1 messages.
 *
 * A "CBS" (CRYPTO ByteString) represents a string of bytes in memory and
 * provides utility functions for safely parsing length-prefixed structures
 * like TLS and ASN.1 from it.
 *
 * A "CBB" (CRYPTO ByteBuilder) is a memory buffer that grows as needed and
 * provides utility functions for building length-prefixed messages. */


/* CRYPTO ByteString */

struct cbs_st {
  const uint8_t *data;
  size_t len;
};

/* CBS_init sets |cbs| to point to |data|. It does not take ownership of
 * |data|. */
OPENSSL_EXPORT void CBS_init(CBS *cbs, const uint8_t *data, size_t len);

/* CBS_data returns a pointer to the contents of |cbs|. */
OPENSSL_EXPORT const uint8_t *CBS_data(const CBS *cbs);

/* CBS_len returns the number of bytes remaining in |cbs|. */
OPENSSL_EXPORT size_t CBS_len(const CBS *cbs);


/* Parsing ASN.1 */

#define CBS_ASN1_BOOLEAN 0x1
#define CBS_ASN1_INTEGER 0x2
#define CBS_ASN1_BITSTRING 0x3
#define CBS_ASN1_OCTETSTRING 0x4
#define CBS_ASN1_NULL 0x5
#define CBS_ASN1_OBJECT 0x6
#define CBS_ASN1_ENUMERATED 0xa
#define CBS_ASN1_SEQUENCE (0x10 | CBS_ASN1_CONSTRUCTED)
#define CBS_ASN1_SET (0x11 | CBS_ASN1_CONSTRUCTED)
#define CBS_ASN1_GENERALIZEDTIME 0x18

#define CBS_ASN1_CONSTRUCTED 0x20
#define CBS_ASN1_CONTEXT_SPECIFIC 0x80

/* CBS_get_asn1 sets |*out| to the contents of DER-encoded, ASN.1 element (not
 * including tag and length bytes) and advances |cbs| over it. The ASN.1
 * element must match |tag_value|. It returns one on success and zero
 * on error.
 *
 * Tag numbers greater than 30 are not supported (i.e. short form only). */
OPENSSL_EXPORT int CBS_get_asn1(CBS *cbs, CBS *out, unsigned tag_value);

/* CBS_get_asn1_element acts like |CBS_get_asn1| but |out| will include the
 * ASN.1 header bytes too. */
OPENSSL_EXPORT int CBS_get_asn1_element(CBS *cbs, CBS *out, unsigned tag_value);

/* CBS_peek_asn1_tag looks ahead at the next ASN.1 tag and returns one
 * if the next ASN.1 element on |cbs| would have tag |tag_value|. If
 * |cbs| is empty or the tag does not match, it returns zero. Note: if
 * it returns one, CBS_get_asn1 may still fail if the rest of the
 * element is malformed. */
OPENSSL_EXPORT int CBS_peek_asn1_tag(const CBS *cbs, unsigned tag_value);

/* CBS_get_asn1_uint64 gets an ASN.1 INTEGER from |cbs| using |CBS_get_asn1|
 * and sets |*out| to its value. It returns one on success and zero on error,
 * where error includes the integer being negative, or too large to represent
 * in 64 bits. */
OPENSSL_EXPORT int CBS_get_asn1_uint64(CBS *cbs, uint64_t *out);


/* CRYPTO ByteBuilder.
 *
 * |CBB| objects allow one to build length-prefixed serialisations. A |CBB|
 * object is associated with a buffer and new buffers are created with
 * |CBB_init|. Several |CBB| objects can point at the same buffer when a
 * length-prefix is pending, however only a single |CBB| can be 'current' at
 * any one time. For example, if one calls |CBB_add_u8_length_prefixed| then
 * the new |CBB| points at the same buffer as the original. But if the original
 * |CBB| is used then the length prefix is written out and the new |CBB| must
 * not be used again.
 *
 * If one needs to force a length prefix to be written out because a |CBB| is
 * going out of scope, use |CBB_flush|. */

struct cbb_buffer_st {
  uint8_t *buf;
  size_t len;      /* The number of valid bytes. */
  size_t cap;      /* The size of buf. */
  char can_resize; /* One iff |buf| is owned by this object. If not then |buf|
                      cannot be resized. */
};

struct cbb_st {
  struct cbb_buffer_st *base;
  /* child points to a child CBB if a length-prefix is pending. */
  CBB *child;
  /* offset is the number of bytes from the start of |base->buf| to this |CBB|'s
   * pending length prefix. */
  size_t offset;
  /* pending_len_len contains the number of bytes in this |CBB|'s pending
   * length-prefix, or zero if no length-prefix is pending. */
  uint8_t pending_len_len;
  char pending_is_asn1;
  /* is_top_level is true iff this is a top-level |CBB| (as opposed to a child
   * |CBB|). Top-level objects are valid arguments for |CBB_finish|. */
  char is_top_level;
};

/* CBB_zero sets an uninitialised |cbb| to the zero state. It must be
 * initialised with |CBB_init| or |CBB_init_fixed| before use, but it is safe to
 * call |CBB_cleanup| without a successful |CBB_init|. This may be used for more
 * uniform cleanup of a |CBB|. */
OPENSSL_EXPORT void CBB_zero(CBB *cbb);

/* CBB_init initialises |cbb| with |initial_capacity|. Since a |CBB| grows as
 * needed, the |initial_capacity| is just a hint. It returns one on success or
 * zero on error. */
OPENSSL_EXPORT int CBB_init(CBB *cbb, size_t initial_capacity);

/* CBB_init_fixed initialises |cbb| to write to |len| bytes at |buf|. Since
 * |buf| cannot grow, trying to write more than |len| bytes will cause CBB
 * functions to fail. It returns one on success or zero on error. */
OPENSSL_EXPORT int CBB_init_fixed(CBB *cbb, uint8_t *buf, size_t len);

/* CBB_cleanup frees all resources owned by |cbb| and other |CBB| objects
 * writing to the same buffer. This should be used in an error case where a
 * serialisation is abandoned.
 *
 * This function can only be called on a "top level" |CBB|, i.e. one initialised
 * with |CBB_init| or |CBB_init_fixed|, or a |CBB| set to the zero state with
 * |CBB_zero|. */
OPENSSL_EXPORT void CBB_cleanup(CBB *cbb);

/* CBB_finish completes any pending length prefix and sets |*out_data| to a
 * malloced buffer and |*out_len| to the length of that buffer. The caller
 * takes ownership of the buffer and, unless the buffer was fixed with
 * |CBB_init_fixed|, must call |OPENSSL_free| when done.
 *
 * It can only be called on a "top level" |CBB|, i.e. one initialised with
 * |CBB_init| or |CBB_init_fixed|. It returns one on success and zero on
 * error. */
OPENSSL_EXPORT int CBB_finish(CBB *cbb, uint8_t **out_data, size_t *out_len);

/* CBB_flush causes any pending length prefixes to be written out and any child
 * |CBB| objects of |cbb| to be invalidated. It returns one on success or zero
 * on error. */
OPENSSL_EXPORT int CBB_flush(CBB *cbb);

/* CBB_len returns the number of bytes written to |cbb|. It does not flush
 * |cbb|.
 *
 * To avoid unfinalized length prefixes, it is a fatal error to call this on a
 * CBB with any active children. */
OPENSSL_EXPORT size_t CBB_len(const CBB *cbb);

/* CBB_add_u8_length_prefixed sets |*out_contents| to a new child of |cbb|. The
 * data written to |*out_contents| will be prefixed in |cbb| with an 8-bit
 * length. It returns one on success or zero on error. */
OPENSSL_EXPORT int CBB_add_u8_length_prefixed(CBB *cbb, CBB *out_contents);

/* CBB_add_u16_length_prefixed sets |*out_contents| to a new child of |cbb|.
 * The data written to |*out_contents| will be prefixed in |cbb| with a 16-bit,
 * big-endian length. It returns one on success or zero on error. */
OPENSSL_EXPORT int CBB_add_u16_length_prefixed(CBB *cbb, CBB *out_contents);

/* CBB_add_u24_length_prefixed sets |*out_contents| to a new child of |cbb|.
 * The data written to |*out_contents| will be prefixed in |cbb| with a 24-bit,
 * big-endian length. It returns one on success or zero on error. */
OPENSSL_EXPORT int CBB_add_u24_length_prefixed(CBB *cbb, CBB *out_contents);

/* CBB_add_asn1 sets |*out_contents| to a |CBB| into which the contents of an
 * ASN.1 object can be written. The |tag| argument will be used as the tag for
 * the object. Passing in |tag| number 31 will return in an error since only
 * single octet identifiers are supported. It returns one on success or zero
 * on error. */
OPENSSL_EXPORT int CBB_add_asn1(CBB *cbb, CBB *out_contents, uint8_t tag);

/* CBB_add_bytes appends |len| bytes from |data| to |cbb|. It returns one on
 * success and zero otherwise. */
OPENSSL_EXPORT int CBB_add_bytes(CBB *cbb, const uint8_t *data, size_t len);

/* CBB_add_space appends |len| bytes to |cbb| and sets |*out_data| to point to
 * the beginning of that space. The caller must then write |len| bytes of
 * actual contents to |*out_data|. It returns one on success and zero
 * otherwise. */
OPENSSL_EXPORT int CBB_add_space(CBB *cbb, uint8_t **out_data, size_t len);

/* CBB_add_u8 appends an 8-bit number from |value| to |cbb|. It returns one on
 * success and zero otherwise. */
OPENSSL_EXPORT int CBB_add_u8(CBB *cbb, uint8_t value);

/* CBB_add_u16 appends a 16-bit, big-endian number from |value| to |cbb|. It
 * returns one on success and zero otherwise. */
OPENSSL_EXPORT int CBB_add_u16(CBB *cbb, uint16_t value);

/* CBB_add_u24 appends a 24-bit, big-endian number from |value| to |cbb|. It
 * returns one on success and zero otherwise. */
OPENSSL_EXPORT int CBB_add_u24(CBB *cbb, uint32_t value);

/* CBB_add_asn1_uint64 writes an ASN.1 INTEGER into |cbb| using |CBB_add_asn1|
 * and writes |value| in its contents. It returns one on success and zero on
 * error. */
OPENSSL_EXPORT int CBB_add_asn1_uint64(CBB *cbb, uint64_t value);


#if defined(__cplusplus)
}  /* extern C */
#endif

#endif  /* OPENSSL_HEADER_BYTESTRING_H */

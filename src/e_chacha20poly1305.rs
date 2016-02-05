use core::slice::from_raw_parts_mut;

#[allow(unsafe_code)]
pub fn evp_aead_chacha20_poly1305_init_rust(ctx_buf: &mut [u64],
                                            key: &[u8]) -> Result<(), ()> {
    assert!(ctx_buf.len() >= key.len());

    let mut ctx_buf_bytes = unsafe {
        from_raw_parts_mut(ctx_buf.as_ptr() as *mut u8, ctx_buf.len() * 8)
    };

    // FIXME: use clone_from_slice when it stabilizes
    for i in 0..key.len() {
        ctx_buf_bytes[i].clone_from(&key[i]);
    }

    Ok(())
}



/*
static int seal_impl(aead_poly1305_update poly1305_update,
                     const void *ctx_buf, uint8_t *out, size_t *out_len,
                     size_t max_out_len, const uint8_t nonce[12],
                     const uint8_t *in, size_t in_len, const uint8_t *ad,
                     size_t ad_len) {
  aead_assert_open_seal_preconditions(alignof(struct aead_chacha20_poly1305_ctx),
                                      ctx_buf, out, out_len, nonce, in, in_len,
                                      ad, ad_len);

  const struct aead_chacha20_poly1305_ctx *c20_ctx = ctx_buf;

  if (!aead_seal_out_max_out_in_tag_len(out_len, max_out_len, in_len,
                                        POLY1305_TAG_LEN)) {
    /* |aead_seal_out_max_out_in_tag_len| already called |OPENSSL_PUT_ERROR|. */
    return 0;
  }

  CRYPTO_chacha_20(out, in, in_len, c20_ctx->key, nonce, 1);

  alignas(16) uint8_t tag[POLY1305_TAG_LEN];
  aead_poly1305(poly1305_update, tag, c20_ctx, nonce, ad, ad_len, out, in_len);

  /* TODO: Does |tag| really need to be |ALIGNED|? If not, we can avoid this
   * call to |memcpy|. */
  memcpy(out + in_len, tag, POLY1305_TAG_LEN);

  return 1;
}
*/


//evp_aead_chacha20_poly1305_seal,
//evp_aead_chacha20_poly1305_open,
//evp_aead_chacha20_poly1305_old_seal,
//evp_aead_chacha20_poly1305_old_open,

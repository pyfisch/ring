use core::slice::from_raw_parts_mut;
use core::mem::size_of_val;

use aead::POLY1305_TAG_LEN;
use c;


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


#[allow(unsafe_code)]
fn aead_seal_out_max_out_in_tag_len(out_len: *mut usize, max_out_len: c::size_t, in_len: usize,
                                    tag_len: usize) -> Result<usize, ()> {
    if c::size_t::max_value() - tag_len < in_len {
        // CIPHER_R_TOO_LARGE
        return Err(());
    }

    let ciphertext_len = in_len + tag_len;
    if max_out_len < ciphertext_len {
        // CIPHER_R_BUFFER_TOO_SMALL
        return Err(());
    }

    unsafe { *out_len = ciphertext_len; }
    Ok(ciphertext_len)
}


#[allow(unsafe_code)]
fn aead_poly1305(tag: &mut [u8], c20_ctx: &AeadChacha20Poly1305Ctx, nonce: *const u8, ad: &[u8], ciphertext: &[u8]) {
    let mut poly1305_key = [0; 32];
    unsafe {
        CRYPTO_chacha_20(poly1305_key.as_mut_ptr(), poly1305_key.as_ptr(),
                         size_of_val(&poly1305_key), c20_ctx.as_ptr(), nonce, 0)
    }

    let ctx: &mut Poly1305State = &mut [0; 512];

    unsafe {
        CRYPTO_poly1305_init(ctx.as_mut_ptr(), poly1305_key.as_ptr());
    }

    // c: update(&ctx, ad, ad_len, ciphertext, ciphertext_len);
    // TODO: this should just be a functon called 'update'?
    poly1305_update(ctx, ad, ciphertext);

    unsafe {
        CRYPTO_poly1305_finish(ctx.as_mut_ptr(), tag.as_ptr());
    }
}

fn poly1305_update(ctx: &mut Poly1305State, ad: &[u8], ciphertext: &[u8]) {
    poly1305_update_padded_16(ctx, ad);
    poly1305_update_padded_16(ctx, ciphertext);
    poly1305_update_length(ctx, ad.len());
    poly1305_update_length(ctx, ciphertext.len());
}

#[allow(unsafe_code)]
fn poly1305_update_padded_16(poly1305: &mut Poly1305State, data: &[u8]) {
    let padding = &[0u8; 16];
    unsafe {
        CRYPTO_poly1305_update(poly1305.as_mut_ptr(), data.as_ptr(), data.len());
        if data.len() % 16 != 0 {
            CRYPTO_poly1305_update(poly1305.as_mut_ptr(), padding.as_ptr(), size_of_val(padding) - (data.len() % 16))
        }
    }
}

#[allow(unsafe_code)]
fn poly1305_update_length(poly1305: &mut Poly1305State, data_len: usize) {
    let mut j: usize = data_len;
    let mut length_bytes = [0u8; 8];
    for i in 0..length_bytes.len() {
        length_bytes[i] = j as u8;
        j >>= 8;
    }
    unsafe {
        CRYPTO_poly1305_update(poly1305.as_mut_ptr(), length_bytes.as_ptr(),
                               size_of_val(&length_bytes));
    }
}

type Poly1305State = [u8];  // size = 512
type AeadChacha20Poly1305Ctx = [u8];  // size = 32

#[allow(unsafe_code)]
fn seal_impl(ctx_buf: *const u64, out: *mut u8, out_len: *mut usize, max_out_len: c::size_t,
             nonce: *const u8, in_: &[u8], ad: &[u8]) -> Result<(), ()> {
    let c20_ctx: &mut AeadChacha20Poly1305Ctx = unsafe {
        from_raw_parts_mut(ctx_buf as *mut u8, 32)
    };

    let a = try!(aead_seal_out_max_out_in_tag_len(out_len, max_out_len, in_.len(),
                                                  POLY1305_TAG_LEN));
    if a == 0 {
        return Err(());
    }

    unsafe {
        CRYPTO_chacha_20(out, in_.as_ptr(), in_.len(), c20_ctx.as_ptr(), nonce, 1);
    }

    let mut tag = [0; POLY1305_TAG_LEN];

    let ciphertext = unsafe { from_raw_parts_mut(out, in_.len()) };
    aead_poly1305(&mut tag, c20_ctx, nonce, ad, ciphertext);

    Ok(())
}


pub fn evp_aead_chacha20_poly1305_seal_rust(ctx_buf: *const u64, out: *mut u8, out_len: *mut usize,
                                            max_out_len: c::size_t, nonce: *const u8, in_: &[u8],
                                            ad: &[u8]) -> Result<(), ()> {
    seal_impl(ctx_buf, out, out_len, max_out_len, nonce, in_, ad)
}

#[allow(dead_code)]
extern {
    fn CRYPTO_chacha_20(out: *mut u8, in_: *const u8, in_len: c::size_t, key: *const u8,
                        nonce: *const u8, counter: u32);
    fn CRYPTO_poly1305_init(state: *mut u8, key: *const u8);
    fn CRYPTO_poly1305_finish(state: *mut u8, mac: *const u8);
    fn CRYPTO_poly1305_update(state: *mut u8, in_: *const u8, in_len: c::size_t);
}

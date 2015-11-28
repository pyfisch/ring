// Copyright 2015 Brian Smith.
//
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHORS DISCLAIM ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY
// SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
// OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
// CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

//! Elliptic curve cryptography.

use super::{c, digest, ffi};
use std;

/// An elliptic curve.
///
/// C analog: `EC_GROUP`
pub struct EllipticCurve {
    ec_group_new: ECGroupNewFn,
    encoded_public_key_len: usize,
    nid: c::int,
}

/// An ephemeral ECDH key pair for use (only) with `ecdh_ephemeral`. The
/// signature of `ecdh_ephemeral` ensures that an `ECDHEphemeralKeyPair`
/// can be used for at most one ECDH key agreement.
pub struct ECDHEphemeralKeyPair {
    key: *mut EC_KEY,
    curve: &'static EllipticCurve
}

impl ECDHEphemeralKeyPair {
    /// Generate a new ephemeral ECDH keypair for the given curve.
    ///
    /// C analog: `EC_KEY_new_by_curve_name` + `EC_KEY_generate_key`.
    pub fn generate(curve: &'static EllipticCurve)
                    -> Result<ECDHEphemeralKeyPair, ()> {
        let key = try!(ffi::map_bssl_ptr_result(unsafe {
            EC_KEY_generate_key_ex(curve.ec_group_new)
        }));
        Ok(ECDHEphemeralKeyPair { key: key, curve: curve })
    }

    /// The size in bytes of the encoded public point returned from
    /// `public_point`.
    #[inline(always)]
    pub fn public_point_len(&self) -> usize {
        self.curve.encoded_public_key_len
    }

    /// Fills `out` with the public point encoded in standard, uncompressed,
    /// form.
    ///
    /// `out.len()` must be equal to the value returned by `public_point_len`.
    pub fn fill_with_encoded_public_point(&self, out: &mut [u8])
                                          -> Result<(), ()> {
        match unsafe {
            EC_KEY_public_key_to_oct(self.key, out.as_mut_ptr(), out.len())
        } {
            n if n == self.public_point_len() => Ok(()),
            _ => Err(())
        }
    }
}

impl Drop for ECDHEphemeralKeyPair {
    fn drop(&mut self) {
        unsafe {
            EC_KEY_free(self.key);
        }
    }
}

/// Performs an ECDH key agreement with an ephemeral key pair and the given
/// public point.
///
/// `my_key_pair` is the ephemeral key pair to use. Since `my_key_pair` is
/// moved, it will not be usable after calling `ecdh_ephemeral`, thus
/// guaranteeing that the key is used for only one ECDH key agreement.
/// `peer_curve` is the curve for the peer's public key point;
/// `ecdh_ephemeral` will return `Err(())` if it does not match `my_key_pair's`
/// curve. `peer_encoded_pubic_point` is the peer's public key point; it must
/// be in uncompressed form and it will be decoded using the
/// Octet-String-to-Elliptic-Curve-Point algorithm in
/// [SEC 1: Elliptic Curve Cryptography, Version 2.0](http://www.secg.org/sec1-v2.pdf).
/// `error_value` is the value to return if an error occurs before `kdf` is
/// called, e.g. when decoding of the peer's public point fails. After the ECDH
/// key agreement is done, `ecdh_ephemeral` calls `kdf` with the raw key
/// material from the ECDH operation and then returns what `kdf` returns.
///
/// C analogs: `ECDH_compute_key_ex` (*ring* only), `EC_POINT_oct2point` +
/// `ECDH_compute_key`.
//
// TODO: If the key is authenticated then we don't necessarily need to verify
// that the peer's public point is on the curve since a malicious
// authenticated peer could just as easily give us a bad public point that is
// on the curve. Also, given that our ECDH key is ephemeral, we're not risking
// the leakage of a long-term key via invalid point attacks. Accordingly, even
// though the lower-level C code does check that the peer's point is on the
// curve, that check seems like overkill, at least for the most typical uses
// of this function. On the other hand, some users may feel that it is
// worthwhile to do point validity check even if it seems to be unnecssary.
// Accordingly, it might be worthwhile to change this interface in the future
// so that the caller can choose how much validation of the peer's public
// point is done.
pub fn ecdh_ephemeral<F, R, E>(my_key_pair: ECDHEphemeralKeyPair,
                               peer_curve: &EllipticCurve,
                               peer_encoded_public_point: &[u8],
                               error_value: E, kdf: F) -> Result<R, E>
                               where F: FnOnce(&[u8]) -> Result<R, E> {
    let mut shared_key = [0u8; MAX_COORDINATE_LEN];
    let mut shared_key_len = 0;
    match unsafe {
        ECDH_compute_key_ex(shared_key.as_mut_ptr(), &mut shared_key_len,
                            shared_key.len(), my_key_pair.key, peer_curve.nid,
                            peer_encoded_public_point.as_ptr(),
                            peer_encoded_public_point.len())
    } {
        1 => kdf(&shared_key[0..shared_key_len]),
        _ => Err(error_value)
    }
}

/// Verifies that the ASN.1-DER-encoded ECDSA signature encoded in `sig` is
/// valid for the data hashed to `digest` using the encoded public key
/// `key`.
///
/// `key` will be decoded using the Octet-String-to-Elliptic-Curve-Point
/// algorithm in
/// [SEC 1: Elliptic Curve Cryptography, Version 2.0](http://www.secg.org/sec1-v2.pdf).
/// It must in be in uncompressed form.
///
/// C analogs: `ECDSA_verify_pkcs1_signed_digest` (*ring* only),
///            `EC_POINT_oct2point` with `ECDSA_verify`.
pub fn verify_ecdsa_signed_digest_asn1(curve: &EllipticCurve,
                                       digest: &digest::Digest, sig: &[u8],
                                       key: &[u8]) -> Result<(),()> {
    ffi::map_bssl_result(unsafe {
        ECDSA_verify_signed_digest(0, digest.as_ref().as_ptr(),
                                   digest.as_ref().len(), sig.as_ptr(),
                                   sig.len(), curve.ec_group_new, key.as_ptr(),
                                   key.len())
    })
}


#[allow(non_snake_case)]
#[doc(hidden)]
#[no_mangle]
pub extern fn BN_generate_dsa_nonce_digest(
        out: *mut u8, out_len: c::size_t,
        part1: *const u8, part1_len: c::size_t,
        part2: *const u8, part2_len: c::size_t,
        part3: *const u8, part3_len: c::size_t,
        part4: *const u8, part4_len: c::size_t,
        part5: *const u8, part5_len: c::size_t)
        -> c::int {
    let mut ctx = digest::Context::new(&digest::SHA512);
    ctx.update(unsafe { std::slice::from_raw_parts(part1, part1_len) });
    ctx.update(unsafe { std::slice::from_raw_parts(part2, part2_len) });
    ctx.update(unsafe { std::slice::from_raw_parts(part3, part3_len) });
    ctx.update(unsafe { std::slice::from_raw_parts(part4, part4_len) });
    ctx.update(unsafe { std::slice::from_raw_parts(part5, part5_len) });
    let digest = ctx.finish();
    let digest = digest.as_ref();
    let out = unsafe { std::slice::from_raw_parts_mut(out, out_len) };
    if out.len() != digest.len() {
        return 0;
    }
    for i in 0..digest.len() {
        out[i] = digest[i];
    }
    return 1;
}

// XXX: Replace with `const fn` when `const fn` is stable:
// https://github.com/rust-lang/rust/issues/24111
macro_rules! encoded_public_key_len {
    ( $bits:expr ) => ( 1 + (2 * (($bits + 7) / 8)) )
}

/// The NIST P-256 curve, a.k.a. secp256r1.
///
/// C analogs: `EC_GROUP_new_p256` (*ring* only),
/// `EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1)`")
pub static CURVE_P256: EllipticCurve = EllipticCurve {
    ec_group_new: EC_GROUP_new_p256,
    encoded_public_key_len: encoded_public_key_len!(256),
    nid: 415, // NID_X9_62_prime256v1
};

/// The NIST P-384 curve, a.k.a. secp384r1.
///
/// C analogs: `EC_GROUP_new_p384` (*ring* only),
/// `EC_GROUP_new_by_curve_name(NID_secp384r1)`")
pub static CURVE_P384: EllipticCurve = EllipticCurve {
    ec_group_new: EC_GROUP_new_p384,
    encoded_public_key_len: encoded_public_key_len!(384),
    nid: 715, // NID_secp384r1
};

/// The NIST P-521 curve, a.k.a. secp521r1.
///
/// C analogs: `EC_GROUP_new_p521` (*ring* only),
/// `EC_GROUP_new_by_curve_name(NID_secp521r1)`")
pub static CURVE_P521: EllipticCurve = EllipticCurve {
    ec_group_new: EC_GROUP_new_p521,
    encoded_public_key_len: encoded_public_key_len!(521),
    nid: 716, // NID_secp521r1
};

const MAX_COORDINATE_LEN: usize = (521 + 7) / 8;

type ECGroupNewFn = unsafe extern fn() -> *mut EC_GROUP;

#[allow(non_camel_case_types)]
enum EC_GROUP { }

#[allow(non_camel_case_types)]
enum EC_KEY { }

// XXX: As of Rust 1.4, the compiler will no longer warn about the use of
// `usize` and `isize` in FFI declarations. Remove the `allow(improper_ctypes)`
// when Rust 1.4 is released.
#[allow(improper_ctypes)]
extern {
    fn EC_GROUP_new_p256() -> *mut EC_GROUP;
    fn EC_GROUP_new_p384() -> *mut EC_GROUP;
    fn EC_GROUP_new_p521() -> *mut EC_GROUP;

    fn EC_KEY_generate_key_ex(ec_group_new: ECGroupNewFn) -> *mut EC_KEY;
    fn EC_KEY_public_key_to_oct(key: *const EC_KEY, out: *mut u8,
                                out_len: c::size_t) -> c::size_t;
    fn EC_KEY_free(key: *mut EC_KEY);


    fn ECDH_compute_key_ex(out: *mut u8, out_len: *mut c::size_t,
                           max_out_len: c::size_t, my_key_pair: *mut EC_KEY,
                           peer_curve_nid: c::int,
                           peer_pub_point_bytes: *const u8,
                           peer_pub_point_bytes_len: c::size_t) -> c::int;

    fn ECDSA_verify_signed_digest(hash_nid: c::int, digest: *const u8,
                                  digest_len: c::size_t, sig_der: *const u8,
                                  sig_der_len: c::size_t,
                                  ec_group_new: ECGroupNewFn,
                                  key_octets: *const u8,
                                  key_octets_len: c::size_t) -> c::int;
}
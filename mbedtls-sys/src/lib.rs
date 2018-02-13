#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

pub mod wrapper {
    use std::os::raw::*;
    use mbedtls_cipher_context_t;

    extern "C" {
        pub fn wrapper_get_iv_size(ctx: *const mbedtls_cipher_context_t) -> c_int;
        pub fn wrapper_get_block_size(ctx: *const mbedtls_cipher_context_t) -> c_uint;
        pub fn wrapper_get_key_bitlen(ctx: *const mbedtls_cipher_context_t) -> c_int;
    }
}

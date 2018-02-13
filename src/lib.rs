#![recursion_limit = "1024"]
extern crate mbedtls_sys;

#[macro_use]
extern crate error_chain;

pub mod cipher;
pub mod errors;

#[cfg(test)]
mod test {
    use std::ffi::{CStr, CString};
    use mbedtls_sys;

    #[test]
    fn version() {
        unsafe {
            let ptr = CString::new("").unwrap().into_raw();
            mbedtls_sys::mbedtls_version_get_string(ptr);
            assert_eq!(
                CString::from_raw(ptr).into_string().unwrap(),
                CStr::from_bytes_with_nul(mbedtls_sys::MBEDTLS_VERSION_STRING)
                    .unwrap()
                    .to_string_lossy()
            );
        }
    }
}

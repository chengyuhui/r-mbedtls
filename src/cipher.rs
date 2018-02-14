use std::os::raw::c_int;
use std::mem;
use mbedtls_sys;
use errors::*;

pub use mbedtls_sys::mbedtls_cipher_type_t as CipherType;

/// Cipher operation mode.
pub enum Mode {
    Encrypt,
    Decrypt,
}

impl Into<mbedtls_sys::mbedtls_operation_t> for Mode {
    fn into(self) -> mbedtls_sys::mbedtls_operation_t {
        use mbedtls_sys::mbedtls_operation_t::*;
        use self::Mode::*;
        match self {
            Encrypt => MBEDTLS_ENCRYPT,
            Decrypt => MBEDTLS_DECRYPT,
        }
    }
}

/// Returns the length of keys(in bits) used with this cipher.
pub fn key_bitlen(t: CipherType) -> Result<usize> {
    let info = unsafe { mbedtls_sys::mbedtls_cipher_info_from_type(t).as_ref() };
    info.ok_or_else(|| ErrorKind::CipherNotFound.into())
        .map(|info| info.key_bitlen as usize)
}

/// Returns the length of the IV used with this cipher, or `None` if the
/// cipher does not use an IV.
pub fn iv_size(t: CipherType) -> Result<Option<usize>> {
    let info = unsafe { mbedtls_sys::mbedtls_cipher_info_from_type(t).as_ref() };
    info.ok_or_else(|| ErrorKind::CipherNotFound.into())
        .map(|info| {
            if info.iv_size == 0 {
                None
            } else {
                Some(info.iv_size as usize)
            }
        })
}

/// Returns the block size of the cipher.
pub fn block_size(t: CipherType) -> Result<usize> {
    let info = unsafe { mbedtls_sys::mbedtls_cipher_info_from_type(t).as_ref() };
    info.ok_or_else(|| ErrorKind::CipherNotFound.into())
        .map(|info| info.block_size as usize)
}

fn check_ret(ret: c_int) -> Result<()> {
    match ret {
        0 => Ok(()),
        mbedtls_sys::MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA => Err(ErrorKind::CipherInvalidArgs.into()),
        x => Err(ErrorKind::CipherError(x).into()),
    }
}

fn iv_opt(iv: Option<&[u8]>) -> (Option<&[u8]>, *const u8, usize) {
    iv.map_or_else(
        || (None, ::std::ptr::null(), 0),
        |iv| (Some(iv), iv.as_ptr(), iv.len()),
    )
}

/// Represents a cipher context.
#[derive(Debug)]
pub struct CipherContext {
    ctx: *mut mbedtls_sys::mbedtls_cipher_context_t,
    cipher_info: CipherInfo,
}

#[derive(Debug)]
pub struct CipherInfo {
    key_bitlen: usize,
    iv_size: usize,
    block_size: usize,
}

impl CipherContext {
    pub fn new(t: CipherType) -> Result<CipherContext> {
        use mbedtls_sys::mbedtls_cipher_context_t as RawContext;
        let mut ctx: RawContext;

        ctx = unsafe { mem::uninitialized() };
        let ptr = &mut ctx as *mut RawContext;

        unsafe {
            mbedtls_sys::mbedtls_cipher_init(ptr);
            mbedtls_sys::mbedtls_cipher_info_from_type(t).as_ref()
        }.ok_or_else(|| ErrorKind::CipherNotFound.into())
            .and_then(|info| {
                let ret = unsafe { mbedtls_sys::mbedtls_cipher_setup(ptr, info) };

                if ret == mbedtls_sys::MBEDTLS_ERR_CIPHER_ALLOC_FAILED {
                    Err(ErrorKind::CipherAllocFailed.into())
                } else {
                    check_ret(ret)
                }.map(|_| CipherContext {
                    ctx: ptr,
                    cipher_info: CipherInfo {
                        key_bitlen: key_bitlen(t).unwrap(),
                        block_size: block_size(t).unwrap(),
                        iv_size: iv_size(t).unwrap().unwrap_or(0),
                    },
                })
            })
    }

    #[inline]
    pub fn block_size(&self) -> usize {
        self.cipher_info.block_size as usize
    }

    #[inline]
    pub fn iv_size(&self) -> usize {
        self.cipher_info.iv_size as usize
    }

    #[inline]
    pub fn key_bitlen(&self) -> usize {
        self.cipher_info.key_bitlen as usize
    }

    pub fn set_iv(&mut self, iv: &[u8]) -> Result<()> {
        let ret = unsafe { mbedtls_sys::mbedtls_cipher_set_iv(self.ctx, iv.as_ptr(), iv.len()) };
        check_ret(ret)
    }

    pub fn set_key(&mut self, key: &[u8], mode: Mode) -> Result<()> {
        let ret = unsafe {
            mbedtls_sys::mbedtls_cipher_setkey(
                self.ctx,
                key.as_ptr(),
                self.key_bitlen() as c_int,
                mode.into(),
            )
        };
        check_ret(ret)
    }

    pub fn update(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize> {
        debug_assert!(output.len() >= input.len() + self.block_size());
        debug_assert!(output.len() <= c_int::max_value() as usize);

        let mut outl = output.len();
        let inl = input.len();

        let ret = unsafe {
            mbedtls_sys::mbedtls_cipher_update(
                self.ctx,
                input.as_ptr(),
                inl,
                output.as_mut_ptr(),
                &mut outl,
            )
        };

        match ret {
            0 => Ok(outl as usize),
            mbedtls_sys::MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA => {
                Err(ErrorKind::CipherInvalidData.into())
            }
            mbedtls_sys::MBEDTLS_ERR_CIPHER_FEATURE_UNAVAILABLE => {
                Err(ErrorKind::UnsupportedMode.into())
            }
            x => Err(ErrorKind::CipherError(x).into()),
        }
    }

    pub fn update_ad(&mut self, ad: &[u8]) -> Result<()> {
        let ret = unsafe { mbedtls_sys::mbedtls_cipher_update_ad(self.ctx, ad.as_ptr(), ad.len()) };
        check_ret(ret)
    }

    pub fn write_tag(&mut self, tag: &mut [u8]) -> Result<()> {
        let ret =
            unsafe { mbedtls_sys::mbedtls_cipher_write_tag(self.ctx, tag.as_mut_ptr(), tag.len()) };
        check_ret(ret)
    }

    pub fn check_tag(&self, tag: &[u8]) -> Result<()> {
        let ret =
            unsafe { mbedtls_sys::mbedtls_cipher_check_tag(self.ctx, tag.as_ptr(), tag.len()) };
        check_ret(ret)
    }

    pub fn reset(&mut self) -> Result<()> {
        let ret = unsafe { mbedtls_sys::mbedtls_cipher_reset(self.ctx) };
        check_ret(ret)
    }

    pub fn finish(&mut self, output: &mut [u8]) -> Result<usize> {
        debug_assert!(output.len() >= self.block_size());

        let mut outl = output.len();

        let ret =
            unsafe { mbedtls_sys::mbedtls_cipher_finish(self.ctx, output.as_mut_ptr(), &mut outl) };

        match ret {
            0 => Ok(outl),
            mbedtls_sys::MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA => {
                Err(ErrorKind::CipherInvalidData.into())
            }
            mbedtls_sys::MBEDTLS_ERR_CIPHER_FULL_BLOCK_EXPECTED => {
                Err(ErrorKind::CipherFullBlockExpected.into())
            }
            mbedtls_sys::MBEDTLS_ERR_CIPHER_INVALID_PADDING => {
                Err(ErrorKind::CipherInvalidPadding.into())
            }
            x => Err(ErrorKind::CipherError(x).into()),
        }
    }

    pub fn auth_decrypt(
        &self,
        iv: Option<&[u8]>,
        ad: &[u8],
        tag: &[u8],
        input: &[u8],
        output: &mut [u8],
    ) -> Result<usize> {
        debug_assert!(output.len() >= input.len());
        debug_assert!(output.len() <= c_int::max_value() as usize);

        let (_iv, iv_ptr, iv_len) = iv_opt(iv);

        let mut outl = output.len();

        let ret = unsafe {
            mbedtls_sys::mbedtls_cipher_auth_decrypt(
                self.ctx,
                iv_ptr,
                iv_len,
                ad.as_ptr(),
                ad.len(),
                input.as_ptr(),
                input.len(),
                output.as_mut_ptr(),
                &mut outl,
                tag.as_ptr(),
                tag.len(),
            )
        };

        match ret {
            0 => Ok(outl),
            mbedtls_sys::MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA => {
                Err(ErrorKind::CipherInvalidData.into())
            }
            mbedtls_sys::MBEDTLS_ERR_CIPHER_AUTH_FAILED => Err(ErrorKind::CipherAuthFailed.into()),
            x => Err(ErrorKind::CipherError(x).into()),
        }
    }

    pub fn auth_encrypt(
        &self,
        iv: Option<&[u8]>,
        ad: &[u8],
        tag: &mut [u8],
        input: &[u8],
        output: &mut [u8],
    ) -> Result<usize> {
        debug_assert!(output.len() >= input.len());
        debug_assert!(output.len() <= c_int::max_value() as usize);

        let (_iv, iv_ptr, iv_len) = iv_opt(iv);
        let mut outl = output.len();

        let ret = unsafe {
            mbedtls_sys::mbedtls_cipher_auth_encrypt(
                self.ctx,
                iv_ptr,
                iv_len,
                ad.as_ptr(),
                ad.len(),
                input.as_ptr(),
                input.len(),
                output.as_mut_ptr(),
                &mut outl,
                tag.as_mut_ptr(),
                tag.len(),
            )
        };

        match ret {
            0 => Ok(outl),
            mbedtls_sys::MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA => {
                Err(ErrorKind::CipherInvalidData.into())
            }
            x => Err(ErrorKind::CipherError(x).into()),
        }
    }

    pub fn crypt<'a, T: Into<Option<&'a [u8]>>>(
        &self,
        iv: T,
        input: &[u8],
        output: &mut [u8],
    ) -> Result<usize> {
        debug_assert!(output.len() >= input.len() + self.block_size());
        debug_assert!(output.len() <= c_int::max_value() as usize);

        let (_iv, iv_ptr, iv_len) = iv_opt(iv.into());
        let mut outl = output.len();

        let ret = unsafe {
            mbedtls_sys::mbedtls_cipher_crypt(
                self.ctx,
                iv_ptr,
                iv_len,
                input.as_ptr(),
                input.len(),
                output.as_mut_ptr(),
                &mut outl,
            )
        };

        match ret {
            0 => Ok(outl),
            mbedtls_sys::MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA => {
                Err(ErrorKind::CipherInvalidData.into())
            }
            mbedtls_sys::MBEDTLS_ERR_CIPHER_FULL_BLOCK_EXPECTED => {
                Err(ErrorKind::CipherFullBlockExpected.into())
            }
            mbedtls_sys::MBEDTLS_ERR_CIPHER_INVALID_PADDING => {
                Err(ErrorKind::CipherInvalidPadding.into())
            }
            x => Err(ErrorKind::CipherError(x).into()),
        }
    }
}

impl Drop for CipherContext {
    fn drop(&mut self) {
        // unsafe { mbedtls_sys::mbedtls_cipher_free(self.ctx) };
    }
}

#[cfg(test)]
mod test {
    #![allow(dead_code, unused_variables)]
    use super::*;

    #[test]
    fn cipher_info() {
        let ctx = CipherContext::new(CipherType::MBEDTLS_CIPHER_AES_128_CBC).unwrap();
        assert_eq!(ctx.key_bitlen(), 128);
        assert_eq!(ctx.iv_size(), 16);
        assert_eq!(ctx.block_size(), 16);
    }

    #[test]
    fn init() {
        CipherContext::new(CipherType::MBEDTLS_CIPHER_AES_128_CBC).unwrap();
    }

    #[test]
    fn set_key() {
        let mut ctx = CipherContext::new(CipherType::MBEDTLS_CIPHER_AES_128_CBC).unwrap();

        let key = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F";

        ctx.set_key(key, Mode::Encrypt).unwrap();
    }

    #[test]
    fn crypt() {
        let mut ctx = CipherContext::new(CipherType::MBEDTLS_CIPHER_AES_128_CBC).unwrap();

        let key = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F";
        let iv = b"\x00\x01\x02\x03\x04\x05\x06\x07\x00\x01\x02\x03\x04\x05\x06\x07";
        let data = b"Some Crypto Text";

        ctx.set_key(key, Mode::Encrypt).unwrap();

        let mut out = vec![0; data.len() + ctx.block_size()];

        ctx.crypt(&iv[..], data, &mut out).unwrap();

        assert_eq!(b"\xB4\xB9\xE7\x30\xD6\xD6\xF7\xDE\x77\x3F\x1C\xFF\xB3\x3E\x44\x5A\x91\xD7\x27\x62\x87\x4D\
        \xFB\x3C\x5E\xC4\x59\x72\x4A\xF4\x7C\xA1", &out[..]);
    }
}

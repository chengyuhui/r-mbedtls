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

/// Represents a cipher context.
pub struct CipherContext {
    ctx: *mut mbedtls_sys::mbedtls_cipher_context_t,
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
                }.map(|_| CipherContext { ctx: ptr })
            })
    }

    #[inline]
    pub fn block_size(&self) -> usize {
        unsafe { mbedtls_sys::wrapper::wrapper_get_block_size(self.ctx) as usize }
    }

    #[inline]
    pub fn iv_size(&self) -> usize {
        unsafe { mbedtls_sys::wrapper::wrapper_get_iv_size(self.ctx) as usize }
    }

    #[inline]
    pub fn key_bitlen(&self) -> usize {
        unsafe { mbedtls_sys::wrapper::wrapper_get_key_bitlen(self.ctx) as usize }
    }

    pub fn set_iv(&mut self, iv: &[u8]) -> Result<()> {
        let ret = unsafe { mbedtls_sys::mbedtls_cipher_set_iv(self.ctx, iv.as_ptr(), iv.len()) };
        check_ret(ret)
    }

    pub fn set_key(&mut self, key: &[u8], mode: Mode) -> Result<()> {
        let len = key.len() as c_int * 8;
        let ret =
            unsafe { mbedtls_sys::mbedtls_cipher_setkey(self.ctx, key.as_ptr(), len, mode.into()) };
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
        let ret = { mbedtls_sys::mbedtls_cipher_update_ad(self.ctx, ad.as_ptr(), ad.len()) };
        check_ret(ret)
    }

    pub fn write_tag(&mut self, tag: &mut [u8]) -> Result<()> {
        let ret = { mbedtls_sys::mbedtls_cipher_write_tag(self.ctx, tag.as_mut_ptr(), tag.len()) };
        check_ret(ret)
    }

    pub fn reset(&mut self) -> Result<()> {
        let ret = { mbedtls_sys::mbedtls_cipher_reset(self.ctx) };
        check_ret(ret)
    }
}

impl Drop for CipherContext {
    fn drop(&mut self) {
        unsafe { mbedtls_sys::mbedtls_cipher_free(self.ctx) };
    }
}

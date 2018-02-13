use std::os::raw::c_int;

error_chain! {
    errors {
        CipherNotFound
        CipherSetupFailed
        InvalidIv
        InvalidKey
        CipherKeyError(code: c_int)
        UnsupportedMode
        InvalidData
        CipherUpdateError(code: c_int)
    }
}

use std::os::raw::c_int;

error_chain! {
    errors {
        CipherNotFound
        CipherSetupFailed
        CipherInvalidArgs
        UnsupportedMode
        CipherInvalidData
        CipherError(code: c_int)
    }
}

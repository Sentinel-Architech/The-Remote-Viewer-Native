use std::os::raw::c_char;
use std::ffi::CString;

#[no_mangle]
pub extern "C" fn trv_core_init() {
    println!("[TRV NATIVE] Sovereign Core Engine Initialized.");
}

#[no_mangle]
pub extern "C" fn trv_generate_identity() -> *mut c_char {
    use ed25519_dalek::SigningKey;
    use rand_core::OsRng;

    let mut csprng = OsRng;
    let signing_key = SigningKey::generate(&mut csprng);
    let pubkey_hex = hex::encode(signing_key.verifying_key().to_bytes());

    CString::new(pubkey_hex).unwrap().into_raw()
}

#[no_mangle]
pub extern "C" fn trv_free_string(s: *mut c_char) {
    if !s.is_null() {
        unsafe {
            let _ = CString::from_raw(s);
        }
    }
}

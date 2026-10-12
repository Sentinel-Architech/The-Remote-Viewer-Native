use std::os::raw::{c_char, c_ulonglong};
use std::ffi::{CStr, CString};
use rusqlite::Connection;

pub struct CoreStore {
    conn: Connection,
}

#[no_mangle]
pub extern "C" fn trv_core_init() -> *mut CoreStore {
    match Connection::open("trv_sovereign_local.db") {
        Ok(conn) => {
            let _ = conn.execute(
                "CREATE TABLE IF NOT EXISTS local_ledger (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp INTEGER NOT NULL,
                    payload TEXT NOT NULL
                );",
                [],
            );
            Box::into_raw(Box::new(CoreStore { conn }))
        }
        Err(_) => std::ptr::null_mut(),
    }
}

#[no_mangle]
pub extern "C" fn trv_store_record(store: *mut CoreStore, timestamp: c_ulonglong, payload: *const c_char) -> bool {
    if store.is_null() || payload.is_null() {
        return false;
    }
    unsafe {
        let store_ref = &*store;
        let c_str = CStr::from_ptr(payload);
        if let Ok(str_slice) = c_str.to_str() {
            let res = store_ref.conn.execute(
                "INSERT INTO local_ledger (timestamp, payload) VALUES (?1, ?2)",
                rusqlite::params![timestamp as u64, str_slice],
            );
            return res.is_ok();
        }
    }
    false
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

pub mod gfx_vortex;
pub use gfx_vortex::*;

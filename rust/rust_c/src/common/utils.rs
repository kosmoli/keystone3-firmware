use alloc::string::{String, ToString};
use core::slice;

use super::ffi::CSliceFFI;
use super::free::Free;
use crate::{extract_array, extract_ptr_with_type};
use cstr_core::{CStr, CString};
use cty::c_char;

use crate::common::types::{PtrString, PtrT};

pub fn convert_c_char(s: String) -> PtrString {
    CString::new(s).unwrap().into_raw()
}

pub unsafe fn recover_c_char(s: *mut c_char) -> String {
    // NULL pointer is treated as an empty string. This is safe and
    // matches the convention used by KOSMO FFI callers that pass
    // `(char *)NULL` for optional parameters like `key_name` in
    // `generate_ur_crypto_hd_key`. Catching NULL here prevents a
    // SIGSEGV in CStr::from_ptr when the C side legitimately has
    // no string to provide.
    if s.is_null() {
        return String::new();
    }
    CStr::from_ptr(s).to_str().unwrap_or_default().to_string()
}

pub unsafe fn check_recover_c_char_lossy(s: *mut c_char) -> (bool, String) {
    // Same NULL tolerance as recover_c_char.
    if s.is_null() {
        return (true, String::new());
    }
    match CStr::from_ptr(s).to_str() {
        Ok(value) => (true, value.to_string()),
        Err(_) => (false, CStr::from_ptr(s).to_string_lossy().into_owned()),
    }
}

pub unsafe fn recover_c_array<'a, T: Free>(s: PtrT<CSliceFFI<T>>) -> &'a [T] {
    let boxed_keys = extract_ptr_with_type!(s, CSliceFFI<T>);
    extract_array!(boxed_keys.data, T, boxed_keys.size)
}

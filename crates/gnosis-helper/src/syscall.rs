use std::{ffi::CString, io, path::Path};

pub(crate) fn path_cstring(path: &Path) -> io::Result<CString> {
    CString::new(path.as_os_str().as_encoded_bytes()).map_err(io::Error::other)
}

pub(crate) fn cvt(result: libc::c_int) -> io::Result<libc::c_int> {
    if result == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(result)
    }
}

pub(crate) fn cvt_long(result: libc::c_long) -> io::Result<libc::c_long> {
    if result == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(result)
    }
}

pub(crate) fn cvt_ssize(result: libc::ssize_t) -> io::Result<usize> {
    if result == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(result as usize)
    }
}

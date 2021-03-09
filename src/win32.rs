#![cfg(feature = "windows")]

use std::ptr::null_mut;
use winapi::um::handleapi::CloseHandle;
use winapi::um::winnt::{HANDLE, TOKEN_ADJUST_PRIVILEGES, TOKEN_QUERY, TOKEN_PRIVILEGES, SE_PRIVILEGE_ENABLED};
use winapi::um::processthreadsapi::{OpenProcessToken, GetCurrentProcess};

use crate::error::Error;

#[derive(Eq, PartialEq, Debug)]
pub struct Win32Handle(pub HANDLE);

impl Win32Handle {
    pub fn new(handle: HANDLE) -> Option<Self> {
        if !handle.is_null() {
            Some(Self(handle))
        } else {
            None
        }
    }
}

impl Drop for Win32Handle {
    fn drop(&mut self) {
        unsafe { CloseHandle(self.0) };
    }
}

pub fn enable_privilege(priv_name: &str) -> Result<(), Error> {
    let token = {
        let mut token: HANDLE = null_mut();
        if unsafe {
            OpenProcessToken(
                GetCurrentProcess(),
                TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                &mut token,
            )
        } != FALSE
        {
            Win32Handle::new(token).ok_or(Error::NullPointer)
        } else {
            error!("OpenProcessToken() failed");
            Err(Error::win32_error())
        }?
    };

    let mut luid = unsafe { std::mem::MaybeUninit::<LUID>::zeroed().assume_init() };

    if unsafe {
        LookupPrivilegeValueW(null_mut(), priv_name.to_wide_null().as_ptr(), &mut luid) != FALSE
    } {
        Ok(())
    } else {
        error!("LookupPrivilegeValueW() failed ");
        Err(Error::win32_error())
    }?;

    let mut token_state =
        unsafe { std::mem::MaybeUninit::<TOKEN_PRIVILEGES>::zeroed().assume_init() };
    token_state.PrivilegeCount = 1;
    token_state.Privileges[0].Luid = luid;
    token_state.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if unsafe {
        AdjustTokenPrivileges(
            token.0,
            FALSE,
            &mut token_state,
            std::mem::size_of::<TOKEN_PRIVILEGES>() as u32,
            null_mut(),
            null_mut(),
        ) != FALSE
    } {
        Ok(())
    } else {
        error!("AdjustTokenPrivileges() failed");
        Err(Error::win32_error())
    }
}

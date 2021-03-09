#![cfg(feature = "windows")]

use std::ffi::CString;
use std::ptr::null_mut;
use winapi::shared::minwindef::{DWORD, FALSE, HMODULE};
use winapi::shared::ntdef::LUID;
use winapi::um::handleapi::CloseHandle;
use winapi::um::libloaderapi::{GetModuleHandleA, GetProcAddress};
use winapi::um::memoryapi::{VirtualProtectEx, WriteProcessMemory};
use winapi::um::processthreadsapi::{GetCurrentProcess, OpenProcessToken};
use winapi::um::winbase::LookupPrivilegeValueW;
use winapi::um::winnt::{
    HANDLE, SE_PRIVILEGE_ENABLED, TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES, TOKEN_QUERY,
};

use log::{debug, error};

use crate::error::Error;
use crate::string::*;
use winapi::um::securitybaseapi::AdjustTokenPrivileges;

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

pub fn write_process_memory<P, T>(
    handle: &Win32Handle,
    address: *const P,
    buffer: *const T,
    len: usize,
) -> Result<(), Error> {
    debug!(
        "WriteProcessMemory: dst: {:#?} src: {:#?} size: {:#x}",
        address, buffer, len
    );
    if unsafe {
        WriteProcessMemory(
            handle.0,
            address as *mut _,
            buffer as *const _,
            len,
            null_mut(),
        ) != 0
    } {
        Ok(())
    } else {
        Err(Error::win32_error())
    }
}

pub fn virtual_protect_ex(
    handle: &Win32Handle,
    ptr: *const u8,
    size: usize,
    prot_flags: DWORD,
) -> Result<DWORD, Error> {
    let mut old_protect: DWORD = 0;

    if unsafe {
        VirtualProtectEx(handle.0, ptr as *mut _, size, prot_flags, &mut old_protect) == FALSE
    } {
        Err(Error::win32_error())
    } else {
        Ok(old_protect)
    }
}

pub fn get_module_handle(module_name: &str) -> Result<HMODULE, Error> {
    let module_name = CString::new(module_name).map_err(|_| Error::NullPointer)?;
    let pointer = unsafe { GetModuleHandleA(module_name.as_ptr()) };
    if pointer.is_null() {
        Err(Error::win32_error())
    } else {
        Ok(pointer)
    }
}

pub fn get_proc_address(module: &HMODULE, proc_name: &str) -> Result<*const u8, Error> {
    let proc_name = CString::new(proc_name).map_err(|_| Error::NullPointer)?;

    let address = unsafe { GetProcAddress(*module, proc_name.as_ptr()) };

    if address.is_null() {
        Err(Error::win32_error())
    } else {
        Ok(address as *const u8)
    }
}

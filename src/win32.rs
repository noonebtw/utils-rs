#![cfg(feature = "windows")]

use std::ffi::CString;
use std::ptr::null_mut;
use winapi::shared::minwindef::{DWORD, FALSE, HMODULE};
use winapi::shared::ntdef::LUID;
use winapi::um::handleapi::CloseHandle;
use winapi::um::libloaderapi::{GetModuleHandleA, GetProcAddress};
use winapi::um::memoryapi::{VirtualProtectEx, WriteProcessMemory, ReadProcessMemory};
use winapi::um::processthreadsapi::{GetCurrentProcess, OpenProcessToken};
use winapi::um::winbase::LookupPrivilegeValueW;
use winapi::um::winnt::{
    HANDLE, SE_PRIVILEGE_ENABLED, TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES, TOKEN_QUERY,
};

use log::{debug, error};

use crate::error::Error;
use crate::string::*;
use winapi::um::securitybaseapi::AdjustTokenPrivileges;
use std::sync::Arc;
use std::mem::size_of;
use std::marker::PhantomData;
use std::convert::TryFrom;


#[cfg(test)]
mod tests {
    use log::info;
    use crate::error::Error;
    use crate::win32::{RemotePtr, Win32Handle};
    use winapi::um::processthreadsapi::GetCurrentProcess;
    use std::mem::size_of;

    fn init() {
        let _ = simple_logger::SimpleLogger::new().init();
    }

    #[test]
    fn test_remote_ptr() -> Result<(), Error> {
        init();

        let obj = vec![0usize, 1, 2, 3];
        let mut asdf = RemotePtr::<u8>::new(
            Win32Handle::new(unsafe {GetCurrentProcess()}).unwrap(),
            obj.as_ptr() as usize );

        info!("{:?}", obj);
        unsafe {asdf.write_as::<usize>(5)?};
        info!("{:?}", obj);

        assert_eq!(obj.as_slice(), &[5usize, 1, 2, 3]);

        unsafe {asdf.offset(size_of::<usize>() as isize * 2).write_as::<usize>(5)?};
        info!("{:?}", obj);

        assert_eq!(obj.as_slice(), &[5usize, 1, 5, 3]);

        unsafe {asdf.write_buffer(&[7usize, 7])?};
        info!("{:?}", obj);

        assert_eq!(obj.as_slice(), &[7usize, 7, 5, 3]);

        Ok(())
    }
}



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

    pub fn get(&self) -> HANDLE {
        self.0
    }
}

impl Drop for Win32Handle {
    fn drop(&mut self) {
        unsafe { CloseHandle(self.0) };
    }
}

pub struct RemotePtr<T> {
    handle: Arc<Win32Handle>,
    address: usize,
    phantom: PhantomData<T>,
}

impl<T> RemotePtr<T> {
    pub fn new(handle: Win32Handle, address: usize) -> Self {
        Self {
            handle: Arc::new(handle),
            address,
            phantom: PhantomData,
        }
    }

    pub fn new_with_arc(handle: Arc<Win32Handle>, address: usize) -> Self {
        Self {
            handle,
            address,
            phantom: PhantomData,
        }
    }

    pub fn address(&self) -> usize {
        self.address
    }

    pub unsafe fn read(&self) -> Result<T, Error> {
        let mut buffer = std::mem::MaybeUninit::<T>::zeroed().assume_init();
        read_process_memory(&self.handle, self.address as *const u8, &mut buffer, size_of::<T>())?;

        Ok(buffer)
    }

    pub unsafe fn read_as<P>(&self) -> Result<P, Error> {
        let mut buffer = std::mem::MaybeUninit::<P>::zeroed().assume_init();
        read_process_memory(&self.handle, self.address as *const u8, &mut buffer, size_of::<P>())?;

        Ok(buffer)
    }

    pub unsafe fn read_bytes(&self, count: usize) -> Result<Vec<u8>, Error> {
        let mut buffer = Vec::<u8>::with_capacity(count);
        buffer.resize(count, 0);

        read_process_memory(&self.handle, self.address as *const u8, buffer.as_mut_ptr(), buffer.len() * size_of::<T>())?;

        Ok(buffer)
    }

    pub unsafe fn read_buffer<P>(&self, buffer: &mut [P]) -> Result<(), Error> {
        read_process_memory(&self.handle, self.address as *const u8, buffer.as_mut_ptr(), buffer.len() * size_of::<P>())
    }

    pub unsafe fn write(&mut self, val: T) -> Result<(), Error> {
        write_process_memory(&self.handle, self.address as *const u8, &val as *const T, size_of::<T>())
    }

    pub unsafe fn write_as<P>(&mut self, val: P) -> Result<(), Error> {
        write_process_memory(&self.handle, self.address as *const u8, &val as *const P, size_of::<P>())
    }

    pub unsafe fn write_buffer<P>(&mut self, buffer: &[P]) -> Result<(), Error> {
        write_process_memory(&self.handle, self.address as *const u8, buffer.as_ptr(), buffer.len() * size_of::<P>())
    }

    pub unsafe fn offset(&self, count: isize) -> Self {
        let offset = count * size_of::<T>() as isize;

        let new_address = if offset.is_negative() {
            self.address.checked_sub(usize::try_from(offset.abs()).unwrap())
        } else {
            self.address.checked_add(usize::try_from(offset.abs()).unwrap())
        }.expect("overflow growing pointer");

        Self {
            handle: self.handle.clone(),
            address: new_address,
            phantom: PhantomData,
        }
    }

    pub unsafe fn add(mut self, count: usize) -> Self {
        self.address += count * size_of::<T>();
        self
    }

    pub unsafe fn sub(mut self, count: usize) -> Self {
        self.address -= count * size_of::<T>();
        self
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

pub fn read_process_memory<P, T>(
    handle: &Win32Handle,
    address: *const P,
    buffer: *mut T,
    len: usize,
) -> Result<(), Error> {
    debug!(
        "ReadProcessMemory: dst: {:#?} src: {:#?} size: {:#x}",
        address, buffer, len
    );
    if unsafe {
        ReadProcessMemory(
            handle.0,
            address as *mut _,
            buffer as *mut _,
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

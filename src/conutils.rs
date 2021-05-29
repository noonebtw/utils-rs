use winapi::um::consoleapi::AllocConsole;
use winapi::um::winuser::{ShowWindow, SW_SHOW};
use winapi::um::wincon::{GetConsoleWindow, FreeConsole};
use winapi::shared::windef::HWND;
use winapi::um::errhandlingapi::GetLastError;

use log::{info, error};

use crate::error;

pub fn show_console() -> error::Result<()> {
    unsafe {
        let result = AllocConsole();
        if result == 0 {
            FreeConsole();
            let result = AllocConsole();

            if result == 0 {
                error!("failed to allocate console, LastError: {:#}", GetLastError());
                return Err(error::Error::win32_error());
            }
        }

        let con_win = GetConsoleWindow();

        if con_win == std::ptr::null_mut() as HWND {
            error!("failed to find console window");
            return Err(error::Error::NullPointer);
        }

        info!("showing console window ({:?})", con_win);
        ShowWindow(con_win, SW_SHOW);
    }

    Ok(())
}
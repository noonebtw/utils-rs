#[cfg(feature = "windows")]
mod windows {
    use std::ffi::{OsStr, OsString};
    use std::os::windows::ffi::{OsStrExt, OsStringExt};

    pub trait ToWide {
        fn to_wide(&self) -> Vec<u16>;
        fn to_wide_null(&self) -> Vec<u16>;
    }

    impl<T> ToWide for T
    where
        T: AsRef<OsStr>,
    {
        fn to_wide(&self) -> Vec<u16> {
            self.as_ref().encode_wide().collect()
        }
        fn to_wide_null(&self) -> Vec<u16> {
            self.as_ref().encode_wide().chain(Some(0)).collect()
        }
    }

    pub trait FromWide {
        fn from_wide(wide: &[u16]) -> Self;
        fn from_wide_null(wide: &[u16]) -> Self;
    }

    impl FromWide for OsString {
        fn from_wide(wide: &[u16]) -> OsString {
            OsStringExt::from_wide(wide)
        }
        fn from_wide_null(wide: &[u16]) -> OsString {
            let len = wide.iter().take_while(|&&c| c != 0).count();
            OsStringExt::from_wide(&wide[..len])
        }
    }
}

#[cfg(feature = "windows")]
pub use windows::*;

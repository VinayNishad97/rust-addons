#![deny(clippy::all)]

use napi_derive::napi;

mod common;

#[cfg(target_os = "windows")]
mod windows;

#[cfg(target_os = "linux")]
mod linux;

#[cfg(target_os = "macos")]
mod macos;

pub use common::ProtectedProcessInfo;
pub use common::Finding;
#[napi]
pub fn get_hidden_processes() -> Vec<ProtectedProcessInfo> {
    #[cfg(target_os = "windows")]
    {
        return windows::get_hidden_processes();
    }

    #[cfg(target_os = "linux")]
    {
        return linux::get_hidden_processes();
    }

    #[cfg(target_os = "macos")]
    {
        return macos::get_hidden_processes();
    }

    Vec::new()
}

#[napi]

pub fn get_suspicious_processes() -> Vec<Finding> {
    #[cfg(target_os = "windows")]
    {
        return windows::get_suspicious_process();
    }

    #[cfg(target_os = "linux")]
    {
      return linux::get_suspicious_process();
    }

    #[cfg(target_os = "macos")]
    {
        return windows::get_suspicious_process();
    }

    Vec::new()
}
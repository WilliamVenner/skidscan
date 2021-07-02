// Stolen from https://github.com/willox/auxtools/tree/master/auxtools/src/sigscan
// Thanks Willox :D

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::Scanner;

#[cfg(target_os = "windows")]
mod windows;
#[cfg(target_os = "windows")]
pub use windows::Scanner;
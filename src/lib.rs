//! Pure-Rust implementation of Linux `fs-verity` Merkle tree hashing and kernel UAPI `ioctl`s.
//!
//! Compliant with `<uapi/linux/fsverity.h>` and
//! <https://www.kernel.org/doc/html/v5.4/filesystems/fsverity.html> (through Linux 6.x).

pub mod config;
pub use config::*;

#[cfg(target_os = "linux")]
pub mod linux;

pub mod digest;
pub use digest::*;

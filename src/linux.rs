//! Linux Kernel UAPI `ioctl` interface for `fs-verity` (`<uapi/linux/fsverity.h>`).
//!
//! Designed for zero-conflict portability across `glibc` (`libc::Ioctl = c_ulong`)
//! and `musl` / Android (`libc::Ioctl = c_int`), as well as 32-bit and 64-bit targets.

use std::convert::TryFrom;
use std::io;
use std::mem;
use std::os::unix::prelude::AsRawFd;

use super::config::{self, InnerHashAlgorithm, VerityConfig};

// ============================================================================
// Linux Kernel UAPI `<linux/fsverity.h>` & `<linux/fs.h>` 32-bit _IOC Constants
// Always cast to `libc::Ioctl` via `as libc::Ioctl` (bit-preserving cast) so
// command codes with bit 31 set (such as `_IOWR` -> `0xC004_6686`) never panic
// on targets where `libc::Ioctl` is signed `i32` (`musl`).
// ============================================================================

/// `_IOW('f', 133, struct fsverity_enable_arg)` (128-byte structure)
pub const FS_IOC_ENABLE_VERITY: u32 = 0x4080_6685;

/// `_IOWR('f', 134, struct fsverity_digest)` (4-byte header before flexible array)
pub const FS_IOC_MEASURE_VERITY: u32 = 0xC004_6686;

/// `_IOWR('f', 135, struct fsverity_read_metadata_arg)` (40-byte structure, Linux 5.12+)
pub const FS_IOC_READ_VERITY_METADATA: u32 = 0xC028_6687;

/// `_IOR('f', 1, long)` (`<linux/fs.h>`)
#[cfg(target_pointer_width = "64")]
pub const FS_IOC_GETFLAGS: u32 = 0x8008_6601;
#[cfg(target_pointer_width = "32")]
pub const FS_IOC_GETFLAGS: u32 = 0x8004_6601;

/// Inode flag `FS_VERITY_FL` (`0x00100000`) from `<linux/fs.h>`.
pub const FS_VERITY_FL: libc::c_long = 0x0010_0000;

/// Metadata types for `FS_IOC_READ_VERITY_METADATA` (Linux 5.12+).
#[repr(u64)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MetadataType {
    /// `FS_VERITY_METADATA_TYPE_MERKLE_TREE = 1`
    MerkleTree = 1,
    /// `FS_VERITY_METADATA_TYPE_DESCRIPTOR = 2`
    Descriptor = 2,
    /// `FS_VERITY_METADATA_TYPE_SIGNATURE = 3`
    Signature = 3,
}

/// Exact 128-byte kernel `struct fsverity_enable_arg` (`<uapi/linux/fsverity.h>`).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct fsverity_enable_arg {
    pub version: u32,
    pub hash_algorithm: u32,
    pub block_size: u32,
    pub salt_size: u32,
    pub salt_ptr: u64,
    pub sig_size: u32,
    pub __reserved1: u32,
    pub sig_ptr: u64,
    pub __reserved2: [u64; 11],
}

// Compile-time check guaranteeing exact 128-byte kernel ABI layout.
const _: () = assert!(mem::size_of::<fsverity_enable_arg>() == 128);

/// Kernel `struct fsverity_digest` with inline 64-byte buffer (`MAX_DIGEST_SIZE`).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct fsverity_digest {
    pub digest_algorithm: u16,
    pub digest_size: u16,
    pub digest: [u8; config::MAX_DIGEST_SIZE],
}

const _: () = assert!(mem::size_of::<fsverity_digest>() == 68);

/// Exact 40-byte kernel `struct fsverity_read_metadata_arg` (`<uapi/linux/fsverity.h>`).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct fsverity_read_metadata_arg {
    pub metadata_type: u64,
    pub offset: u64,
    pub length: u64,
    pub buf_ptr: u64,
    pub __reserved: u64,
}

const _: () = assert!(mem::size_of::<fsverity_read_metadata_arg>() == 40);

/// Enables `fs-verity` on the given read-only file descriptor (`FS_IOC_ENABLE_VERITY`).
pub fn fsverity_enable(
    fd: impl AsRawFd,
    block_size: usize,
    hash: InnerHashAlgorithm,
    salt: &[u8],
) -> io::Result<()> {
    fsverity_enable_with_sig(fd, block_size, hash, salt, None)
}

/// Enables `fs-verity` on the given read-only file descriptor with an optional
/// built-in PKCS#7 DER detached signature (`CONFIG_FS_VERITY_BUILTIN_SIGNATURES`).
pub fn fsverity_enable_with_sig(
    fd: impl AsRawFd,
    block_size: usize,
    hash: InnerHashAlgorithm,
    salt: &[u8],
    signature: Option<&[u8]>,
) -> io::Result<()> {
    if !block_size.is_power_of_two()
        || !(config::MIN_BLOCK_SIZE..=config::MAX_BLOCK_SIZE).contains(&block_size)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid block_size ({block_size})"),
        ));
    }
    if salt.len() > config::MAX_SALT_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("salt length ({}) exceeds MAX_SALT_SIZE", salt.len()),
        ));
    }

    let salt_ptr = if salt.is_empty() {
        0u64
    } else {
        salt.as_ptr() as usize as u64
    };

    let (sig_size, sig_ptr) = match signature {
        Some(sig) if !sig.is_empty() => {
            if sig.len() > config::MAX_SIGNATURE_SIZE {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "signature length ({}) exceeds MAX_SIGNATURE_SIZE",
                        sig.len()
                    ),
                ));
            }
            (sig.len() as u32, sig.as_ptr() as usize as u64)
        }
        _ => (0u32, 0u64),
    };

    let args = fsverity_enable_arg {
        version: 1,
        hash_algorithm: hash as u32,
        block_size: block_size as u32,
        salt_size: salt.len() as u32,
        salt_ptr,
        sig_size,
        __reserved1: 0,
        sig_ptr,
        __reserved2: [0; 11],
    };

    // SAFETY: `args` is a 128-byte `#[repr(C)]` struct whose pointers (`salt_ptr`, `sig_ptr`)
    // remain valid for the duration of the synchronous `ioctl` call.
    let ret = unsafe {
        libc::ioctl(
            fd.as_raw_fd(),
            FS_IOC_ENABLE_VERITY as libc::Ioctl,
            &args as *const fsverity_enable_arg,
        )
    };

    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Enables `fs-verity` using a validated [`VerityConfig`].
pub fn fsverity_enable_config(fd: impl AsRawFd, cfg: &VerityConfig) -> io::Result<()> {
    cfg.validate()?;
    fsverity_enable_with_sig(
        fd,
        cfg.block_size,
        cfg.algorithm,
        &cfg.salt,
        cfg.signature.as_deref(),
    )
}

/// Retrieves the kernel's `fs-verity` measurement digest (`FS_IOC_MEASURE_VERITY`) in O(1) time.
pub fn fsverity_measure(fd: impl AsRawFd) -> io::Result<(InnerHashAlgorithm, Box<[u8]>)> {
    let mut digest = fsverity_digest {
        digest_algorithm: 0,
        digest_size: config::MAX_DIGEST_SIZE as u16,
        digest: [0u8; config::MAX_DIGEST_SIZE],
    };

    // SAFETY: `digest` is a properly aligned `#[repr(C)]` buffer with `digest_size = 64`.
    let ret = unsafe {
        libc::ioctl(
            fd.as_raw_fd(),
            FS_IOC_MEASURE_VERITY as libc::Ioctl,
            &mut digest as *mut fsverity_digest,
        )
    };

    if ret < 0 {
        return Err(io::Error::last_os_error());
    }

    let algo = InnerHashAlgorithm::try_from(digest.digest_algorithm)?;
    let size = digest.digest_size as usize;
    if size > config::MAX_DIGEST_SIZE || size != algo.digest_size() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("kernel returned invalid digest_size={size} for algorithm {algo}"),
        ));
    }

    Ok((algo, Box::from(&digest.digest[..size])))
}

/// Checks whether `FS_VERITY_FL` (`0x00100000`) is set on the file's inode via `FS_IOC_GETFLAGS`.
pub fn fsverity_is_enabled(fd: impl AsRawFd) -> io::Result<bool> {
    let mut flags: libc::c_long = 0;

    // SAFETY: `FS_IOC_GETFLAGS` writes a `c_long` into `flags`.
    let ret = unsafe {
        libc::ioctl(
            fd.as_raw_fd(),
            FS_IOC_GETFLAGS as libc::Ioctl,
            &mut flags as *mut libc::c_long,
        )
    };

    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok((flags & FS_VERITY_FL) != 0)
    }
}

/// Reads raw `fs-verity` metadata (Merkle tree blocks, 256-byte descriptor, or builtin signature)
/// from the kernel via `FS_IOC_READ_VERITY_METADATA` (Linux 5.12+).
pub fn fsverity_read_metadata(
    fd: impl AsRawFd,
    metadata_type: MetadataType,
    offset: u64,
    buf: &mut [u8],
) -> io::Result<usize> {
    let arg = fsverity_read_metadata_arg {
        metadata_type: metadata_type as u64,
        offset,
        length: buf.len() as u64,
        buf_ptr: buf.as_mut_ptr() as usize as u64,
        __reserved: 0,
    };

    // SAFETY: `arg` points to `buf` for the duration of the synchronous syscall.
    let ret = unsafe {
        libc::ioctl(
            fd.as_raw_fd(),
            FS_IOC_READ_VERITY_METADATA as libc::Ioctl,
            &arg as *const fsverity_read_metadata_arg,
        )
    };

    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(ret as usize)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ioctl_constants_and_struct_abi() {
        assert_eq!(mem::size_of::<fsverity_enable_arg>(), 128);
        assert_eq!(mem::size_of::<fsverity_read_metadata_arg>(), 40);
        assert_eq!(mem::size_of::<fsverity_digest>(), 68);

        let enable_cmd = FS_IOC_ENABLE_VERITY as libc::Ioctl;
        let measure_cmd = FS_IOC_MEASURE_VERITY as libc::Ioctl;
        let meta_cmd = FS_IOC_READ_VERITY_METADATA as libc::Ioctl;

        assert_eq!(enable_cmd as u32, 0x4080_6685);
        assert_eq!(measure_cmd as u32, 0xC004_6686);
        assert_eq!(meta_cmd as u32, 0xC028_6687);
    }
}

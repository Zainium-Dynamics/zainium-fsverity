use std::convert::TryFrom;
use std::fmt;
use std::io;
use std::str::FromStr;

/// Maximum size of digests (64 bytes for SHA-512), per `<linux/fsverity.h>`.
pub const MAX_DIGEST_SIZE: usize = 64;

/// Maximum size of salts (32 bytes), per `<linux/fsverity.h>`.
pub const MAX_SALT_SIZE: usize = 32;

/// Maximum built-in PKCS#7 DER signature size (16128 bytes), per `FS_VERITY_MAX_SIGNATURE_SIZE`.
pub const MAX_SIGNATURE_SIZE: usize = 16128;

/// Maximum Merkle tree levels (`FS_VERITY_MAX_LEVELS` in `fs/verity/fsverity_private.h`).
pub const MAX_LEVELS: usize = 8;

/// Minimum supported Merkle tree block size (1 KiB, Linux 6.3+ sub-page block support).
pub const MIN_BLOCK_SIZE: usize = 1024;

/// Maximum supported Merkle tree block size (64 KiB page size on 64-bit ARM/PowerPC).
pub const MAX_BLOCK_SIZE: usize = 65536;

/// Default Merkle tree block size (4096 bytes).
pub const DEFAULT_BLOCK_SIZE: usize = 4096;

/// Enum of the supported inner hash algorithms matching `FS_VERITY_HASH_ALG_*` in `<linux/fsverity.h>`.
#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
#[repr(u8)]
pub enum InnerHashAlgorithm {
    /// `FS_VERITY_HASH_ALG_SHA256 = 1`
    Sha256 = 1,

    /// `FS_VERITY_HASH_ALG_SHA512 = 2`
    Sha512 = 2,
}

pub type HashAlgorithm = InnerHashAlgorithm;

impl Default for InnerHashAlgorithm {
    #[inline]
    fn default() -> Self {
        Self::Sha256
    }
}

impl InnerHashAlgorithm {
    /// Output digest size in bytes (32 for SHA-256, 64 for SHA-512).
    #[inline]
    pub const fn digest_size(self) -> usize {
        match self {
            Self::Sha256 => 32,
            Self::Sha512 => 64,
        }
    }

    /// Internal compression block size in bytes (64 for SHA-256, 128 for SHA-512).
    /// Used by the Linux kernel to zero-pad a non-empty salt before prepending it to each hashed block.
    #[inline]
    pub const fn hash_block_size(self) -> usize {
        match self {
            Self::Sha256 => 64,
            Self::Sha512 => 128,
        }
    }

    #[inline]
    pub const fn as_u16(self) -> u16 {
        self as u16
    }

    #[inline]
    pub const fn as_u32(self) -> u32 {
        self as u32
    }
}

impl fmt::Display for InnerHashAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sha256 => f.write_str("sha256"),
            Self::Sha512 => f.write_str("sha512"),
        }
    }
}

impl FromStr for InnerHashAlgorithm {
    type Err = io::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "sha256" | "sha-256" | "1" => Ok(Self::Sha256),
            "sha512" | "sha-512" | "2" => Ok(Self::Sha512),
            other => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("unsupported fs-verity hash algorithm: '{other}'"),
            )),
        }
    }
}

impl TryFrom<u8> for InnerHashAlgorithm {
    type Error = io::Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Sha256),
            2 => Ok(Self::Sha512),
            other => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unknown kernel fs-verity hash_algorithm id: {other}"),
            )),
        }
    }
}

impl TryFrom<u16> for InnerHashAlgorithm {
    type Error = io::Error;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        u8::try_from(value)
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("kernel fs-verity hash_algorithm id out of u8 range: {value}"),
                )
            })
            .and_then(Self::try_from)
    }
}

impl TryFrom<u32> for InnerHashAlgorithm {
    type Error = io::Error;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        u8::try_from(value)
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("kernel fs-verity hash_algorithm id out of u8 range: {value}"),
                )
            })
            .and_then(Self::try_from)
    }
}

/// Validated configuration parameters for `fs-verity` operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerityConfig {
    pub algorithm: InnerHashAlgorithm,
    pub block_size: usize,
    pub salt: Vec<u8>,
    pub signature: Option<Vec<u8>>,
}

impl Default for VerityConfig {
    fn default() -> Self {
        Self {
            algorithm: InnerHashAlgorithm::Sha256,
            block_size: DEFAULT_BLOCK_SIZE,
            salt: Vec::new(),
            signature: None,
        }
    }
}

impl VerityConfig {
    pub fn new(
        algorithm: InnerHashAlgorithm,
        block_size: usize,
        salt: Vec<u8>,
        signature: Option<Vec<u8>>,
    ) -> io::Result<Self> {
        let cfg = Self {
            algorithm,
            block_size,
            salt,
            signature,
        };
        cfg.validate()?;
        Ok(cfg)
    }

    /// Validates parameters against Linux kernel `fs/verity/enable.c` constraints.
    pub fn validate(&self) -> io::Result<()> {
        if !self.block_size.is_power_of_two()
            || !(MIN_BLOCK_SIZE..=MAX_BLOCK_SIZE).contains(&self.block_size)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "block_size ({}) must be a power of two in [{MIN_BLOCK_SIZE}..={MAX_BLOCK_SIZE}]",
                    self.block_size
                ),
            ));
        }
        if self.salt.len() > MAX_SALT_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "salt length ({}) exceeds MAX_SALT_SIZE ({MAX_SALT_SIZE})",
                    self.salt.len()
                ),
            ));
        }
        if let Some(sig) = &self.signature {
            if sig.len() > MAX_SIGNATURE_SIZE {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "signature length ({}) exceeds MAX_SIGNATURE_SIZE ({MAX_SIGNATURE_SIZE})",
                        sig.len()
                    ),
                ));
            }
        }
        Ok(())
    }

    #[inline]
    pub const fn log_blocksize(&self) -> u8 {
        self.block_size.trailing_zeros() as u8
    }
}

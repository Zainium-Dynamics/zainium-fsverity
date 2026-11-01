use sha2::digest::crypto_common::BlockSizeUser;
use sha2::digest::generic_array::typenum::Unsigned;
use sha2::digest::{
    self, Digest, FixedOutput, FixedOutputReset, HashMarker, OutputSizeUser, Reset, Update,
};
use sha2::{Sha256, Sha512};
use std::io::{self, Write};
use std::mem;

use crate::config::*;

static ZEROES: [u8; 128] = [0u8; 128];

/// Exact 256-byte kernel `struct fsverity_descriptor` layout (`<linux/fsverity.h>`).
/// All multi-byte integers are Little-Endian (`__le32`, `__le64`).
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FsVerityDescriptor {
    pub version: u8,
    pub hash_algorithm: u8,
    pub log_blocksize: u8,
    pub salt_size: u8,
    pub __reserved_0x04: u32,
    pub data_size_le: u64,
    pub root_hash: [u8; MAX_DIGEST_SIZE],
    pub salt: [u8; MAX_SALT_SIZE],
    pub __reserved: [u8; 144],
}

const _: () = assert!(mem::size_of::<FsVerityDescriptor>() == 256);

impl FsVerityDescriptor {
    pub fn new(
        algorithm: InnerHashAlgorithm,
        block_size: usize,
        file_size: u64,
        root_hash_slice: &[u8],
        salt_slice: &[u8],
    ) -> io::Result<Self> {
        if !block_size.is_power_of_two() || !(MIN_BLOCK_SIZE..=MAX_BLOCK_SIZE).contains(&block_size)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid Merkle tree block_size",
            ));
        }
        if root_hash_slice.len() > MAX_DIGEST_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "root_hash exceeds MAX_DIGEST_SIZE",
            ));
        }
        if salt_slice.len() > MAX_SALT_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "salt exceeds MAX_SALT_SIZE",
            ));
        }

        let mut root_hash = [0u8; MAX_DIGEST_SIZE];
        root_hash[..root_hash_slice.len()].copy_from_slice(root_hash_slice);

        let mut salt = [0u8; MAX_SALT_SIZE];
        salt[..salt_slice.len()].copy_from_slice(salt_slice);

        Ok(Self {
            version: 1,
            hash_algorithm: algorithm as u8,
            log_blocksize: block_size.trailing_zeros() as u8,
            salt_size: salt_slice.len() as u8,
            __reserved_0x04: 0,
            data_size_le: file_size.to_le(),
            root_hash,
            salt,
            __reserved: [0u8; 144],
        })
    }

    #[inline]
    pub fn data_size(&self) -> u64 {
        u64::from_le(self.data_size_le)
    }

    /// Safely views the 256-byte descriptor as a raw byte array.
    #[inline]
    pub fn as_bytes(&self) -> &[u8; 256] {
        // SAFETY: `FsVerityDescriptor` is `#[repr(C)]`, 256 bytes, with no uninitialized padding.
        unsafe { &*(self as *const Self as *const [u8; 256]) }
    }
}

/// Kernel `struct fsverity_formatted_digest` (`<linux/fsverity.h>`) used as the payload
/// for built-in PKCS#7 signature verification (`CONFIG_FS_VERITY_BUILTIN_SIGNATURES`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FsVerityFormattedDigest {
    pub algorithm: InnerHashAlgorithm,
    pub digest: Vec<u8>,
}

impl FsVerityFormattedDigest {
    pub const MAGIC: &'static [u8; 8] = b"FSVerity";

    pub fn new(algorithm: InnerHashAlgorithm, digest: Vec<u8>) -> io::Result<Self> {
        if digest.len() != algorithm.digest_size() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "digest length does not match algorithm digest_size",
            ));
        }
        Ok(Self { algorithm, digest })
    }

    /// Serializes into the exact binary layout expected by the Linux kernel's `.fs-verity` keyring verifier:
    /// `magic[8] ("FSVerity") || __le16 digest_algorithm || __le16 digest_size || u8 digest[]`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(12 + self.digest.len());
        out.extend_from_slice(Self::MAGIC);
        out.extend_from_slice(&self.algorithm.as_u16().to_le_bytes());
        out.extend_from_slice(&(self.digest.len() as u16).to_le_bytes());
        out.extend_from_slice(&self.digest);
        out
    }
}

/// Trait for the inner hash algorithms we support (`Sha256` and `Sha512`).
pub trait InnerHash: Digest + BlockSizeUser + Clone + Default {
    const INNER_HASH_ALGORITHM: InnerHashAlgorithm;

    fn update_padded(&mut self, data: &[u8], padded_size: usize) {
        self.update(data);
        self.update_zeroes(padded_size.checked_sub(data.len()).unwrap());
    }

    fn update_zeroes(&mut self, amount: usize) {
        let (quotient, remainder) = (amount / ZEROES.len(), amount % ZEROES.len());
        if remainder != 0 {
            self.update(&ZEROES[..remainder]);
        }
        for _ in 0..quotient {
            self.update(&ZEROES);
        }
    }
}

impl InnerHash for Sha256 {
    const INNER_HASH_ALGORITHM: InnerHashAlgorithm = InnerHashAlgorithm::Sha256;
}

impl InnerHash for Sha512 {
    const INNER_HASH_ALGORITHM: InnerHashAlgorithm = InnerHashAlgorithm::Sha512;
}

#[derive(Clone)]
struct FixedSizeBlock<D>
where
    D: InnerHash,
{
    inner: D,
    remaining: usize,
}

impl<D> FixedSizeBlock<D>
where
    D: InnerHash,
{
    fn new<S: AsRef<[u8]> + Clone + Default>(config: &FsVerityConfig<D, S>) -> Self {
        Self {
            inner: config.salted_digest(),
            remaining: config.block_size,
        }
    }

    fn append(&mut self, data: &[u8]) {
        self.inner.update(data);
        self.remaining = self.remaining.checked_sub(data.len()).unwrap();
    }

    fn fill_to_end(&mut self) {
        self.inner.update_zeroes(self.remaining);
        self.remaining = 0;
    }

    fn overflowing_append<'a>(&mut self, data: &'a [u8]) -> &'a [u8] {
        let (a, b) = data.split_at(self.remaining.min(data.len()));
        self.append(a);
        b
    }

    fn finalize_into(mut self, dest: &mut digest::Output<D>) {
        self.fill_to_end();
        self.inner.finalize_into(dest);
    }

    fn finalize_into_and_reset<S: AsRef<[u8]> + Clone + Default>(
        &mut self,
        dest: &mut digest::Output<D>,
        config: &FsVerityConfig<D, S>,
    ) {
        self.fill_to_end();
        let Self { inner, .. } = mem::replace(self, Self::new(config));
        inner.finalize_into(dest);
    }
}

#[derive(Clone)]
struct FsVerityConfig<D = Sha256, S = [u8; 0]>
where
    D: InnerHash,
    S: AsRef<[u8]> + Clone + Default,
{
    block_size: usize,
    salt: S,
    salted_digest: D,
}

impl<D, S> FsVerityConfig<D, S>
where
    D: InnerHash,
    S: AsRef<[u8]> + Clone + Default,
{
    fn new(block_size: usize, salt: S) -> Self {
        assert!(
            salt.as_ref().len() <= MAX_SALT_SIZE,
            "salt exceeds MAX_SALT_SIZE (32 bytes)"
        );
        assert!(
            block_size.is_power_of_two(),
            "block_size must be a power of two"
        );
        assert!(
            block_size >= D::OutputSize::USIZE * 2,
            "block_size must hold at least 2 digests"
        );
        assert!(D::OutputSize::USIZE <= MAX_DIGEST_SIZE);

        let mut salted_digest = <D as digest::Digest>::new();
        for chunk in salt.as_ref().chunks(D::BlockSize::USIZE) {
            salted_digest.update_padded(chunk, D::BlockSize::USIZE);
        }

        Self {
            block_size,
            salt,
            salted_digest,
        }
    }

    #[inline]
    fn salted_digest(&self) -> D {
        self.salted_digest.clone()
    }

    #[inline]
    fn inner_hash_algorithm(&self) -> InnerHashAlgorithm {
        D::INNER_HASH_ALGORITHM
    }
}

/// Streaming calculator for Linux `fs-verity` file measurements.
#[derive(Clone)]
pub struct FsVerityDigest<D = Sha256, S = [u8; 0]>
where
    D: InnerHash,
    S: AsRef<[u8]> + Clone + Default,
{
    config: FsVerityConfig<D, S>,
    levels: Vec<FixedSizeBlock<D>>,
    bytes_written: u64,
}

impl<D> FsVerityDigest<D>
where
    D: InnerHash,
{
    pub fn new() -> Self {
        Self::new_with_salt(Default::default())
    }
}

impl<D, S> FsVerityDigest<D, S>
where
    D: InnerHash,
    S: AsRef<[u8]> + Clone + Default,
{
    pub fn new_with_salt(salt: S) -> Self {
        Self::new_with_salt_and_block_size(salt, DEFAULT_BLOCK_SIZE)
    }

    pub fn new_with_salt_and_block_size(salt: S, block_size: usize) -> Self {
        let config = FsVerityConfig::new(block_size, salt);
        Self {
            config,
            levels: Vec::new(),
            bytes_written: 0,
        }
    }

    #[inline]
    pub fn inner_hash_algorithm(&self) -> InnerHashAlgorithm {
        self.config.inner_hash_algorithm()
    }

    /// Consumes the streaming state and returns both the 256-byte `FsVerityDescriptor`
    /// and the final `fs-verity` measurement digest.
    pub fn finalize_descriptor_and_digest(
        mut self,
    ) -> (FsVerityDescriptor, digest::Output<Self>) {
        let mut last_digest: digest::Output<Self> = Default::default();
        let mut overflow: &[u8] = &[];
        for mut level in self.levels.drain(..) {
            level.append(overflow);
            level.finalize_into(&mut last_digest);
            overflow = &last_digest;
        }

        let descriptor = FsVerityDescriptor::new(
            self.config.inner_hash_algorithm(),
            self.config.block_size,
            self.bytes_written,
            &last_digest,
            self.config.salt.as_ref(),
        )
        .expect("FsVerityConfig already validated descriptor invariants");

        // Per Linux kernel `fs/verity/open.c` (`fsverity_hash_buffer`), the 256-byte
        // `fsverity_descriptor` (which embeds `salt_size` and `salt[32]`) is hashed
        // directly without prepending the padded block salt.
        let mut desc_hasher = <D as digest::Digest>::new();
        desc_hasher.update(descriptor.as_bytes());
        let mut out: digest::Output<Self> = Default::default();
        desc_hasher.finalize_into(&mut out);

        (descriptor, out)
    }
}

impl<D, S> Default for FsVerityDigest<D, S>
where
    D: InnerHash,
    S: AsRef<[u8]> + Clone + Default,
{
    fn default() -> Self {
        Self::new_with_salt(Default::default())
    }
}

impl<D, S> Update for FsVerityDigest<D, S>
where
    D: InnerHash,
    S: AsRef<[u8]> + Clone + Default,
{
    fn update(&mut self, data: &[u8]) {
        self.bytes_written = self
            .bytes_written
            .checked_add(data.len() as u64)
            .expect("file size overflowed u64");

        for chunk in data.chunks(self.config.block_size) {
            let mut keep_space_for_one_digest = false;
            let mut last_digest: digest::Output<Self>;
            let mut overflow = chunk;
            for level in self.levels.iter_mut() {
                overflow = level.overflowing_append(overflow);
                if keep_space_for_one_digest {
                    if level.remaining >= D::OutputSize::USIZE {
                        assert!(overflow.is_empty());
                        break;
                    }
                } else if overflow.is_empty() {
                    break;
                }

                let mut tmp: digest::Output<Self> = Default::default();
                level.finalize_into_and_reset(&mut tmp, &self.config);
                level.append(overflow);
                last_digest = tmp;

                overflow = &last_digest;
                keep_space_for_one_digest = true;
            }

            if !overflow.is_empty() {
                assert!(self.levels.len() < MAX_LEVELS);
                let mut level = FixedSizeBlock::new(&self.config);
                level.append(overflow);
                self.levels.push(level);
            }
        }
    }
}

impl<D, S> OutputSizeUser for FsVerityDigest<D, S>
where
    D: InnerHash,
    S: AsRef<[u8]> + Clone + Default,
{
    type OutputSize = D::OutputSize;
}

impl<D, S> FixedOutput for FsVerityDigest<D, S>
where
    D: InnerHash,
    S: AsRef<[u8]> + Clone + Default,
{
    fn finalize_into(self, out: &mut digest::Output<Self>) {
        let (_desc, digest_out) = self.finalize_descriptor_and_digest();
        *out = digest_out;
    }
}

impl<D, S> BlockSizeUser for FsVerityDigest<D, S>
where
    D: InnerHash,
    S: AsRef<[u8]> + Clone + Default,
{
    type BlockSize = D::BlockSize;
}

impl<D, S> Reset for FsVerityDigest<D, S>
where
    D: InnerHash,
    S: AsRef<[u8]> + Clone + Default,
{
    fn reset(&mut self) {
        self.levels.clear();
        self.bytes_written = 0;
    }
}

impl<D, S> FixedOutputReset for FsVerityDigest<D, S>
where
    D: InnerHash,
    S: AsRef<[u8]> + Clone + Default,
{
    fn finalize_into_reset(&mut self, out: &mut digest::Output<Self>) {
        let new =
            Self::new_with_salt_and_block_size(self.config.salt.clone(), self.config.block_size);
        let old = mem::replace(self, new);
        FixedOutput::finalize_into(old, out);
    }
}

impl<D, S> Write for FsVerityDigest<D, S>
where
    D: InnerHash,
    S: AsRef<[u8]> + Clone + Default,
{
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        Update::update(self, buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<D, S> HashMarker for FsVerityDigest<D, S>
where
    D: InnerHash,
    S: AsRef<[u8]> + Clone + Default,
{
}

/// Alias for `FsVerityDigest<Sha256, S>`
pub type FsVeritySha256<S = [u8; 0]> = FsVerityDigest<Sha256, S>;

/// Alias for `FsVerityDigest<Sha512, S>`
pub type FsVeritySha512<S = [u8; 0]> = FsVerityDigest<Sha512, S>;

/// Trait object interface for runtime-selected `FsVerityDigest`.
pub trait DynFsVerityDigest: sha2::digest::DynDigest + Write {
    fn inner_hash_algorithm(&self) -> InnerHashAlgorithm;
}

impl<D: InnerHash + 'static, S: AsRef<[u8]> + Clone + Default + 'static> DynFsVerityDigest
    for FsVerityDigest<D, S>
{
    fn inner_hash_algorithm(&self) -> InnerHashAlgorithm {
        self.config.inner_hash_algorithm()
    }
}

pub fn new_dyn(inner_hash: InnerHashAlgorithm) -> Box<dyn DynFsVerityDigest> {
    match inner_hash {
        InnerHashAlgorithm::Sha256 => Box::new(FsVeritySha256::new()),
        InnerHashAlgorithm::Sha512 => Box::new(FsVeritySha512::new()),
    }
}

pub fn new_dyn_with_salt<S: AsRef<[u8]> + Clone + Default + 'static>(
    inner_hash: InnerHashAlgorithm,
    salt: S,
) -> Box<dyn DynFsVerityDigest> {
    match inner_hash {
        InnerHashAlgorithm::Sha256 => Box::new(FsVeritySha256::new_with_salt(salt)),
        InnerHashAlgorithm::Sha512 => Box::new(FsVeritySha512::new_with_salt(salt)),
    }
}

pub fn new_dyn_with_salt_and_block_size<S: AsRef<[u8]> + Clone + Default + 'static>(
    inner_hash: InnerHashAlgorithm,
    salt: S,
    block_size: usize,
) -> Box<dyn DynFsVerityDigest> {
    match inner_hash {
        InnerHashAlgorithm::Sha256 => {
            Box::new(FsVeritySha256::new_with_salt_and_block_size(salt, block_size))
        }
        InnerHashAlgorithm::Sha512 => {
            Box::new(FsVeritySha512::new_with_salt_and_block_size(salt, block_size))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_kernel_vectors_in_memory() {
        let block_size = 4096usize;
        let hashes_per_block = 4096usize / 32usize;

        let cases: Vec<(&str, &str, Vec<u8>)> = vec![
            (
                "empty",
                "3d248ca542a24fc62d1c43b916eae5016878e2533c88238480b26128a1f1af95",
                vec![],
            ),
            (
                "onebyte",
                "9845e616f7d2f7a1cd6742f0546a36d2e74d4eb8ae7d9bdc0b0df982c27861b7",
                vec![b'A'],
            ),
            (
                "oneblock",
                "3fd7a78101899a79cd337b1b4e5414be8bcb376b133370156ef6e65026d930ed",
                vec![b'A'; block_size],
            ),
            (
                "oneblockplusonebyte",
                "c0b9455d545b6b1ee5e7b227bd1ed463aaa530a4840dcd93465163a2b3aff0da",
                {
                    let mut v = vec![b'A'; block_size];
                    v.push(b'B');
                    v
                },
            ),
            (
                "hashblock_0_0",
                "f5c2b9ded1595acfe8a996795264d488dd6140531f6a01f8f8086a83fd835935",
                vec![b'A'; block_size * hashes_per_block],
            ),
            (
                "hashblock_0_-1",
                "5c00a54bd1d8341d7bbad060ff1b8e88ed2646d7bb38db6e752cd1cff66c0a78",
                vec![b'A'; block_size * hashes_per_block - 1],
            ),
            (
                "hashblock_0_1",
                "a7abb76568871169a79104d00679fae6521dfdb2a2648e380c02b10e96e217ff",
                vec![b'A'; block_size * hashes_per_block + 1],
            ),
            (
                "hashblock_-1_0",
                "c4b519068d8c8c68fd5e362fc3526c5b11e15f8eb72d4678017906f9e7f2d137",
                vec![b'A'; block_size * (hashes_per_block - 1)],
            ),
            (
                "hashblock_1_0",
                "09510d2dbb55fa16f2768165c42d19c4da43301dfaa05705b2ecb4aaa4a5686a",
                vec![b'A'; block_size * (hashes_per_block + 1)],
            ),
            (
                "hashblock_-1_-1",
                "7aa0bb537c623562f898386ac88acd319267e4ab3200f3fd1cf648cfdb4a0379",
                vec![b'A'; block_size * (hashes_per_block - 1) - 1],
            ),
            (
                "hashblock_-1_1",
                "f804e9777f91d3697ca015303c23251ad3d80205184cfa3d1066ab28cb906330",
                vec![b'A'; block_size * (hashes_per_block - 1) + 1],
            ),
            (
                "hashblock_1_-1",
                "26159b4fc68c63881c25c33b23f2583ffaa64fee411af33c3b03238eea56755c",
                vec![b'A'; block_size * (hashes_per_block + 1) - 1],
            ),
            (
                "hashblock_1_1",
                "57bed0934bf3ab4610d54938f03cff27bd0d9d76c9a77e283f9fb2b7e29c5ab8",
                vec![b'A'; block_size * (hashes_per_block + 1) + 1],
            ),
        ];

        for (name, expected_hex, payload) in cases {
            let mut hasher = new_dyn(InnerHashAlgorithm::Sha256);
            hasher.write_all(&payload).unwrap();
            let got = hex::encode(hasher.finalize());
            assert_eq!(got, expected_hex, "vector mismatch for {name}");
        }
    }

    #[test]
    fn test_formatted_digest_layout() {
        let raw = vec![0x11u8; 32];
        let fmt_digest = FsVerityFormattedDigest::new(InnerHashAlgorithm::Sha256, raw).unwrap();
        let bytes = fmt_digest.to_bytes();
        assert_eq!(&bytes[0..8], b"FSVerity");
        assert_eq!(&bytes[8..10], &[1, 0]); // __le16 algorithm = 1
        assert_eq!(&bytes[10..12], &[32, 0]); // __le16 size = 32
        assert_eq!(bytes.len(), 44);
    }
}

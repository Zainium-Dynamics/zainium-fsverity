use std::env;
use std::fs::File;
use std::io::{self, BufReader, Write};
use std::process::ExitCode;
use std::str::FromStr;

use fs_verity::{
    new_dyn_with_salt_and_block_size, InnerHashAlgorithm, VerityConfig, DEFAULT_BLOCK_SIZE,
};

#[cfg(target_os = "linux")]
use fs_verity::linux::{
    fsverity_enable_config, fsverity_is_enabled, fsverity_measure, fsverity_read_metadata,
    MetadataType,
};

fn print_usage(prog: &str) {
    eprintln!(
        "Usage:
  {prog} <FILE>...                                   (compute SHA-256 fs-verity digest for files)
  {prog} digest  <FILE> [--alg sha256|sha512] [--block-size BYTES] [--salt HEX]
  {prog} enable  <FILE> [--alg sha256|sha512] [--block-size BYTES] [--salt HEX] [--sig FILE]
  {prog} measure <FILE>
  {prog} status  <FILE>
  {prog} dump-descriptor <FILE>"
    );
}

fn parse_config_flags(args: &[String]) -> io::Result<VerityConfig> {
    let mut cfg = VerityConfig::default();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--alg" | "--hash-alg" => {
                i += 1;
                let val = args.get(i).ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, "missing value for --alg")
                })?;
                cfg.algorithm = InnerHashAlgorithm::from_str(val)?;
            }
            "--block-size" => {
                i += 1;
                let val = args.get(i).ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, "missing value for --block-size")
                })?;
                cfg.block_size = val.parse::<usize>().map_err(|e| {
                    io::Error::new(io::ErrorKind::InvalidInput, format!("invalid block size: {e}"))
                })?;
            }
            "--salt" => {
                i += 1;
                let val = args.get(i).ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, "missing value for --salt")
                })?;
                cfg.salt = hex::decode(val).map_err(|e| {
                    io::Error::new(io::ErrorKind::InvalidInput, format!("invalid hex salt: {e}"))
                })?;
            }
            "--sig" | "--signature" => {
                i += 1;
                let val = args.get(i).ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, "missing value for --sig")
                })?;
                cfg.signature = Some(std::fs::read(val)?);
            }
            other => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("unknown option '{other}'"),
                ));
            }
        }
        i += 1;
    }
    cfg.validate()?;
    Ok(cfg)
}

fn compute_file_digest(path: &str, cfg: &VerityConfig) -> io::Result<()> {
    let mut f = BufReader::with_capacity(64 * 1024, File::open(path)?);
    let mut hasher = new_dyn_with_salt_and_block_size(
        cfg.algorithm,
        cfg.salt.clone(),
        cfg.block_size,
    );
    io::copy(&mut f, &mut hasher)?;
    let algo = hasher.inner_hash_algorithm();
    let digest = hasher.finalize();
    println!("{}:{} {}", algo, hex::encode(digest), path);
    Ok(())
}

fn run() -> io::Result<()> {
    let args: Vec<String> = env::args().collect();
    let prog = args.first().map(String::as_str).unwrap_or("fs-verity");

    if args.len() < 2 {
        print_usage(prog);
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "missing arguments",
        ));
    }

    match args[1].as_str() {
        "--help" | "-h" | "help" => {
            print_usage(prog);
            Ok(())
        }
        "digest" => {
            if args.len() < 3 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "missing <FILE> for 'digest'",
                ));
            }
            let cfg = parse_config_flags(&args[3..])?;
            compute_file_digest(&args[2], &cfg)
        }
        #[cfg(target_os = "linux")]
        "enable" => {
            if args.len() < 3 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "missing <FILE> for 'enable'",
                ));
            }
            let cfg = parse_config_flags(&args[3..])?;
            let file = File::open(&args[2])?;
            fsverity_enable_config(file, &cfg)?;
            println!("fs-verity enabled on {}", &args[2]);
            Ok(())
        }
        #[cfg(target_os = "linux")]
        "measure" => {
            if args.len() < 3 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "missing <FILE> for 'measure'",
                ));
            }
            let file = File::open(&args[2])?;
            let (algo, digest) = fsverity_measure(file)?;
            println!("{}:{} {}", algo, hex::encode(digest), &args[2]);
            Ok(())
        }
        #[cfg(target_os = "linux")]
        "status" => {
            if args.len() < 3 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "missing <FILE> for 'status'",
                ));
            }
            let file = File::open(&args[2])?;
            let enabled = fsverity_is_enabled(file)?;
            println!(
                "{}: {}",
                &args[2],
                if enabled { "enabled" } else { "disabled" }
            );
            Ok(())
        }
        #[cfg(target_os = "linux")]
        "dump-descriptor" => {
            if args.len() < 3 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "missing <FILE> for 'dump-descriptor'",
                ));
            }
            let file = File::open(&args[2])?;
            let mut buf = [0u8; 256];
            let n = fsverity_read_metadata(file, MetadataType::Descriptor, 0, &mut buf)?;
            io::stdout().write_all(&buf[..n])?;
            Ok(())
        }
        _ => {
            let default_cfg = VerityConfig {
                algorithm: InnerHashAlgorithm::Sha256,
                block_size: DEFAULT_BLOCK_SIZE,
                salt: Vec::new(),
                signature: None,
            };
            for path in args.iter().skip(1) {
                compute_file_digest(path, &default_cfg)?;
            }
            Ok(())
        }
    }
}

fn main() -> ExitCode {
    if let Err(e) = run() {
        eprintln!("error: {e}");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}

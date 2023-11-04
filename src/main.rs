// SPDX-FileCopyrightText: 2023 Brian Kubisiak <brian@kubisiak.com>
//
// SPDX-License-Identifier: GPL-3.0-only

use std::io::Write;

use clap::Parser;
use sha2::Digest;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

fn nar_blob<W: Write>(
    output: &mut W,
    blob: &git2::Blob,
    executable: bool,
) -> Result<()> {
    nar_bytes(output, b"(")?;
    nar_bytes(output, b"type")?;
    nar_bytes(output, b"regular")?;

    if executable {
        nar_bytes(output, b"executable")?;
        nar_bytes(output, b"")?;
    }

    nar_bytes(output, b"contents")?;
    nar_int(output, blob.size() as u64)?;
    output.write_all(blob.content())?;

    if (blob.size() % 8) != 0 {
        nar_padding(output, blob.size())?;
    }

    nar_bytes(output, b")")?;
    Ok(())
}

fn nar_symlink<W: Write>(output: &mut W, blob: &git2::Blob) -> Result<()> {
    nar_bytes(output, b"(")?;
    nar_bytes(output, b"type")?;
    nar_bytes(output, b"symlink")?;
    nar_bytes(output, b"target")?;
    nar_int(output, blob.size() as u64)?;
    output.write_all(blob.content())?;

    if (blob.size() % 8) != 0 {
        nar_padding(output, blob.size())?;
    }

    nar_bytes(output, b")")?;
    Ok(())
}

fn is_executable(mode: i32) -> bool {
    (mode & 0o100) != 0
}

fn is_symlink(mode: i32) -> bool {
    (mode & 0o20000) != 0
}

fn nar_int<W: Write>(output: &mut W, i: u64) -> Result<()> {
    let buf: [u8; 8] = i.to_le_bytes();
    output.write_all(&buf)?;
    Ok(())
}

fn nar_padding<W: Write>(output: &mut W, len: usize) -> Result<()> {
    let padding_size = (8 - (len % 8)) % 8;
    let buf = vec![0; padding_size];
    output.write_all(&buf)?;
    Ok(())
}

fn nar_bytes<W: Write>(output: &mut W, data: &[u8]) -> Result<()> {
    nar_int(output, data.len() as u64)?;
    output.write_all(data)?;
    nar_padding(output, data.len())?;
    Ok(())
}

fn nar_tree<W: Write>(
    repo: &git2::Repository,
    output: &mut W,
    tree: &git2::Tree,
) -> Result<()> {
    let mut entries: Vec<git2::TreeEntry> = tree.iter().collect();
    // Really annoying copy here due to the limitations on type
    // inference for lifetimes in closures. This should be fixable,
    // but I'm not wasting time on it for now.
    entries.sort_by_key(|entry| entry.name_bytes().to_vec());

    nar_bytes(output, b"(")?;
    nar_bytes(output, b"type")?;
    nar_bytes(output, b"directory")?;

    for entry in entries {
        nar_bytes(output, b"entry")?;
        nar_bytes(output, b"(")?;
        nar_bytes(output, b"name")?;
        nar_bytes(output, entry.name_bytes())?;
        nar_bytes(output, b"node")?;
        match entry.kind().unwrap() {
            git2::ObjectType::Tree => {
                nar_tree(
                    repo,
                    output,
                    &entry.to_object(repo)?.peel_to_tree()?,
                )?;
            }
            git2::ObjectType::Blob => {
                if !is_symlink(entry.filemode()) {
                    nar_blob(
                        output,
                        &entry.to_object(repo)?.peel_to_blob()?,
                        is_executable(entry.filemode()),
                    )?;
                } else {
                    nar_symlink(
                        output,
                        &entry.to_object(repo)?.peel_to_blob()?,
                    )?;
                }
            }
            _ => panic!("encountered unhashable object"),
        }
        nar_bytes(output, b")")?;
    }

    nar_bytes(output, b")")?;

    Ok(())
}

fn nar_commit<W: Write>(reference: &str, output: &mut W) -> Result<()> {
    let repo = git2::Repository::open(".")?;
    let reference = repo.resolve_reference_from_short_name(reference)?;
    let tree = reference.peel_to_tree()?;
    nar_bytes(output, b"nix-archive-1")?;
    nar_tree(&repo, output, &tree)?;
    Ok(())
}

fn into_base32(output: sha2::Sha256) -> Result<String> {
    let hash = output.finalize();

    // sha256 is 32 bytes, pad with 3 bytes to 35 total (so it's
    // divisible by 5 for base32 encoding)
    let mut bytes = vec![0; 3];
    for b in hash.into_iter().rev() {
        bytes.push(b);
    }

    let mut encoding = data_encoding::Specification::new();
    // nix's alphabet is unusual
    encoding.symbols = "0123456789abcdfghijklmnpqrsvwxyz".to_string();

    let padded_result = encoding.encoding()?.encode(&bytes);
    // trim the leading 4 bytes that were produced by padding with 0s above
    Ok(padded_result[4..].to_string())
}

/// Find the fixed-output hash of a git checkout without actually
/// checking it out.
#[derive(clap::Parser, Debug)]
struct Args {
    /// Git revision to hash
    rev: String,

    /// Output a NAR to stdout instead of hashing the rev
    #[clap(short, long)]
    nar: bool,
}

fn run(args: Args) -> Result<()> {
    if args.nar {
        nar_commit(&args.rev, &mut std::io::stdout())?;
    } else {
        let mut hasher = sha2::Sha256::new();
        nar_commit(&args.rev, &mut hasher)?;
        println!("{}", into_base32(hasher)?);
    }
    Ok(())
}

fn main() -> std::process::ExitCode {
    let args = Args::parse();
    match run(args) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            std::process::ExitCode::FAILURE
        }
    }
}

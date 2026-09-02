//! Crash-recoverable, symlink-safe storage primitives for connector-owned files.

use anyhow::{bail, Context, Result};
use std::fs::{self, File, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt as _;

/// Reject an existing symlink before any connector-owned file operation.
pub fn reject_symlink(path: &Path, description: &str) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            bail!("refusing to follow a symlink for {description}")
        }
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| format!("inspect {description}")),
    }
}

/// Create a connector-owned directory and reject a symlink at the exact path.
pub fn ensure_directory(path: &Path, description: &str) -> Result<()> {
    reject_symlink(path, description)?;
    fs::create_dir_all(path).with_context(|| format!("create {description}"))?;
    let metadata = fs::symlink_metadata(path).with_context(|| format!("inspect {description}"))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        bail!("{description} is not a private connector-owned directory");
    }
    Ok(())
}

/// Open a new private file without following an existing symlink.
pub fn create_private_new(path: &Path, description: &str) -> Result<File> {
    let parent = path
        .parent()
        .context("connector storage path omitted a parent directory")?;
    reject_symlink(parent, "connector storage directory")?;
    reject_symlink(path, description)?;
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    options.mode(0o600);
    options
        .open(path)
        .with_context(|| format!("create {description}"))
}

/// Deterministic backup path retained during recoverable replacement.
pub fn backup_path(path: &Path) -> Result<PathBuf> {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .context("connector storage path omitted a UTF-8 file name")?;
    Ok(path.with_file_name(format!("{name}.bak")))
}

/// Replace a connector-owned file while always retaining a valid old or new copy.
pub fn write_recoverable(path: &Path, bytes: &[u8], description: &str) -> Result<()> {
    let parent = path
        .parent()
        .context("connector storage path omitted a parent directory")?;
    ensure_directory(parent, "connector storage directory")?;
    reject_symlink(path, description)?;
    let backup = backup_path(path)?;
    reject_symlink(&backup, "connector backup file")?;
    let temporary = parent.join(format!(
        ".{}-{}.tmp",
        path.file_name()
            .and_then(|name| name.to_str())
            .context("connector storage path omitted a UTF-8 file name")?,
        uuid::Uuid::new_v4()
    ));
    let mut file = create_private_new(&temporary, "temporary connector file")?;
    if let Err(error) = file
        .write_all(bytes)
        .and_then(|()| file.sync_all())
        .context("write and flush temporary connector file")
    {
        drop(file);
        let _ = fs::remove_file(&temporary);
        return Err(error);
    }
    drop(file);

    if backup.try_exists().context("inspect connector backup")? {
        fs::remove_file(&backup).context("remove stale connector backup")?;
    }
    let had_primary = path
        .try_exists()
        .context("inspect connector primary file")?;
    if had_primary {
        fs::rename(path, &backup).context("retain connector backup before replacement")?;
    }
    if let Err(error) = fs::rename(&temporary, path) {
        if had_primary {
            let _ = fs::rename(&backup, path);
        }
        let _ = fs::remove_file(&temporary);
        return Err(error).context("install replacement connector file");
    }

    sync_parent(path)?;

    if backup.try_exists().context("inspect connector backup")? {
        fs::remove_file(&backup).context("remove committed connector backup")?;
    }
    Ok(())
}

/// Flush the parent directory entry where the platform exposes directory fsync.
pub fn sync_parent(path: &Path) -> Result<()> {
    let parent = path
        .parent()
        .context("connector storage path omitted a parent directory")?;
    #[cfg(unix)]
    {
        File::open(parent)
            .and_then(|directory| directory.sync_all())
            .context("flush connector storage directory")?;
    }
    #[cfg(not(unix))]
    let _ = parent;
    Ok(())
}

/// Read and validate a primary file, recovering a validated backup when needed.
pub fn read_recoverable<T, F>(
    path: &Path,
    maximum_bytes: usize,
    description: &str,
    parse: F,
) -> Result<Option<T>>
where
    F: Fn(&[u8]) -> Result<T>,
{
    let parent = path
        .parent()
        .context("connector storage path omitted a parent directory")?;
    reject_symlink(parent, "connector storage directory")?;
    reject_symlink(path, description)?;
    let backup = backup_path(path)?;
    reject_symlink(&backup, "connector backup file")?;
    if path
        .try_exists()
        .context("inspect connector primary file")?
    {
        return read_bounded(path, maximum_bytes, description)
            .and_then(|bytes| parse(&bytes))
            .map(Some);
    }
    if !backup
        .try_exists()
        .context("inspect connector recovery backup")?
    {
        return Ok(None);
    }
    let value = read_bounded(&backup, maximum_bytes, "connector recovery backup")
        .and_then(|bytes| parse(&bytes))?;
    fs::rename(&backup, path).context("restore validated connector backup")?;
    sync_parent(path)?;
    Ok(Some(value))
}

/// Remove the primary and recovery backup for an exact connector-owned file.
pub fn remove_recoverable(path: &Path, description: &str) -> Result<()> {
    let parent = path
        .parent()
        .context("connector storage path omitted a parent directory")?;
    reject_symlink(parent, "connector storage directory")?;
    reject_symlink(path, description)?;
    let backup = backup_path(path)?;
    reject_symlink(&backup, "connector backup file")?;
    for candidate in [path, backup.as_path()] {
        match fs::remove_file(candidate) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error).with_context(|| format!("remove {description}")),
        }
    }
    Ok(())
}

fn read_bounded(path: &Path, maximum_bytes: usize, description: &str) -> Result<Vec<u8>> {
    let metadata = fs::symlink_metadata(path).with_context(|| format!("inspect {description}"))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        bail!("{description} is not a regular connector-owned file");
    }
    if metadata.len() > maximum_bytes as u64 {
        bail!("{description} exceeded the safety limit");
    }
    fs::read(path).with_context(|| format!("read {description}"))
}

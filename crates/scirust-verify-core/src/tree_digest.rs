//! Source-tree digesting.
//!
//! Rules (documented contract):
//!
//! * files are visited in sorted relative-path order (byte-wise);
//! * each file contributes `path\0<sha256 of content>\n` to the stream;
//! * the tree digest is the sha256 of that stream;
//! * excluded directories: `.git`, `target`, `.scirust-verify`, `node_modules`;
//! * symlinks are recorded as `path\0link <target>\n` and never followed,
//!   so a symlink cannot smuggle outside content into the identity;
//! * empty trees hash to the empty-stream digest.

use std::fs;
use std::path::Path;

use scirust_verify_model::Digest;

const EXCLUDED_DIRS: [&str; 4] = [".git", "target", ".scirust-verify", "node_modules"];

/// Computes the source-tree digest of `root`.
pub fn tree_digest(root: &Path) -> std::io::Result<Digest> {
    use sha2::Digest as _;
    let mut hasher = sha2::Sha256::new();
    let mut stack = vec![root.to_path_buf()];
    // Depth-first with sorted entries => deterministic global order.
    while let Some(dir) = stack.pop() {
        let mut entries: Vec<_> = fs::read_dir(&dir)?.collect::<Result<Vec<_>, _>>()?;
        entries.sort_by_key(|e| e.file_name());
        for entry in entries.into_iter().rev() {
            let path = entry.path();
            let rel = path.strip_prefix(root).unwrap_or(&path);
            if path.is_dir() {
                let name = entry.file_name();
                if EXCLUDED_DIRS.contains(&name.to_string_lossy().as_ref()) {
                    continue;
                }
                stack.push(path);
            } else if path.symlink_metadata()?.file_type().is_symlink() {
                let target = fs::read_link(&path)?;
                hasher.update(format!("{}\0link {}\n", rel.display(), target.display()).as_bytes());
            } else {
                let content = fs::read(&path)?;
                hasher.update(
                    format!(
                        "{}\0{}\n",
                        rel.display(),
                        Digest::sha256_hex(&content).value
                    )
                    .as_bytes(),
                );
            }
        }
    }
    Ok(Digest::sha256_hex(&hasher.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!(
            "svt-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn identical_trees_hash_identically_regardless_of_creation_order() {
        let a = scratch("a");
        let b = scratch("b");
        fs::write(a.join("zeta.txt"), b"z").unwrap();
        fs::write(a.join("alpha.txt"), b"a").unwrap();
        fs::create_dir_all(a.join("sub")).unwrap();
        fs::write(a.join("sub").join("f"), b"f").unwrap();

        fs::create_dir_all(b.join("sub")).unwrap();
        fs::write(b.join("sub").join("f"), b"f").unwrap();
        fs::write(b.join("alpha.txt"), b"a").unwrap();
        fs::write(b.join("zeta.txt"), b"z").unwrap();

        assert_eq!(tree_digest(&a).unwrap(), tree_digest(&b).unwrap());

        // Content change changes digest.
        fs::write(a.join("zeta.txt"), b"Z").unwrap();
        assert_ne!(tree_digest(&a).unwrap(), tree_digest(&b).unwrap());
    }

    #[test]
    fn excluded_directories_do_not_contribute() {
        let a = scratch("excl");
        fs::write(a.join("keep.txt"), b"k").unwrap();
        fs::create_dir_all(a.join("target")).unwrap();
        fs::write(a.join("target").join("junk"), b"junk").unwrap();
        fs::create_dir_all(a.join(".git")).unwrap();
        fs::write(a.join(".git").join("HEAD"), b"ref").unwrap();

        let b = scratch("excl2");
        fs::write(b.join("keep.txt"), b"k").unwrap();

        assert_eq!(tree_digest(&a).unwrap(), tree_digest(&b).unwrap());
    }

    #[cfg(unix)]
    #[test]
    fn symlinks_are_recorded_not_followed() {
        let a = scratch("sym");
        let outside = scratch("outside");
        fs::write(outside.join("secret"), b"sensitive-content").unwrap();
        std::os::unix::fs::symlink(outside.join("secret"), a.join("link")).unwrap();

        let d1 = tree_digest(&a).unwrap();
        fs::write(outside.join("secret"), b"TAMPERED").unwrap();
        let d2 = tree_digest(&a).unwrap();
        assert_eq!(d1, d2, "tree digest must not depend on link target content");
    }
}

from pathlib import Path


def replace_once(path: str, old: str, new: str):
    p = Path(path)
    text = p.read_text()
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{path}: expected one match, found {count}: {old[:100]!r}")
    p.write_text(text.replace(old, new, 1))

replace_once(
    "Cargo.toml",
    'zeroize = "1"\n',
    'zeroize = "1"\nlibc = "0.2"\n',
)
replace_once(
    "crates/scirust-verify-signature/Cargo.toml",
    'zeroize = { workspace = true }\n',
    'zeroize = { workspace = true }\nlibc = { workspace = true }\n',
)

replace_once(
    "crates/scirust-verify-signature/src/lib.rs",
    '''    let mut options = fs::OpenOptions::new();\n    options.write(true);\n    if force {\n        options.create(true).truncate(true);\n    } else {\n        options.create_new(true);\n    }\n    let mut file = options\n        .open(path)\n        .map_err(|e| SignatureError::io(path, e))?;\n    file.write_all(&bytes)''',
    '''    let mut options = fs::OpenOptions::new();\n    options.write(true);\n    if force {\n        options.create(true).truncate(true);\n    } else {\n        options.create_new(true);\n    }\n    #[cfg(unix)]\n    {\n        use std::os::unix::fs::OpenOptionsExt as _;\n        options.custom_flags(libc::O_NOFOLLOW);\n    }\n    let mut file = options\n        .open(path)\n        .map_err(|e| SignatureError::io(path, e))?;\n    file.write_all(&bytes)''',
)

replace_once(
    "crates/scirust-verify-signature/src/lib.rs",
    '''    #[cfg(unix)]\n    {\n        use std::os::unix::fs::OpenOptionsExt as _;\n        options.mode(0o600);\n    }\n    let result = (|| -> Result<(), SignatureError> {\n        let mut file = options\n            .open(path)\n            .map_err(|e| SignatureError::io(path, e))?;\n        file.write_all(&bytes)\n            .map_err(|e| SignatureError::io(path, e))?;\n        file.sync_all().map_err(|e| SignatureError::io(path, e))?;\n        #[cfg(unix)]\n        {\n            use std::os::unix::fs::PermissionsExt as _;\n            fs::set_permissions(path, fs::Permissions::from_mode(0o600))\n                .map_err(|e| SignatureError::io(path, e))?;\n        }\n        Ok(())\n    })();''',
    '''    #[cfg(unix)]\n    {\n        use std::os::unix::fs::OpenOptionsExt as _;\n        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);\n    }\n    let result = (|| -> Result<(), SignatureError> {\n        let mut file = options\n            .open(path)\n            .map_err(|e| SignatureError::io(path, e))?;\n        #[cfg(unix)]\n        {\n            use std::os::unix::fs::PermissionsExt as _;\n            file.set_permissions(fs::Permissions::from_mode(0o600))\n                .map_err(|e| SignatureError::io(path, e))?;\n        }\n        file.write_all(&bytes)\n            .map_err(|e| SignatureError::io(path, e))?;\n        file.sync_all().map_err(|e| SignatureError::io(path, e))?;\n        Ok(())\n    })();''',
)

p = Path("crates/scirust-verify-signature/src/lib.rs")
text = p.read_text()
marker = '''    #[test]\n    fn output_overwrite_requires_force()'''
if marker not in text:
    raise SystemExit("overwrite test marker missing")
new_test = r'''    #[cfg(unix)]
    #[test]
    fn private_key_force_overwrite_restores_restrictive_permissions() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = temp_dir("force-permissions");
        let private = dir.join("private.json");
        let public = dir.join("public.json");
        generate_keypair(&private, &public, false).unwrap();
        fs::set_permissions(&private, fs::Permissions::from_mode(0o644)).unwrap();
        generate_keypair(&private, &public, true).unwrap();
        let mode = fs::metadata(&private).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let _ = fs::remove_dir_all(dir);
    }

    #[cfg(unix)]
    #[test]
    fn force_never_follows_final_component_symlink() {
        use std::os::unix::fs::symlink;
        let dir = temp_dir("force-symlink");
        let victim = dir.join("victim.json");
        let private = dir.join("private.json");
        let public = dir.join("public.json");
        fs::write(&victim, b"do-not-touch").unwrap();
        symlink(&victim, &private).unwrap();
        assert!(matches!(
            generate_keypair(&private, &public, true),
            Err(SignatureError::SymlinkOutput(_)) | Err(SignatureError::Io { .. })
        ));
        assert_eq!(fs::read(&victim).unwrap(), b"do-not-touch");
        let _ = fs::remove_dir_all(dir);
    }

'''
text = text.replace(marker, new_test + marker, 1)
p.write_text(text)

print("keyfile open hardening applied")

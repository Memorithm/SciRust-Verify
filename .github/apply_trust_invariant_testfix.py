from pathlib import Path

p = Path("crates/scirust-verify-cli/tests/e2e.rs")
text = p.read_text()

old = '''    let manifest = project.join("scirust-verify.toml");
    let body = std::fs::read_to_string(&manifest)
        .unwrap()
        .replace("source_clean = \\"informational\\"", "source_clean = \\"required\\"");
    std::fs::write(&manifest, body).unwrap();
'''
new = '''    let manifest = project.join("scirust-verify.toml");
    let mut body = std::fs::read_to_string(&manifest).unwrap();
    body.push_str("\\n[claims]\\nsource_clean = \\"required\\"\\n");
    std::fs::write(&manifest, body).unwrap();
'''
if text.count(old) != 1:
    raise SystemExit(f"nested git test block match count={text.count(old)}")
text = text.replace(old, new, 1)

old = '''    let mut body = std::fs::read_to_string(&manifest).unwrap();
    body = body.replace(
        "profile = \\"basic\\"",
        "profile = \\"basic\\"\\ntargets = [\\"x86_64-unknown-linux-gnu\\"]\\nfeatures = [\\"demo-feature\\"]",
    );
    std::fs::write(&manifest, body).unwrap();
'''
new = '''    let mut body = std::fs::read_to_string(&manifest).unwrap();
    body = body.replace(
        "profile = \\"basic\\"",
        "profile = \\"basic\\"\\ntargets = [\\"x86_64-unknown-linux-gnu\\"]\\nfeatures = [\\"demo-feature\\"]",
    );
    body = body.replace("fmt = false", "fmt = true");
    body = body.replace("clippy = false", "clippy = true");
    std::fs::write(&manifest, body).unwrap();
'''
if text.count(old) != 1:
    raise SystemExit(f"cargo selection setup match count={text.count(old)}")
text = text.replace(old, new, 1)

old = '''    let out = cli()
        .args(["plan", project.to_str().unwrap(), "--json"])
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let doc: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let checks = doc["checks"].as_array().unwrap();
    let args_for = |id: &str| -> Vec<String> {
        let check = checks.iter().find(|c| c["id"] == id).unwrap();
        check["action"]["command"]["args"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_owned())
            .collect()
    };
    let fmt = args_for("cargo:fmt");
    assert!(!fmt.iter().any(|a| a == "--target" || a == "--features"), "{fmt:?}");
    let clippy = args_for("cargo:clippy");
    let sep = clippy.iter().position(|a| a == "--").unwrap();
    let target = clippy.iter().position(|a| a == "--target").unwrap();
    let features = clippy.iter().position(|a| a == "--features").unwrap();
    assert!(target < sep && features < sep, "{clippy:?}");
'''
new = '''    let out = cli()
        .args(["plan", project.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let text = String::from_utf8_lossy(&out.stdout);
    let fmt = text.lines().find(|line| line.contains("command: cargo fmt")).unwrap();
    assert!(!fmt.contains("--target") && !fmt.contains("--features"), "{fmt}");
    let clippy = text
        .lines()
        .find(|line| line.contains("command: cargo clippy"))
        .unwrap();
    let sep = clippy.find(" -- ").unwrap();
    let target = clippy.find("--target").unwrap();
    let features = clippy.find("--features").unwrap();
    assert!(target < sep && features < sep, "{clippy}");
'''
if text.count(old) != 1:
    raise SystemExit(f"cargo plan test block match count={text.count(old)}")
text = text.replace(old, new, 1)

p.write_text(text)
print("regression harness fixes applied")

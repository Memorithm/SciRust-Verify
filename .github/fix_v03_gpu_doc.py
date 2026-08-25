from pathlib import Path

p = Path("crates/scirust-verify-model/src/scope.rs")
s = p.read_text()
old = '''    /// Returns true if any GPU identity has been recorded — used by report
    /// generation to avoid claiming GPU coverage that does not exist.
    pub fn gpu_is_unknown(&self) -> bool {
'''
new = '''    /// Returns true when no concrete GPU identity has been recorded. Report
    /// generation uses this to avoid claiming GPU coverage that does not exist.
    pub fn gpu_is_unknown(&self) -> bool {
'''
if s.count(old) != 1:
    raise SystemExit(f"gpu_is_unknown doc anchor count={s.count(old)}")
p.write_text(s.replace(old, new, 1))
print("GPU scope documentation corrected")

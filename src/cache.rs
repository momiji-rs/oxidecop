//! Result cache: skip linting files whose (content, config, cop-set, binary)
//! tuple was seen before — rubocop's cache behavior, native speed. Entries
//! live under the user cache dir, keyed by a 128-bit FNV of the tuple; a
//! rebuild of the binary invalidates everything via its mtime+len salt.
use crate::cops::Offense;
use std::path::PathBuf;

/// FNV-1a, 64-bit; two different offset bases give us 128 key bits.
fn fnv(data: &[u8], mut hash: u64) -> u64 {
    for b in data {
        hash ^= *b as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

pub struct Cache {
    file: PathBuf,
    salt: String,
    // content-hash -> serialized offense lines, loaded once
    entries: std::collections::HashMap<u128, String>,
    fresh: std::sync::Mutex<Vec<(u128, String)>>,
}

impl Cache {
    /// None when the cache directory can't be created (cache disabled).
    pub fn open(config_text: &str, only: &Option<Vec<String>>) -> Option<Cache> {
        let base = std::env::var_os("RUBOCOP_RS_CACHE_DIR")
            .map(PathBuf::from)
            .or_else(|| {
                std::env::var_os("XDG_CACHE_HOME").map(|c| PathBuf::from(c).join("rubocop-rs"))
            })
            .or_else(|| {
                std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".cache").join("rubocop-rs"))
            })?;
        // binary identity: version + the executable's mtime/len (a rebuild
        // with the same version must not reuse entries)
        let exe = std::env::current_exe().ok()?;
        let meta = std::fs::metadata(&exe).ok()?;
        let mtime = meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let mut salt = format!("{}:{}:{}", env!("CARGO_PKG_VERSION"), mtime, meta.len());
        salt.push(':');
        salt.push_str(&only.as_ref().map(|o| o.join(",")).unwrap_or_default());
        let h1 = fnv(config_text.as_bytes(), 0xcbf29ce484222325);
        let h2 = fnv(salt.as_bytes(), h1);
        std::fs::create_dir_all(&base).ok()?;
        let file = base.join(format!("{h2:016x}.cache"));
        // ONE consolidated file per (config, cop-set, binary): loaded whole,
        // flushed once — thousands of per-entry files cost more in syscalls
        // than the linting they save.
        let mut entries = std::collections::HashMap::new();
        if let Ok(text) = std::fs::read_to_string(&file) {
            for rec in text.split('\u{0}') {
                if let Some((k, v)) = rec.split_once('\u{1}') {
                    if let Ok(key) = u128::from_str_radix(k, 16) {
                        entries.insert(key, v.to_string());
                    }
                }
            }
        }
        Some(Cache { file, salt, entries, fresh: std::sync::Mutex::new(Vec::new()) })
    }

    fn key(&self, src: &[u8]) -> u128 {
        let mut h1 = fnv(self.salt.as_bytes(), 0xcbf29ce484222325);
        h1 = fnv(src, h1);
        let mut h2 = fnv(self.salt.as_bytes(), 0x9e3779b97f4a7c15);
        h2 = fnv(src, h2);
        ((h1 as u128) << 64) | h2 as u128
    }

    /// Cached offenses for this source, if present and well-formed.
    pub fn get(&self, src: &[u8]) -> Option<Vec<Offense>> {
        let text = self.entries.get(&self.key(src))?;
        let mut out = Vec::new();
        for line in text.lines() {
            let mut it = line.splitn(5, '\t');
            let l: usize = it.next()?.parse().ok()?;
            let c: usize = it.next()?.parse().ok()?;
            let cop = crate::cops::intern_cop(it.next()?)?;
            let correctable = it.next()? == "1";
            let message = it.next()?.replace("\\t", "\t").replace("\\n", "\n").replace("\\\\", "\\");
            out.push(Offense { line: l, col: c, cop, correctable, message });
        }
        Some(out)
    }

    /// Record a fresh result (kept in memory until `flush`).
    pub fn put(&self, src: &[u8], offenses: &[Offense]) {
        let mut text = String::new();
        for o in offenses {
            let msg = o.message.replace('\\', "\\\\").replace('\t', "\\t").replace('\n', "\\n");
            text.push_str(&format!("{}\t{}\t{}\t{}\t{}\n", o.line, o.col, o.cop,
                u8::from(o.correctable), msg));
        }
        if let Ok(mut f) = self.fresh.lock() {
            f.push((self.key(src), text));
        }
    }

    /// Merge fresh entries and rewrite the cache file (atomic rename).
    pub fn flush(mut self) {
        let fresh = std::mem::take(&mut *self.fresh.lock().unwrap_or_else(|e| e.into_inner()));
        if fresh.is_empty() {
            return;
        }
        for (k, v) in fresh {
            self.entries.insert(k, v);
        }
        let mut out = String::new();
        for (k, v) in &self.entries {
            out.push_str(&format!("{k:032x}\u{1}{v}\u{0}"));
        }
        let tmp = self.file.with_extension("tmp");
        if std::fs::write(&tmp, out).is_ok() {
            let _ = std::fs::rename(&tmp, &self.file);
        }
    }
}

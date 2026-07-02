//! rubocop-rs — a fast, native RuboCop-compatible Ruby linter over the Prism
//! AST. Pattern cops are DATA (see `declarative` + `nodepattern`); imperative
//! cops are small methods under `cops/`. Fidelity is measured against RuboCop's
//! own spec suite via the `oracle/` harness. See README.md.
//!
//! This file is only the runner: argv, file discovery, config I/O, output
//! formatting, `--fix`, and the exit code. All linting lives behind
//! `cops::lint`, which is pure per file — so files lint in parallel.
mod cache;
mod config;
mod cops;
mod declarative;
mod nodepattern;
mod schema_gen;

use rayon::prelude::*;
use std::path::{Path, PathBuf};

/// Ruby files rubocop inspects by default (a pragmatic subset of its
/// `AllCops: Include`), skipping the directories it excludes by default.
/// Directory levels fan out on the rayon pool; the shebang probe on
/// extensionless files is I/O and parallelizes with them.
fn collect_files(
    path: &Path,
    depth: usize,
    includes: &[regex::Regex],
    cfg_dirs: &std::sync::Mutex<std::collections::HashSet<PathBuf>>,
) -> Vec<PathBuf> {
    if path.is_dir() {
        let skip = path
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.starts_with('.') || matches!(n, "vendor" | "node_modules" | "tmp"));
        if skip {
            return Vec::new();
        }
        let entries: Vec<PathBuf> = std::fs::read_dir(path)
            .map(|rd| rd.filter_map(|e| e.ok().map(|e| e.path())).collect())
            .unwrap_or_default();
        // note nested configs in passing — nearest-config discovery then
        // needs no extra stat sweep
        if entries.iter().any(|e| e.file_name().is_some_and(|n| n == ".rubocop.yml")) {
            if let Ok(mut set) = cfg_dirs.lock() {
                set.insert(path.to_path_buf());
            }
        }
        // fan out only near the root — deep levels have too few entries to
        // pay rayon's task overhead
        if depth < 2 {
            entries.par_iter().flat_map(|e| collect_files(e, depth + 1, includes, cfg_dirs)).collect()
        } else {
            entries.iter().flat_map(|e| collect_files(e, depth + 1, includes, cfg_dirs)).collect()
        }
    } else if is_ruby_file(path) || included_by_config(path, includes) || ruby_shebang(path) {
        vec![path.to_path_buf()]
    } else {
        Vec::new()
    }
}

/// A file the config's own `AllCops: Include` globs pull in (rubocop unions
/// user Include with its defaults; ours only ever ADD files too).
fn included_by_config(path: &Path, includes: &[regex::Regex]) -> bool {
    if includes.is_empty() {
        return false;
    }
    let rel = path.strip_prefix("./").unwrap_or(path).to_string_lossy().replace('\\', "/");
    includes.iter().any(|re| re.is_match(&rel))
}

/// rubocop's TargetFinder also picks up extensionless executables whose first
/// line is a ruby shebang.
fn ruby_shebang(path: &Path) -> bool {
    if path.extension().is_some() {
        return false;
    }
    let Ok(f) = std::fs::File::open(path) else { return false };
    use std::io::Read;
    let mut buf = [0u8; 64];
    let n = std::io::BufReader::new(f).read(&mut buf).unwrap_or(0);
    let head = &buf[..n];
    head.starts_with(b"#!")
        && head
            .split(|b| *b == b'\n')
            .next()
            .is_some_and(|l| l.windows(4).any(|w| w == b"ruby"))
}

fn is_ruby_file(path: &Path) -> bool {
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    matches!(
        path.extension().and_then(|e| e.to_str()),
        Some("rb" | "rake" | "gemspec" | "ru" | "builder" | "jbuilder" | "rabl" | "thor" | "gemfile" | "podspec")
    ) || matches!(
        name,
        "Gemfile" | "Rakefile" | "rakefile" | "Guardfile" | "Capfile" | "Berksfile" | "Brewfile"
            | "Dangerfile" | "Fastfile" | "Podfile" | "Puppetfile" | "Thorfile" | "Vagrantfile"
            | "Appraisals" | "Steepfile" | ".irbrc" | ".pryrc" | ".simplecov" | "buildfile"
    )
}

/// Load a config honoring `inherit_from` (base files first, child overrides;
/// Exclude lists merge), recursively with a depth cap.
fn load_config_chain(path: &Path, depth: usize) -> config::Config {
    let text = std::fs::read_to_string(path).unwrap_or_default();
    let child = config::Config::parse(&text);
    if (child.inherits.is_empty() && child.inherit_gems.is_empty()) || depth > 8 {
        return child;
    }
    let dir = path.parent().unwrap_or(Path::new("."));
    let mut base: Option<config::Config> = None;
    let absorb = |sub: config::Config, base: &mut Option<config::Config>| match base {
        None => *base = Some(sub),
        Some(b) => b.merge_child(sub),
    };
    // inherit_gem first (lowest precedence), best-effort via RubyGems
    for (gem, paths) in &child.inherit_gems {
        let Some(gdir) = gem_dir(gem) else { continue };
        let paths: Vec<String> =
            if paths.is_empty() { vec![".rubocop.yml".into()] } else { paths.clone() };
        for rel in paths {
            let sub = load_config_chain(&Path::new(&gdir).join(rel), depth + 1);
            absorb(sub, &mut base);
        }
    }
    for inh in &child.inherits {
        if inh.starts_with("http://") || inh.starts_with("https://") {
            continue; // remote configs unsupported
        }
        let sub = load_config_chain(&dir.join(inh), depth + 1);
        absorb(sub, &mut base);
    }
    match base {
        Some(mut b) => {
            b.merge_child(child);
            b
        }
        None => child,
    }
}

/// A gem's installation dir, via RubyGems (one subprocess per distinct gem,
/// memoized; None when ruby or the gem is unavailable).
fn gem_dir(gem: &str) -> Option<String> {
    use std::collections::HashMap;
    use std::sync::Mutex;
    static CACHE: Mutex<Option<HashMap<String, Option<String>>>> = Mutex::new(None);
    let mut guard = CACHE.lock().ok()?;
    let map = guard.get_or_insert_with(HashMap::new);
    if let Some(v) = map.get(gem) {
        return v.clone();
    }
    let out = std::process::Command::new("ruby")
        .arg("-e")
        .arg(format!("print Gem::Specification.find_by_name({gem:?}).gem_dir"))
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .filter(|s| !s.is_empty());
    map.insert(gem.to_string(), out.clone());
    out
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut paths: Vec<PathBuf> = Vec::new();
    let mut cfg_path: Option<String> = None;
    let mut fix = false;
    let mut fix_once = false;
    let mut autocorrect = false;
    let mut use_cache = true;
    let mut only: Option<Vec<String>> = None;
    let mut except: Option<Vec<String>> = None;
    let mut format = "simple".to_string();
    let mut stdin_path: Option<String> = None;
    let mut color: Option<bool> = None;
    let mut it = args[1..].iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--fix" => fix = true,
            // single lint+apply pass — the semantics of rubocop's
            // expect_correction DSL when a corrector ignore_node's (a fresh
            // `-a` run iterates instead); used by the oracle harness
            "--fix-once" => {
                fix = true;
                fix_once = true;
            }
            "-a" | "--autocorrect" | "-A" | "--autocorrect-all" => autocorrect = true,
            "--no-cache" => use_cache = false,
            "--cache" => {
                use_cache = it.next().map(|v| v == "true").unwrap_or(true);
            }
            "--only" => {
                only = it.next().map(|v| v.split(',').map(|c| c.trim().to_string()).collect());
            }
            "--except" => {
                except = it.next().map(|v| v.split(',').map(|c| c.trim().to_string()).collect());
            }
            "-f" | "--format" => {
                if let Some(v) = it.next() {
                    format = v.clone();
                }
            }
            "--stdin" => stdin_path = it.next().cloned(),
            "--color" => color = Some(true),
            "--no-color" => color = Some(false),
            "-v" | "--version" => {
                println!("rubocop-rs {}", env!("CARGO_PKG_VERSION"));
                return;
            }
            "-h" | "--help" => {
                println!("usage: rubocop-rs [options] <path>...\n\
                    \x20 --only COPS        run only the listed cops/departments\n\
                    \x20 --except COPS      skip the listed cops/departments\n\
                    \x20 -f, --format FMT   simple (default) | json | quiet\n\
                    \x20 -a, --autocorrect  apply corrections in place\n\
                    \x20 --fix              print corrected source to stdout (single file)\n\
                    \x20 --stdin PATH       lint stdin as PATH\n\
                    \x20 --cache true|false / --no-cache\n\
                    \x20 --[no-]color, -v, -h");
                return;
            }
            // back-compat: a bare .yml positional arg is the config
            s if s.ends_with(".yml") || s.ends_with(".yaml") => cfg_path = Some(s.to_string()),
            s => paths.push(PathBuf::from(s)),
        }
    }
    let use_color = color.unwrap_or_else(|| {
        use std::io::IsTerminal;
        std::io::stdout().is_terminal()
    });
    if paths.is_empty() && stdin_path.is_none() {
        eprintln!("usage: rubocop-rs [options] <path>... (see --help)");
        std::process::exit(2);
    }

    let cfg_file = cfg_path.clone().unwrap_or_else(|| ".rubocop.yml".to_string());
    let mut cfg = load_config_chain(Path::new(&cfg_file), 0);
    cfg.only = only;
    cfg.except = except;
    let cfg_text_for_cache = cfg.identity();
    let eng = cops::Engine::new(&cfg);

    // --stdin: lint the piped source as the given path
    if let Some(sp) = stdin_path {
        use std::io::Read;
        let mut src = Vec::new();
        std::io::stdin().read_to_end(&mut src).ok();
        let result = cops::lint(&src, &cfg, &eng, &sp);
        if autocorrect || fix {
            let out = if fix_once {
                let result = cops::lint(&src, &cfg, &eng, &sp);
                apply_fixes(&src, result.fixes)
            } else {
                apply_fixes_iter(src, &cfg, &eng, &sp)
            };
            use std::io::Write;
            std::io::stdout().write_all(&out).unwrap();
            return;
        }
        let total = result.offenses.len();
        print_simple(&[(sp, result.offenses)], 1, use_color, &cfg);
        std::process::exit(if total > 0 { 1 } else { 0 });
    }

    let includes = cfg.include_matchers();
    let cfg_dirs = std::sync::Mutex::new(std::collections::HashSet::new());
    let mut files: Vec<PathBuf> = Vec::new();
    for p in &paths {
        // an explicitly named file is linted regardless of extension
        if p.is_dir() {
            files.extend(collect_files(p, 0, &includes, &cfg_dirs));
        } else {
            files.push(p.clone());
        }
    }
    let cfg_dirs = cfg_dirs.into_inner().unwrap_or_default();
    // dirs the walker covered — explicit file args outside them need a stat
    // probe for nearest-config instead
    let walked_roots: Vec<PathBuf> = paths.iter().filter(|p| p.is_dir()).cloned().collect();
    // honor AllCops: Exclude (paths made config-relative, i.e. CWD-relative)
    let excludes = cfg.exclude_matchers();
    if !excludes.is_empty() {
        files.retain(|f| {
            let rel = f.strip_prefix("./").unwrap_or(f).to_string_lossy().replace('\\', "/");
            !excludes.iter().any(|re| re.is_match(&rel))
        });
    }

    // --fix rewrites a single file's source to stdout (like `rubocop -a`
    // piped); multi-file in-place correction is not wired up yet.
    if fix {
        if files.len() != 1 {
            eprintln!("--fix currently supports exactly one file");
            std::process::exit(2);
        }
        let src = std::fs::read(&files[0]).expect("read");
        let rel = files[0].strip_prefix("./").unwrap_or(&files[0]).to_string_lossy().replace('\\', "/");
        let out = if fix_once {
            let result = cops::lint(&src, &cfg, &eng, &rel);
            apply_fixes(&src, result.fixes)
        } else {
            apply_fixes_iter(src, &cfg, &eng, &rel)
        };
        use std::io::Write;
        std::io::stdout().write_all(&out).unwrap();
        return;
    }

    // -a / --autocorrect: apply fixes in place across all files
    if autocorrect {
        let corrected: usize = files
            .par_iter()
            .map(|f| {
                let rel = f.strip_prefix("./").unwrap_or(f).to_string_lossy().replace('\\', "/");
                let Ok(src) = std::fs::read(f) else { return 0 };
                let out = apply_fixes_iter(src.clone(), &cfg, &eng, &rel);
                if out != src && std::fs::write(f, &out).is_ok() {
                    1
                } else {
                    0
                }
            })
            .sum();
        println!("{} file{} corrected", corrected, if corrected == 1 { "" } else { "s" });
        return;
    }

    // Result cache: keyed by (binary identity, config, --only set, content).
    let cache = if use_cache { cache::Cache::open(&cfg_text_for_cache, &cfg.only) } else { None };

    // Nearest-config discovery (rubocop's per-file rule): a `.rubocop.yml` in
    // a subdirectory governs the files beneath it INSTEAD of the root config.
    // Only when the user didn't pin a config explicitly.
    let mut nested_engines: Vec<(PathBuf, config::Config, cops::Engine, Vec<regex::Regex>)> = Vec::new();
    let file_cfg: Vec<usize> = if cfg_path.is_none() {
        let mut dir_cfg: std::collections::HashMap<PathBuf, Option<usize>> = std::collections::HashMap::new();
        files
            .iter()
            .map(|f| {
                let mut dir = f.parent().unwrap_or(Path::new("."));
                loop {
                    // the CWD's own config is the root engine
                    if dir.as_os_str().is_empty() || dir == Path::new(".") || dir == Path::new("/") {
                        return usize::MAX;
                    }
                    if let Some(hit) = dir_cfg.get(dir) {
                        match hit {
                            Some(i) => return *i,
                            None => {}
                        }
                    } else if cfg_dirs.contains(dir)
                        || (!walked_roots.iter().any(|r| dir.starts_with(r))
                            && dir.join(".rubocop.yml").is_file())
                    {
                        let cf = dir.join(".rubocop.yml");
                        let mut sub = load_config_chain(&cf, 0);
                        sub.only = cfg.only.clone();
                        sub.except = cfg.except.clone();
                        let e = cops::Engine::new(&sub);
                        let ex = sub.exclude_matchers();
                        nested_engines.push((dir.to_path_buf(), sub, e, ex));
                        let i = nested_engines.len() - 1;
                        dir_cfg.insert(dir.to_path_buf(), Some(i));
                        return i;
                    } else {
                        dir_cfg.insert(dir.to_path_buf(), None);
                    }
                    match dir.parent() {
                        Some(p) => dir = p,
                        None => return usize::MAX,
                    }
                }
            })
            .collect()
    } else {
        Vec::new()
    };

    // Lint in parallel; report in deterministic (sorted) file order.
    let mut results: Vec<(String, Vec<cops::Offense>)> = files
        .par_iter()
        .enumerate()
        .map(|(fi, f)| {
            let display = f.display().to_string();
            let nested = file_cfg.get(fi).copied().filter(|i| *i != usize::MAX);
            let (the_cfg, the_eng, rel) = match nested {
                Some(i) => {
                    let (dir, c, e, ex) = &nested_engines[i];
                    let rel = f.strip_prefix(dir).unwrap_or(f).to_string_lossy().replace('\\', "/");
                    // the nested config's own AllCops Exclude (root excludes
                    // were applied during collection)
                    if ex.iter().any(|re| re.is_match(&rel)) {
                        return (display, Vec::new());
                    }
                    (c, e, rel)
                }
                None => {
                    let rel = f.strip_prefix("./").unwrap_or(f).to_string_lossy().replace('\\', "/");
                    (&cfg, &eng, rel)
                }
            };
            // nested-config files skip the cache: its key is salted with the
            // ROOT config only
            let meta = if nested.is_none() && cache.is_some() {
                std::fs::metadata(f).ok().map(|m| {
                    let mt = m
                        .modified()
                        .ok()
                        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                        .map(|d| d.as_nanos() as u64)
                        .unwrap_or(0);
                    (mt, m.len())
                })
            } else {
                None
            };
            // warm path: an unchanged (mtime, len) stat reuses the cached
            // result without reading the file
            if let (Some(c), Some((mt, ln))) = (&cache, meta) {
                if let Some(hit) = c.get_by_meta(&rel, mt, ln) {
                    return (display, hit);
                }
            }
            match std::fs::read(f) {
                Ok(src) => {
                    if nested.is_none() {
                        if let Some(c) = &cache {
                            if let Some(hit) = c.get(&src) {
                                return (display, hit);
                            }
                        }
                    }
                    let offenses = cops::lint(&src, the_cfg, the_eng, &rel).offenses;
                    if nested.is_none() {
                        if let Some(c) = &cache {
                            c.put(&src, &offenses, meta.map(|(mt, ln)| (rel.as_str(), mt, ln)));
                        }
                    }
                    (display, offenses)
                }
                Err(e) => {
                    eprintln!("rubocop-rs: cannot read {display}: {e}");
                    (display, Vec::new())
                }
            }
        })
        .collect();
    results.sort_by(|a, b| a.0.cmp(&b.0));
    if let Some(c) = cache {
        c.flush();
    }

    let total: usize = results.iter().map(|(_, o)| o.len()).sum();
    match format.as_str() {
        "json" | "j" => print_json(&results, &cfg),
        "quiet" | "q" => print_simple(&results, usize::MAX, false, &cfg),
        _ => print_simple(&results, results.len(), use_color, &cfg),
    }

    if std::env::var_os("RUBOCOP_RS_TIMING").is_some() {
        let ms = |a: &std::sync::atomic::AtomicU64| a.load(std::sync::atomic::Ordering::Relaxed) as f64 / 1e6;
        eprintln!("timing (cpu-ms summed across threads):");
        eprintln!("  parse  {:9.1}", ms(&cops::T_PARSE));
        eprintln!("  prep   {:9.1}", ms(&cops::T_PREP));
        eprintln!("  text   {:9.1}", ms(&cops::T_TEXT));
        eprintln!("  visit  {:9.1}", ms(&cops::T_VISIT));
        eprintln!("  post   {:9.1}", ms(&cops::T_POST));
    }

    std::process::exit(if total > 0 { 1 } else { 0 });
}

/// Apply autocorrect edits right-to-left, skipping overlaps.
/// rubocop reruns its correctors until the source stops changing (long lines
/// re-break, one insertion per line per pass); mirror that with a capped loop.
fn apply_fixes_iter(src: Vec<u8>, cfg: &config::Config, eng: &cops::Engine, rel: &str) -> Vec<u8> {
    let mut cur = src;
    for _ in 0..200 {
        let result = cops::lint(&cur, cfg, eng, rel);
        if result.fixes.is_empty() {
            return cur;
        }
        let out = apply_fixes(&cur, result.fixes);
        if out == cur {
            return cur;
        }
        cur = out;
    }
    cur
}

fn apply_fixes(src: &[u8], mut fixes: Vec<cops::Fix>) -> Vec<u8> {
    let mut out = src.to_vec();
    fixes.sort_by(|a, b| b.0.cmp(&a.0)); // descending by start
    let mut last_start = usize::MAX;
    for (s, e, rep) in fixes {
        if s <= e && e <= out.len() && e <= last_start {
            out.splice(s..e, rep.iter().copied());
            last_start = s;
        }
    }
    out
}

/// rubocop's simple formatter (headers per offending file, summary line).
/// `nfiles == usize::MAX` marks quiet mode (offenses only, no summary).
fn print_simple(results: &[(String, Vec<cops::Offense>)], nfiles: usize, color: bool, cfg: &config::Config) {
    let quiet = nfiles == usize::MAX;
    let mut total = 0usize;
    let mut correctable = 0usize;
    for (path, offenses) in results {
        if offenses.is_empty() {
            continue;
        }
        println!("== {path} ==");
        for o in offenses {
            let c = if o.correctable { correctable += 1; "[Correctable] " } else { "" };
            let sev = severity_letter(cfg.severity_word(o.cop));
            let msg = if color {
                // like rubocop's simple formatter: `...` spans render yellow
                let mut out = String::new();
                let mut inside = false;
                for part in o.message.split('`') {
                    if inside {
                        out.push_str("\x1b[33m");
                        out.push_str(part);
                        out.push_str("\x1b[0m");
                    } else {
                        out.push_str(part);
                    }
                    inside = !inside;
                }
                out
            } else {
                o.message.clone()
            };
            println!("{sev}:{:>3}:{:>3}: {}{}: {}", o.line, o.col, c, o.cop, msg);
        }
        total += offenses.len();
    }
    if quiet {
        return;
    }
    println!("\n{nfiles} file{} inspected, {total} offense{} detected{}",
        if nfiles == 1 { "" } else { "s" },
        if total == 1 { "" } else { "s" },
        if correctable > 0 { format!(", {correctable} offense{} autocorrectable", if correctable == 1 { "" } else { "s" }) } else { String::new() });
}

fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\t' => out.push_str("\\t"),
            '\r' => out.push_str("\\r"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

/// rubocop's JSON formatter schema (location carries the start position).
fn severity_letter(word: &str) -> char {
    match word {
        "info" => 'I',
        "refactor" => 'R',
        "warning" => 'W',
        "error" => 'E',
        "fatal" => 'F',
        _ => 'C',
    }
}

fn print_json(results: &[(String, Vec<cops::Offense>)], cfg: &config::Config) {
    let mut files = Vec::new();
    let mut total = 0usize;
    for (path, offenses) in results {
        total += offenses.len();
        let offs: Vec<String> = offenses
            .iter()
            .map(|o| {
                let sev = cfg.severity_word(o.cop);
                format!(
                    "{{\"severity\":\"{sev}\",\"message\":\"{}\",\"cop_name\":\"{}\",\"corrected\":false,\"correctable\":{},\"location\":{{\"start_line\":{},\"start_column\":{},\"line\":{},\"column\":{}}}}}",
                    json_escape(&o.message), o.cop, o.correctable, o.line, o.col, o.line, o.col
                )
            })
            .collect();
        files.push(format!(
            "{{\"path\":\"{}\",\"offenses\":[{}]}}",
            json_escape(path),
            offs.join(",")
        ));
    }
    println!(
        "{{\"metadata\":{{\"rubocop_version\":\"{}\",\"ruby_engine\":\"rubocop-rs\"}},\"files\":[{}],\"summary\":{{\"offense_count\":{total},\"target_file_count\":{n},\"inspected_file_count\":{n}}}}}",
        env!("CARGO_PKG_VERSION"),
        files.join(","),
        n = results.len()
    );
}

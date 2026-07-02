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
fn collect_files(path: &Path, depth: usize) -> Vec<PathBuf> {
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
        // fan out only near the root — deep levels have too few entries to
        // pay rayon's task overhead
        if depth < 2 {
            entries.par_iter().flat_map(|e| collect_files(e, depth + 1)).collect()
        } else {
            entries.iter().flat_map(|e| collect_files(e, depth + 1)).collect()
        }
    } else if is_ruby_file(path) || ruby_shebang(path) {
        vec![path.to_path_buf()]
    } else {
        Vec::new()
    }
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
    if child.inherits.is_empty() || depth > 8 {
        return child;
    }
    let dir = path.parent().unwrap_or(Path::new("."));
    let mut base: Option<config::Config> = None;
    for inh in &child.inherits {
        if inh.starts_with("http://") || inh.starts_with("https://") {
            continue; // remote configs unsupported
        }
        let sub = load_config_chain(&dir.join(inh), depth + 1);
        match &mut base {
            None => base = Some(sub),
            Some(b) => b.merge_child(sub),
        }
    }
    match base {
        Some(mut b) => {
            b.merge_child(child);
            b
        }
        None => child,
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut paths: Vec<PathBuf> = Vec::new();
    let mut cfg_path: Option<String> = None;
    let mut fix = false;
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
            let out = apply_fixes(&src, result.fixes);
            use std::io::Write;
            std::io::stdout().write_all(&out).unwrap();
            return;
        }
        let total = result.offenses.len();
        print_simple(&[(sp, result.offenses)], 1, use_color);
        std::process::exit(if total > 0 { 1 } else { 0 });
    }

    let mut files: Vec<PathBuf> = Vec::new();
    for p in &paths {
        // an explicitly named file is linted regardless of extension
        if p.is_dir() {
            files.extend(collect_files(p, 0));
        } else {
            files.push(p.clone());
        }
    }
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
        let result = cops::lint(&src, &cfg, &eng, &rel);
        let out = apply_fixes(&src, result.fixes);
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
                let result = cops::lint(&src, &cfg, &eng, &rel);
                if result.fixes.is_empty() {
                    return 0;
                }
                let out = apply_fixes(&src, result.fixes);
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

    // Lint in parallel; report in deterministic (sorted) file order.
    let mut results: Vec<(String, Vec<cops::Offense>)> = files
        .par_iter()
        .map(|f| {
            let display = f.display().to_string();
            let rel = f.strip_prefix("./").unwrap_or(f).to_string_lossy().replace('\\', "/");
            match std::fs::read(f) {
                Ok(src) => {
                    if let Some(c) = &cache {
                        if let Some(hit) = c.get(&src) {
                            return (display, hit);
                        }
                    }
                    let offenses = cops::lint(&src, &cfg, &eng, &rel).offenses;
                    if let Some(c) = &cache {
                        c.put(&src, &offenses);
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
        "json" | "j" => print_json(&results),
        "quiet" | "q" => print_simple(&results, usize::MAX, false),
        _ => print_simple(&results, results.len(), use_color),
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
fn print_simple(results: &[(String, Vec<cops::Offense>)], nfiles: usize, color: bool) {
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
            // Lint's default severity is warning, everything else convention.
            let sev = if o.cop.starts_with("Lint/") { 'W' } else { 'C' };
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
fn print_json(results: &[(String, Vec<cops::Offense>)]) {
    let mut files = Vec::new();
    let mut total = 0usize;
    for (path, offenses) in results {
        total += offenses.len();
        let offs: Vec<String> = offenses
            .iter()
            .map(|o| {
                let sev = if o.cop.starts_with("Lint/") { "warning" } else { "convention" };
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

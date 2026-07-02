//! rubocop-rs — a fast, native RuboCop-compatible Ruby linter over the Prism
//! AST. Pattern cops are DATA (see `declarative` + `nodepattern`); imperative
//! cops are small methods under `cops/`. Fidelity is measured against RuboCop's
//! own spec suite via the `oracle/` harness. See README.md.
//!
//! This file is only the runner: argv, file discovery, config I/O, output
//! formatting, `--fix`, and the exit code. All linting lives behind
//! `cops::lint`, which is pure per file — so files lint in parallel.
mod config;
mod cops;
mod declarative;
mod nodepattern;
mod schema_gen;

use rayon::prelude::*;
use std::path::{Path, PathBuf};

/// Ruby files rubocop inspects by default (a pragmatic subset of its
/// `AllCops: Include`), skipping the directories it excludes by default.
fn collect_files(path: &Path, out: &mut Vec<PathBuf>) {
    if path.is_dir() {
        let skip = path
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.starts_with('.') || matches!(n, "vendor" | "node_modules" | "tmp"));
        if skip {
            return;
        }
        let mut entries: Vec<PathBuf> = std::fs::read_dir(path)
            .map(|rd| rd.filter_map(|e| e.ok().map(|e| e.path())).collect())
            .unwrap_or_default();
        entries.sort();
        for e in entries {
            collect_files(&e, out);
        }
    } else if is_ruby_file(path) || ruby_shebang(path) {
        out.push(path.to_path_buf());
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
    let mut only: Option<Vec<String>> = None;
    let mut it = args[1..].iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--fix" => fix = true,
            "--only" => {
                only = it.next().map(|v| v.split(',').map(|c| c.trim().to_string()).collect());
            }
            // back-compat: a bare .yml positional arg is the config
            s if s.ends_with(".yml") || s.ends_with(".yaml") => cfg_path = Some(s.to_string()),
            s => paths.push(PathBuf::from(s)),
        }
    }
    if paths.is_empty() {
        eprintln!("usage: rubocop-rs <path>... [config.yml] [--fix]");
        std::process::exit(2);
    }

    let cfg_file = cfg_path.clone().unwrap_or_else(|| ".rubocop.yml".to_string());
    let mut cfg = load_config_chain(Path::new(&cfg_file), 0);
    cfg.only = only;
    let eng = cops::Engine::new(&cfg);

    let mut files: Vec<PathBuf> = Vec::new();
    for p in &paths {
        // an explicitly named file is linted regardless of extension
        if p.is_dir() {
            collect_files(p, &mut files);
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
        let mut out = src.clone();
        let mut fixes = result.fixes;
        fixes.sort_by(|a, b| b.0.cmp(&a.0)); // descending by start
        for (s, e, rep) in fixes {
            if s <= e && e <= out.len() {
                out.splice(s..e, rep.iter().copied());
            }
        }
        use std::io::Write;
        std::io::stdout().write_all(&out).unwrap();
        return;
    }

    // Lint in parallel; report in deterministic (sorted) file order.
    let mut results: Vec<(String, Vec<cops::Offense>)> = files
        .par_iter()
        .map(|f| {
            let display = f.display().to_string();
            let rel = f.strip_prefix("./").unwrap_or(f).to_string_lossy().replace('\\', "/");
            match std::fs::read(f) {
                Ok(src) => (display, cops::lint(&src, &cfg, &eng, &rel).offenses),
                Err(e) => {
                    eprintln!("rubocop-rs: cannot read {display}: {e}");
                    (display, Vec::new())
                }
            }
        })
        .collect();
    results.sort_by(|a, b| a.0.cmp(&b.0));

    let mut total = 0usize;
    let mut correctable = 0usize;
    for (path, offenses) in &results {
        if offenses.is_empty() {
            continue;
        }
        println!("== {path} ==");
        for o in offenses {
            let c = if o.correctable { correctable += 1; "[Correctable] " } else { "" };
            // Lint's default severity is warning, everything else convention.
            let sev = if o.cop.starts_with("Lint/") { 'W' } else { 'C' };
            println!("{sev}:{:>3}:{:>3}: {}{}: {}", o.line, o.col, c, o.cop, o.message);
        }
        total += offenses.len();
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

    let nfiles = results.len();
    println!("\n{nfiles} file{} inspected, {total} offense{} detected{}",
        if nfiles == 1 { "" } else { "s" },
        if total == 1 { "" } else { "s" },
        if correctable > 0 { format!(", {correctable} offense{} autocorrectable", if correctable == 1 { "" } else { "s" }) } else { String::new() });
    std::process::exit(if total > 0 { 1 } else { 0 });
}

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
    } else if is_ruby_file(path) {
        out.push(path.to_path_buf());
    }
}

fn is_ruby_file(path: &Path) -> bool {
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    matches!(path.extension().and_then(|e| e.to_str()), Some("rb" | "rake" | "gemspec"))
        || matches!(name, "Gemfile" | "Rakefile")
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

    let cfg_text = cfg_path
        .and_then(|p| std::fs::read_to_string(p).ok())
        .or_else(|| std::fs::read_to_string(".rubocop.yml").ok())
        .unwrap_or_default();
    let mut cfg = config::Config::parse(&cfg_text);
    cfg.only = only;

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
        let result = cops::lint(&src, &cfg);
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
            match std::fs::read(f) {
                Ok(src) => (display, cops::lint(&src, &cfg).offenses),
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

    let nfiles = results.len();
    println!("\n{nfiles} file{} inspected, {total} offense{} detected{}",
        if nfiles == 1 { "" } else { "s" },
        if total == 1 { "" } else { "s" },
        if correctable > 0 { format!(", {correctable} offense{} autocorrectable", if correctable == 1 { "" } else { "s" }) } else { String::new() });
    std::process::exit(if total > 0 { 1 } else { 0 });
}

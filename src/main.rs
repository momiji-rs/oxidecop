//! rubocop-rs — a fast, native RuboCop-compatible Ruby linter over the Prism
//! AST. Pattern cops are DATA (see `declarative` + `nodepattern`); imperative
//! cops are small methods under `cops/`. Fidelity is measured against RuboCop's
//! own spec suite via the `oracle/` harness. See README.md.
//!
//! This file is only the runner: argv, file/config I/O, output formatting, and
//! `--fix` application. All linting lives behind `cops::lint`.
mod config;
mod cops;
mod declarative;
mod nodepattern;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let path = args.get(1).expect("usage: rubocop-rs-poc <file.rb> [config.yml]");
    let src = std::fs::read(path).expect("read");

    // config: explicit 2nd arg, else ./.rubocop.yml, else empty
    let cfg_text = args
        .get(2)
        .and_then(|p| std::fs::read_to_string(p).ok())
        .or_else(|| std::fs::read_to_string(".rubocop.yml").ok())
        .unwrap_or_default();
    let cfg = config::Config::parse(&cfg_text);

    let result = cops::lint(&src, &cfg);

    // --fix: apply autocorrect edits right-to-left (non-overlapping) and print
    // the corrected source, like `rubocop -a`.
    if args.iter().any(|a| a == "--fix") {
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

    println!("== {path} ==");
    let mut correctable = 0;
    for o in &result.offenses {
        let c = if o.correctable { correctable += 1; "[Correctable] " } else { "" };
        println!("C:{:>3}:{:>3}: {}{}: {}", o.line, o.col, c, o.cop, o.message);
    }
    let n = result.offenses.len();
    println!("\n1 file inspected, {n} offense{} detected{}",
        if n == 1 { "" } else { "s" },
        if correctable > 0 { format!(", {correctable} offense{} autocorrectable", if correctable == 1 { "" } else { "s" }) } else { String::new() });
}

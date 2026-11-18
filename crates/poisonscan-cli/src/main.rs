#![forbid(unsafe_code)]

use std::fs;
use std::io::{self, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use poisonscan_core::output::{render, Format};
use poisonscan_core::{Rule, RuleSet, Scanner, Trust, Verdict};
use poisonscan_sources::{Directory, EnvelopeSource, JsonLines};


#[derive(Parser)]
#[command(name = "poisonscan", version, about = "Detect collection-to-LLM poisoning (indirect prompt injection, RAG corpus poisoning)")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Scan envelopes (JSON Lines) from a file or stdin ("-").
    Scan {
        #[arg(default_value = "-")]
        input: String,
        #[command(flatten)]
        opts: ScanOpts,
    },
    /// Scan a directory of raw files (one document per file).
    ScanDir {
        path: PathBuf,
        /// Trust level of this source: low|medium|high
        #[arg(long, default_value = "low")]
        trust: String,
        #[command(flatten)]
        opts: ScanOpts,
    },
    /// Like scan, but print every finding with a neutralised excerpt of the matched
    /// text (analyst use: excerpts may contain hostile text, keep them out of SIEMs).
    Explain {
        #[arg(default_value = "-")]
        input: String,
        #[arg(long, default_value = "rules")]
        rules: PathBuf,
    },
    /// Rule pack tooling.
    Rules {
        #[command(subcommand)]
        cmd: RulesCmd,
    },
}

#[derive(clap::Args)]
struct ScanOpts {
    /// Rule directory (searched recursively for *.yml / *.yaml).
    #[arg(long, default_value = "rules")]
    rules: PathBuf,
    /// Output format: native|ocsf|ecs
    #[arg(long, default_value = "native")]
    format: Format,
    /// Only emit documents whose verdict is at least this: allow|flag|quarantine
    #[arg(long, default_value = "flag")]
    min_verdict: String,
    /// Max bytes scanned per document.
    #[arg(long, default_value_t = 2 * 1024 * 1024)]
    max_bytes: usize,
    /// Worker threads (default 2, to stay light on shared hosts; 0 = all cores).
    #[arg(long, default_value_t = 2)]
    threads: usize,
    /// Documents per batch. Memory is bounded by batch x max-bytes.
    #[arg(long, default_value_t = 256)]
    batch: usize,
}

#[derive(Subcommand)]
enum RulesCmd {
    /// Validate every rule file (schema, regex, ids, test examples present).
    Lint { #[arg(default_value = "rules")] dir: PathBuf },
    /// Run each rule's positive/negative examples, and an optional corpus check.
    Test {
        #[arg(default_value = "rules")]
        dir: PathBuf,
        /// Corpus root with poisoned/ and benign/ subdirectories.
        #[arg(long)]
        corpus: Option<PathBuf>,
    },
}

fn rule_files(dir: &Path) -> Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for e in fs::read_dir(&d).with_context(|| format!("reading {}", d.display()))? {
            let p = e?.path();
            if p.is_dir() {
                stack.push(p);
            } else if matches!(p.extension().and_then(|x| x.to_str()), Some("yml" | "yaml")) {
                out.push(p);
            }
        }
    }
    out.sort();
    Ok(out)
}

fn load_rules(dir: &Path) -> Result<Vec<(PathBuf, Rule)>> {
    rule_files(dir)?
        .into_iter()
        .map(|p| {
            let text = fs::read_to_string(&p)?;
            let r = Rule::from_yaml(&p.display().to_string(), &text)?;
            Ok((p, r))
        })
        .collect()
}

fn load_ruleset(dir: &Path) -> Result<RuleSet> {
    let rules = load_rules(dir)?.into_iter().map(|(_, r)| r).collect();
    Ok(RuleSet::new(rules)?)
}

fn parse_trust(s: &str) -> Result<Trust> {
    Ok(match s {
        "low" => Trust::Low,
        "medium" => Trust::Medium,
        "high" => Trust::High,
        _ => bail!("trust must be low|medium|high"),
    })
}

fn verdict_rank(v: Verdict) -> u8 {
    match v {
        Verdict::Allow => 0,
        Verdict::Flag => 1,
        Verdict::Quarantine => 2,
    }
}

/// One unit of work: either a raw JSON line (parsed in the worker) or an
/// already-built envelope (directory adapter).
enum Job {
    Line(usize, String),
    Env(Result<poisonscan_core::Envelope>),
}

/// Pulls up to `n` jobs from the input. Reading stays sequential (I/O);
/// parsing and scanning run in parallel.
trait JobSource {
    fn next_batch(&mut self, n: usize, batch: &mut Vec<Job>);
}

impl<R: io::BufRead> JobSource for JsonLines<R> {
    fn next_batch(&mut self, n: usize, batch: &mut Vec<Job>) {
        while batch.len() < n {
            match self.next_raw() {
                None => break,
                Some(Ok((no, line))) => batch.push(Job::Line(no, line)),
                Some(Err(e)) => batch.push(Job::Env(Err(e))),
            }
        }
    }
}

impl JobSource for Directory {
    fn next_batch(&mut self, n: usize, batch: &mut Vec<Job>) {
        while batch.len() < n {
            match self.next_envelope() {
                None => break,
                Some(r) => batch.push(Job::Env(r)),
            }
        }
    }
}

enum Outcome {
    Report(Box<poisonscan_core::ScanReport>),
    Error(String),
}

fn run_scan(src: &mut dyn JobSource, opts: &ScanOpts) -> Result<ExitCode> {
    use rayon::prelude::*;

    let rules = load_ruleset(&opts.rules)?;
    let scanner = Scanner::new(&rules).with_limits(poisonscan_core::Limits { max_bytes: opts.max_bytes });
    let min = match opts.min_verdict.as_str() {
        "allow" => 0,
        "flag" => 1,
        "quarantine" => 2,
        _ => bail!("min-verdict must be allow|flag|quarantine"),
    };
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(opts.threads)
        .build()
        .context("thread pool")?;
    let stdout = io::stdout();
    let mut out = BufWriter::new(stdout.lock());
    let (mut total, mut emitted, mut errors) = (0u64, 0u64, 0u64);
    let mut batch = Vec::with_capacity(opts.batch);
    loop {
        batch.clear();
        src.next_batch(opts.batch, &mut batch);
        if batch.is_empty() {
            break;
        }
        // par_drain keeps input order in the collected Vec: output is deterministic.
        let results: Vec<Outcome> = pool.install(|| {
            batch
                .par_drain(..)
                .map(|job| {
                    let env = match job {
                        Job::Line(no, line) => poisonscan_sources::parse_line(no, &line),
                        Job::Env(r) => r,
                    };
                    match env {
                        Err(e) => Outcome::Error(format!("skipped: {e:#}")),
                        Ok(env) => match scanner.scan(&env) {
                            Ok(r) => Outcome::Report(Box::new(r)),
                            Err(e) => Outcome::Error(format!("{}: {e}", env.id)),
                        },
                    }
                })
                .collect()
        });
        let now = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0);
        for o in results {
            match o {
                Outcome::Error(msg) => {
                    errors += 1;
                    eprintln!("poisonscan: {msg}");
                }
                Outcome::Report(report) => {
                    total += 1;
                    if verdict_rank(report.verdict) >= min {
                        emitted += 1;
                        serde_json::to_writer(&mut out, &render(&report, opts.format, now))?;
                        out.write_all(b"\n")?;
                    }
                }
            }
        }
    }
    out.flush()?;
    eprintln!("poisonscan: {total} document(s) scanned, {emitted} reported, {errors} error(s), {} rule(s) [{}]", rules.len(), rules.fingerprint);
    Ok(if errors > 0 { ExitCode::from(2) } else { ExitCode::SUCCESS })
}

fn run_explain(input: &str, rules_dir: &Path) -> Result<ExitCode> {
    let rules = load_ruleset(rules_dir)?;
    let scanner = Scanner::new(&rules);
    let reader: Box<dyn io::BufRead> = if input == "-" {
        Box::new(BufReader::new(io::stdin()))
    } else {
        Box::new(BufReader::new(fs::File::open(input).with_context(|| input.to_string())?))
    };
    let mut src = JsonLines::new(reader);
    let mut out = BufWriter::new(io::stdout().lock());
    while let Some(env) = src.next_envelope() {
        let env = env?;
        let (report, excerpts) = scanner.explain(&env)?;
        if report.findings.is_empty() {
            continue;
        }
        let rule_titles: std::collections::HashMap<&str, &str> =
            rules.rules().iter().map(|r| (r.id.as_str(), r.title.as_str())).collect();
        serde_json::to_writer(
            &mut out,
            &serde_json::json!({
                "document_id": report.document_id,
                "source_uri": report.source_uri,
                "score": report.score,
                "verdict": report.verdict,
                "findings": report.findings.iter().map(|f| serde_json::json!({
                    "rule_id": f.rule_id, "segment": f.segment,
                    "title": rule_titles.get(f.rule_id.as_str()).copied().unwrap_or(f.title.as_str())
                })).collect::<Vec<_>>(),
                "excerpts": excerpts,
            }),
        )?;
        out.write_all(b"\n")?;
    }
    out.flush()?;
    Ok(ExitCode::SUCCESS)
}

fn rules_lint(dir: &Path) -> Result<ExitCode> {
    let files = rule_files(dir)?;
    let mut bad = 0;
    let mut ids = std::collections::HashMap::new();
    for p in &files {
        let text = fs::read_to_string(p)?;
        match Rule::from_yaml(&p.display().to_string(), &text) {
            Err(e) => {
                bad += 1;
                println!("FAIL {e}");
            }
            Ok(r) => {
                let mut errs = r.lint();
                if let Some(prev) = ids.insert(r.id.clone(), p.clone()) {
                    errs.push(format!("duplicate id, also in {}", prev.display()));
                }
                if errs.is_empty() {
                    println!("ok   {} {}", r.id, p.display());
                } else {
                    bad += 1;
                    println!("FAIL {} {}: {}", r.id, p.display(), errs.join("; "));
                }
            }
        }
    }
    println!("{} rule file(s), {} error(s)", files.len(), bad);
    Ok(if bad == 0 { ExitCode::SUCCESS } else { ExitCode::FAILURE })
}

fn rules_test(dir: &Path, corpus: Option<&Path>) -> Result<ExitCode> {
    let loaded = load_rules(dir)?;
    let rules = RuleSet::new(loaded.iter().map(|(_, r)| r.clone()).collect())?;
    let scanner = Scanner::new(&rules);
    let mut failures = 0;
    for r in rules.rules() {
        for (sample, want) in r.tests.positive.iter().map(|s| (s, true)).chain(r.tests.negative.iter().map(|s| (s, false))) {
            let lower = sample.to_ascii_lowercase();
            let is_html = ["<html", "<body", "<p>", "<p ", "<div", "<span", "<img", "<!--"].iter().any(|t| lower.contains(t));
            let ct = if is_html { "text/html" } else { "text/plain" };
            let got = scanner.scan_text(sample, ct).findings.iter().any(|f| f.rule_id == r.id);
            if got != want {
                failures += 1;
                println!("FAIL {} {} example not {}: {:.80}", r.id, if want { "positive" } else { "negative" }, if want { "detected" } else { "ignored" }, sample);
            }
        }
    }
    println!("rule examples: {} failure(s)", failures);

    if let Some(root) = corpus {
        for (sub, expect_flag) in [("poisoned", true), ("benign", false)] {
            let mut src = Directory::new(&root.join(sub), Trust::Low, 2 * 1024 * 1024);
            let (mut n, mut wrong) = (0, 0);
            while let Some(env) = src.next_envelope() {
                let env = env?;
                n += 1;
                let flagged = scanner.scan(&env)?.verdict != Verdict::Allow;
                if flagged != expect_flag {
                    wrong += 1;
                    println!("FAIL corpus/{sub}: {} {}", env.id, if expect_flag { "missed" } else { "false positive" });
                }
            }
            println!("corpus/{sub}: {n} document(s), {wrong} error(s)");
            failures += wrong;
        }
    }
    Ok(if failures == 0 { ExitCode::SUCCESS } else { ExitCode::FAILURE })
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let res = match cli.cmd {
        Cmd::Scan { input, opts } => {
            if input == "-" {
                run_scan(&mut JsonLines::new(io::stdin().lock()), &opts)
            } else {
                match fs::File::open(&input) {
                    Ok(f) => run_scan(&mut JsonLines::new(BufReader::new(f)), &opts),
                    Err(e) => Err(anyhow::anyhow!("{input}: {e}")),
                }
            }
        }
        Cmd::ScanDir { path, trust, opts } => parse_trust(&trust)
            .and_then(|t| run_scan(&mut Directory::new(&path, t, opts.max_bytes as u64), &opts)),
        Cmd::Explain { input, rules } => run_explain(&input, &rules),
        Cmd::Rules { cmd: RulesCmd::Lint { dir } } => rules_lint(&dir),
        Cmd::Rules { cmd: RulesCmd::Test { dir, corpus } } => rules_test(&dir, corpus.as_deref()),
    };
    match res {
        Ok(c) => c,
        Err(e) => {
            eprintln!("poisonscan: error: {e:#}");
            ExitCode::FAILURE
        }
    }
}

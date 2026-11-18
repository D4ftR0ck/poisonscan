# poisonscan

Detects **collection-to-LLM poisoning**: indirect prompt injection and RAG corpus poisoning
hidden in content that pipelines collect automatically (mail, web pages, feeds, PDF…) before
an LLM reads it. Most existing guardrails watch the *user → LLM* prompt; poisonscan watches
the *collection → LLM* channel.

Status: early prototype (v0.1). Design notes: [docs/DESIGN.md](docs/DESIGN.md).

## Quick start

```bash
cargo build --release
# rule pack checks (CI)
./target/release/poisonscan rules lint
./target/release/poisonscan rules test --corpus corpus
# scan envelopes (JSON Lines, schema poisonscan.envelope/v1)
./target/release/poisonscan scan docs.jsonl --format ocsf
# scan a directory of raw files
./target/release/poisonscan scan-dir ./collected --trust low --format ecs
```

Input envelope (one per line):

```json
{"id":"msg-42","source":{"type":"email","uri":"mailto:x@example.net","trust":"low"},
 "content_type":"text/html","content":"…","content_encoding":"utf8"}
```

Outputs: `native`, `ocsf` (Detection Finding, class 2004), `ecs`. Alerts never contain raw
excerpts of the scanned content.

## Performance

Parsing and scanning run in parallel batches (`--threads`, default 2, `0` = all cores;
`--batch`, default 256 documents). Output order always follows input order. Memory is
bounded by `batch × max-bytes`.

Rule authors: `\b` is compiled as an ASCII word boundary. A Unicode `\b` makes the regex
DFA fall back to a slow engine on any non-ASCII text (about 16× slower on French text).
`rules lint` rejects a `\b` placed right next to a non-ASCII letter (e.g. `\bécris`),
where it could never match.

## Layout

| Crate | Role |
|---|---|
| `poisonscan-core` | no I/O: normalisation, rule funnel (Aho-Corasick + RegexSet), scoring, output formats |
| `poisonscan-sources` | read-only adapters (JSON Lines, directories) |
| `poisonscan-cli` | `scan`, `scan-dir`, `rules lint`, `rules test` |

Rules live in `rules/` (one YAML file per rule, with mandatory positive/negative examples).
Built-in structural detectors use reserved ids `PSN-Bxxx`.

## License

MIT OR Apache-2.0 (license files to be added).

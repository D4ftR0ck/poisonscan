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
# tag the rows of a SQLite table (incremental; the table itself is only read)
./target/release/poisonscan tag-sqlite --config examples/tag-sqlite.toml
```

`tag-sqlite` writes two tables next to the scanned one:

- `poisonscan_tags(key, score, verdict, rules, mitre, rules_fingerprint, content_xxh3, scanned_at)`:
  one row per flagged document. Applications join on it to show a marker; nothing is
  excluded and the document text is never modified.
- `poisonscan_seen(key, content_xxh3, rules_fingerprint)`: every scanned row, so the next
  run only scans new or changed rows, or everything again when the rule pack changes.

Tags of rows deleted from the table are removed at the end of each run (`--no-prune` to
keep them). Use `key = "content"` when the table is rebuilt with new row numbers: the tag
key is then the SHA-256 (hex) of the scanned content, which any client can recompute.
Other options: `--dry-run`, `--full`, `--limit`, `--threads`, `--reset`.

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

## What it catches, and what it does not

Normalisation produces several views of each document: visible text, hidden text (CSS
hiding including classes, off-screen, tiny or white text, nested elements, comments, alt
text), Unicode-tag smuggled text, and a de-obfuscated view (base64 / percent / HTML-entity
decoding up to depth 2, Cyrillic/Greek look-alikes folded to ASCII, leetspeak, spaced-out
letters). Rules run on every view; a match that only appears in a hidden or decoded view
weighs 1.5×. Documents over `--max-bytes` are scanned head and tail.

Known limits (see `corpus/known-bypass/`):
- **False facts without instructions** (PoisonedRAG-style) are out of reach of
  per-document rules: they need corpus-level analysis (near-duplicates, provenance,
  retrieval "magnets"), planned as a separate stage.
- **Free paraphrase** beyond the rule vocabulary needs the optional ML stage (planned).
- Ciphers the decoder does not undo (ROT13, custom) are caught only through the
  "decode and follow" wrapper rule.
- The HTML walker is not a full HTML5 parser and does not evaluate external CSS.

## Layout

| Crate | Role |
|---|---|
| `poisonscan-core` | no I/O: normalisation, rule funnel (Aho-Corasick + RegexSet), scoring, output formats |
| `poisonscan-sources` | read-only adapters (JSON Lines, directories) |
| `poisonscan-cli` | `scan`, `scan-dir`, `rules lint`, `rules test` |

Rules live in `rules/` (one YAML file per rule, with mandatory positive/negative examples).
Built-in structural detectors use reserved ids `PSN-Bxxx`.

## License

Licensed under either of [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at your option.
Security reports: see [SECURITY.md](SECURITY.md).

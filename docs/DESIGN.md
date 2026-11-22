# poisonscan: detecting "collection → LLM" poisoning

*[Version française](DESIGN.fr.md)*

Open-source, public project. This document is the design note: it describes the target architecture. The **Status** section below says what is implemented in v0.1 and what is still planned.

## Status (v0.1)
**Implemented:**
- `poisonscan-core` (no I/O, `#![forbid(unsafe_code)]`): Unicode normalisation (NFKC, invisible and tag characters, confusables), HTML visible/hidden split, de-obfuscation (base64, percent-encoding, HTML entities), a two-stage funnel (Aho-Corasick keywords, then a single `RegexSet` pass), scoring weighted by segment and source trust, verdicts `allow` / `flag` / `quarantine`.
- Rule pack: 19 YAML rules (`ai-directed/`, `exfil/`, `hidden-text/`) and 5 built-in signals, mapped to MITRE ATLAS techniques, each with positive and negative examples and a sample in `corpus/poisoned/by-rule/`.
- `poisonscan-sources`: JSON Lines envelopes and directories of raw files.
- `poisonscan-cli`: `scan`, `scan-dir`, `explain` (neutralised excerpts, for analysts), `rules lint`, `rules test --corpus`, and `tag-sqlite` (incremental tags stored next to a SQLite table; see the README).
- Outputs: `native`, `ocsf` (Detection Finding), `ecs`. Alerts never carry raw excerpts.
- Parallel batch scanning (`rayon`), bounded memory, xxh3 content hash and rule-pack fingerprint on every verdict.

**Planned:** MIME and PDF decoders, Maildir/mbox and PostgreSQL adapters, PyO3 binding, `integrations/` (Splunk, Elastic, Sentinel), CEF/syslog outputs, CI, signed rule packs, ML classifier stage, "magnet" passage detection, public benchmark.

## Problem
More and more systems automatically collect external content (emails, web pages, RSS feeds, PDFs, tickets, scraping…), store it, then pass it to an LLM: in a RAG, an assistant, an agent or an enrichment step. An attacker can slip instructions or fabricated claims into this content. This is called **indirect prompt injection** and **RAG corpus poisoning**.

## Positioning: what sets the project apart
Most existing tools monitor the **user → LLM** channel, that is, the prompt a person types at the moment they send it.
poisonscan monitors the **collection → LLM** channel: content ingested automatically, that no human has reviewed, and that an LLM will read later.
- **No user to monitor**: the origin is a source (sender, domain, URL, feed), and each source is given a trust level.
- **Delayed effect**: poisoned content can sit in a store for weeks. The project therefore offers a check at ingestion **and** a full scan of the existing store, with traceability (hash, source, date).
- **Volume**: corpora of tens of GB or more, hence the choice of Rust and of streaming analysis.
- **Signals specific to collection**:
  - hidden text (invisible HTML, zero-width characters, Unicode tags, white-on-white text, PDF metadata);
  - instructions addressed "to the AI" in an email or a page;
  - the same payload recurring from one source to another;
  - a low-trust source that suddenly becomes abundant;
  - "magnet" passages that are retrieved for far too many queries.
- **Out of scope**: application logs. They usually do not contain the collected text, only operational messages.

## Technical references
- **PoisonedRAG** (Zou et al., USENIX Security 2025): about 5 crafted texts per targeted question are enough to force the attacker's answer in about 90% of cases, even in a store of several million documents.
- **EchoLeak** (Microsoft 365 Copilot, 2025, CVE-2025-32711): an email received, with no click from the victim, is indexed, then its instructions leak data.
- **Slack AI** (2024, reported by PromptArmor): a message in a public channel makes the assistant leak the content of private channels.
- **MITRE ATLAS AML.T0070 (RAG Poisoning)**: the reference technique, with traceability recommendations (query, retrieved passages, scores, source, trust level).
- **Greshake et al. 2023**, "Not what you've signed up for": the foundation of indirect injection.

## Existing open-source work
- **Rust crates** (recent, little tested): `atlas-detect` (97 MITRE ATLAS rules in a `RegexSet`), `jailguard` (small embedded MLP classifier), `llm-security`, `prompt-inj-rs`, `llm-kernel`.
- **Python**: LLM Guard, Vigil (YARA rules), Rebuff (archived), prompt-armor. Garak is a red-team tool, not a detector.
- **RAG-specific**: Cisco Adversarial Hubness Detector (vector index analysis), Semantic Chameleon (research code).
- Nothing mature for the collection → LLM channel. Licences and maintenance status must be checked before reusing any of it.

## Architecture
One Rust engine, two uses:
1. **Ingestion check**: a library called by the collector before storage. It returns a score, explanations and a verdict (accept, flag, quarantine). Planned bindings: native Rust, Python (PyO3), and later a C interface or a "pipe" mode for other languages.
2. **`scan-store`**: a full pass over an existing store, done once and then incrementally, with a ranked report (passage, source, hash, ingestion date, rules triggered).

Cargo workspace:
- `poisonscan-core`: no I/O. Normalisation (Unicode NFKC, HTML and MIME decoding, hidden-text extraction), a chain of detectors (`Detector` trait), then scoring with explanations.
- `poisonscan-sources`: read-only adapters (`Source` trait). To start with: files and directories, JSONL, SQLite, Maildir/mbox. Later: PostgreSQL and a few common vector databases.
- `poisonscan-cli`: `scan-store`, `explain <id>`, `rules lint`, `rules test`.
- `poisonscan-py`: PyO3 binding.

Adding a storage type means adding a `Source`; adding a detection method means adding a `Detector`. Nothing else changes.

## Standard input: the "document envelope"
The principle: a single published, versioned input format that any pipeline can produce. `Source` adapters only convert a store to this format.
- **Format**: JSON Lines, one document per line, described by a JSON schema (`envelope/v1`):
  ```json
  {"schema":"poisonscan.envelope/v1","id":"…","source":{"type":"email|web|rss|pdf|ticket|api|other","uri":"…","trust":"low|medium|high"},
   "collected_at":"2026-11-18T10:00:00Z","content_type":"text/plain|text/html|message/rfc822|application/pdf",
   "content":"…","content_encoding":"utf8|base64","metadata":{}}
  ```
  The format is deliberately close to the OCSF `File` / `Email` objects and to the ECS `email.*` / `url.*` fields, so that an output event links to it easily.
- **Input channels**:
  - stdin or pipe (`poisonscan scan -`);
  - JSONL files and directories;
  - library call (Rust or PyO3) with the same structure;
  - native `Source` adapters (SQLite, Maildir, directories…) that produce the envelope.
- **Decoders by `content_type`**: HTML (visible and hidden text kept apart), MIME (parts and attachments), PDF (text and metadata). All decoders are capped in size and depth.
- **No input HTTP server in the core**: Vector, Fluent Bit or Logstash can write JSONL to a file or a pipe (`exec` or `file` output). An HTTP service mode may come later, in a separate crate, disabled by default.
- The source trust level (`trust`) is supplied by the caller and weights the score.

## Standard output and SIEM integration
The principle: standard formats rather than connectors written for each product. Transport is left to existing agents.
- **Output events** in JSON Lines, with a versioned schema, and two priority formats:
  - **OCSF**: Detection Finding class, for Splunk, AWS Security Lake and the other tools that adopt it;
  - **ECS**: for Elastic and OpenSearch.
  CEF and syslog RFC 5424 are planned as options for older SIEMs.
- Each alert carries `mitre.technique = AML.T0070` (plus the rule id, pack version, hash, source and score). **Never a raw excerpt**, because LLM assistants built into SIEMs could read it again and replay the attack.
- **Destinations**: file, stdout, syslog, journald. Optional, later: a generic HTTP webhook, in a separate crate.
- **`integrations/` directory** (configuration, no code in the engine):
  - Splunk: `props.conf` and `transforms.conf`, SPL searches, dashboard;
  - Elastic: index template, ingest pipeline, detection rules;
  - Microsoft Sentinel and Defender XDR: custom Log Analytics table and KQL correlation queries;
  - Vector and Fluent Bit examples.
- **MDE**: read-only, through correlation in Sentinel or Defender XDR. Pushing indicators (domains, URLs) to MDE stays an example script, disabled by default and subject to human approval.

## Security
Scanned content is hostile by definition.
- `#![forbid(unsafe_code)]` in the core, which has no network or file access.
- Linear-time regex engine: no ReDoS.
- Per-item size and decoding depth are capped, against decompression bombs and nested encodings.
- Adapters are strictly read-only.
- A hardened systemd unit example is provided: `PrivateNetwork`, `ProtectSystem=strict`, `NoNewPrivileges`, `SystemCallFilter`.
- **No raw excerpt in alerts**, so the payload is not fed back into another LLM: id, hash, rule and score only. `explain` shows a neutralised excerpt.
- Supply chain: `cargo-deny`, `cargo-audit`, committed `Cargo.lock`, few dependencies.

## Performance (low CPU load)
- Funnel: Aho-Corasick prefilter and O(n) byte scan, then a single-pass `RegexSet`, then an ML classifier (optional Cargo feature) only above a threshold.
- Incremental: one cursor per source and one xxh3 hash per item. An item is scanned again only if its content or the rule version changes.
- Streaming reads in fixed-size batches: constant memory whatever the size of the store.
- No mandatory daemon. Tunable `rayon` parallelism (number of threads), so it also runs on small machines (ARM, 1-vCPU VMs).
- Public benchmark: throughput (MB/s) and peak memory published for each release.

## Rule maintainability (external contributions)
- **Rules separate from code**: a `rules/` repository or directory, one rule per YAML file, grouped by family (`hidden-text/`, `ai-directed/`, `exfil/`…).
- **Format inspired by Sigma and YARA**, described by a JSON schema: stable `id` (`PSN-0042`), `title`, `version`, `status` (`experimental` / `stable` / `deprecated`), `author`, `date`, `references`, `severity`, `channel`, `match`, `exceptions`.
- **Examples in every rule**: `tests.positive` and `tests.negative`, checked on every contribution.
- **CI** (`rules lint`, `rules test`): schema, compilation, per-rule cost cap, examples, id uniqueness, and non-regression on a shared corpus (poisoned + benign) with a false-positive threshold.
- **Versioning**: the rule pack is versioned (semver) separately from the engine, and the engine declares the format version it accepts. Each verdict records the pack version used.
- **Lifecycle**: a rule is never deleted, it moves to `deprecated`; an id is never reused; a `CHANGELOG` is kept for the pack.
- **Contribution**: `CONTRIBUTING.md`, rule template, mandatory review, test corpus extended with anonymised samples.
- **False positives**: `explain` shows which rule fired; the fix is an exception or a negative example, without touching the engine.
- **Trust**: published packs are signed (minisign) and the engine checks the signature.
- **Bootstrap**: a one-off converter from existing rules (Vigil YARA, atlas-detect, LLM Guard), respecting their licences.

## Project governance
- MIT OR Apache-2.0 licence for the engine. The rule pack licence is still to be chosen (for example the same, or the Detection Rule License, as Sigma does).
- `SECURITY.md`: procedure for private reporting of bypasses.
- Public test corpus, with no personal data at all.

## Work order
1. ✅ Specify the rule format (schema) and build a first poisoned and benign corpus, inspired by EchoLeak, PoisonedRAG and Slack AI.
2. ✅ `poisonscan-core` + `rules lint/test`. CI still to be set up.
3. `poisonscan-sources` (files, JSONL, SQLite, Maildir) + store scanning + `explain`. Done: JSONL, directories, `explain`, and for SQLite `tag-sqlite` (tags in `poisonscan_tags`, incremental scanning, orphan clean-up, content-hash key when needed). Remaining: Maildir/mbox.
4. PyO3 binding and an example of integration into a RAG ingestion pipeline.
5. Public benchmark, then a first published release.

## Open questions
- ~~Alert only, or also quarantine by default?~~ Decided: verdicts are informational. poisonscan never removes or edits a document; whether to quarantine is up to the calling pipeline.
- Detecting "magnet" passages: reuse the embeddings of an existing index, or compute them?

## Verification
- The poisoned corpus is fully detected; the false-positive rate on the benign corpus stays under the set threshold.
- Throughput and peak memory measured on a modest machine and on a typical machine.

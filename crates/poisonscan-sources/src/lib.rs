//! Read-only source adapters. Each adapter yields `Envelope`s in a stream,
//! with bounded memory, so any store can be scanned the same way.
#![forbid(unsafe_code)]

use std::fs;
use std::io::{BufRead, Read};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use poisonscan_core::envelope::{ContentEncoding, Envelope, Source, Trust};

/// A source of envelopes.
pub trait EnvelopeSource {
    fn next_envelope(&mut self) -> Option<Result<Envelope>>;
}

/// JSON Lines reader (`poisonscan.envelope/v1`), from stdin or a file.
pub struct JsonLines<R: BufRead> {
    reader: R,
    line_no: usize,
    buf: String,
}

impl<R: BufRead> JsonLines<R> {
    pub fn new(reader: R) -> Self {
        JsonLines { reader, line_no: 0, buf: String::new() }
    }
}

impl<R: BufRead> JsonLines<R> {
    /// Next non-empty raw line with its line number, without parsing it.
    /// Lets callers parse in parallel.
    pub fn next_raw(&mut self) -> Option<Result<(usize, String)>> {
        loop {
            self.buf.clear();
            self.line_no += 1;
            match self.reader.read_line(&mut self.buf) {
                Ok(0) => return None,
                Ok(_) if self.buf.trim().is_empty() => continue,
                Ok(_) => return Some(Ok((self.line_no, std::mem::take(&mut self.buf)))),
                Err(e) => return Some(Err(e.into())),
            }
        }
    }
}

/// Parse one JSON Lines record into an envelope.
pub fn parse_line(line_no: usize, line: &str) -> Result<Envelope> {
    serde_json::from_str(line.trim_end()).with_context(|| format!("line {line_no}: invalid envelope"))
}

impl<R: BufRead> EnvelopeSource for JsonLines<R> {
    fn next_envelope(&mut self) -> Option<Result<Envelope>> {
        self.next_raw()
            .map(|r| r.and_then(|(n, line)| parse_line(n, &line)))
    }
}

/// Recursive directory reader: each regular file becomes one envelope.
/// Symlinks are not followed; files above `max_bytes` are read partially
/// (the scanner then flags truncation).
pub struct Directory {
    stack: Vec<PathBuf>,
    files: Vec<PathBuf>,
    trust: Trust,
    max_bytes: u64,
}

impl Directory {
    pub fn new(root: &Path, trust: Trust, max_bytes: u64) -> Self {
        Directory { stack: vec![root.to_path_buf()], files: Vec::new(), trust, max_bytes }
    }

    fn content_type(path: &Path) -> (&'static str, &'static str) {
        match path.extension().and_then(|e| e.to_str()).map(|e| e.to_ascii_lowercase()).as_deref() {
            Some("html" | "htm") => ("text/html", "web"),
            Some("eml") => ("message/rfc822", "email"),
            Some("md" | "txt" | "csv" | "json" | "xml") => ("text/plain", "file"),
            _ => ("text/plain", "file"),
        }
    }

    fn read(&self, path: &Path) -> Result<Envelope> {
        let mut bytes = Vec::new();
        fs::File::open(path)?.take(self.max_bytes + 1).read_to_end(&mut bytes)?;
        let (ct, kind) = Self::content_type(path);
        Ok(Envelope {
            schema: Some(poisonscan_core::ENVELOPE_SCHEMA.into()),
            id: path.display().to_string(),
            source: Source { kind: kind.into(), uri: format!("file://{}", path.display()), trust: self.trust },
            collected_at: None,
            content_type: ct.into(),
            content: String::from_utf8_lossy(&bytes).into_owned(),
            content_encoding: ContentEncoding::Utf8,
            metadata: serde_json::Value::Null,
        })
    }
}

impl EnvelopeSource for Directory {
    fn next_envelope(&mut self) -> Option<Result<Envelope>> {
        loop {
            if let Some(f) = self.files.pop() {
                return Some(self.read(&f).with_context(|| format!("{}", f.display())));
            }
            let dir = self.stack.pop()?;
            let meta = match fs::symlink_metadata(&dir) {
                Ok(m) => m,
                Err(e) => return Some(Err(e.into())),
            };
            if meta.is_file() {
                self.files.push(dir);
                continue;
            }
            if !meta.is_dir() {
                continue;
            }
            let entries = match fs::read_dir(&dir) {
                Ok(e) => e,
                Err(e) => return Some(Err(e.into())),
            };
            let mut items: Vec<_> = entries.filter_map(|e| e.ok()).collect();
            items.sort_by_key(|e| std::cmp::Reverse(e.path()));
            for e in items {
                match e.file_type() {
                    Ok(t) if t.is_dir() => self.stack.push(e.path()),
                    Ok(t) if t.is_file() => self.files.push(e.path()),
                    _ => {}
                }
            }
        }
    }
}

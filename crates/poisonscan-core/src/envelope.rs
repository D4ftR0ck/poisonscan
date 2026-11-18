//! Input envelope: one collected document, as produced by any pipeline.

use base64::Engine as _;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Trust {
    Low,
    #[default]
    Medium,
    High,
}

impl Trust {
    /// Weight applied to the raw score: content from low-trust sources counts more.
    pub fn factor(self) -> f32 {
        match self {
            Trust::Low => 1.0,
            Trust::Medium => 0.85,
            Trust::High => 0.6,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Source {
    /// email | web | rss | pdf | ticket | api | file | other
    #[serde(rename = "type", default = "default_source_type")]
    pub kind: String,
    #[serde(default)]
    pub uri: String,
    #[serde(default)]
    pub trust: Trust,
}

fn default_source_type() -> String {
    "other".into()
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ContentEncoding {
    #[default]
    Utf8,
    Base64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Envelope {
    #[serde(default)]
    pub schema: Option<String>,
    pub id: String,
    #[serde(default)]
    pub source: Source,
    #[serde(default)]
    pub collected_at: Option<String>,
    #[serde(default = "default_content_type")]
    pub content_type: String,
    pub content: String,
    #[serde(default)]
    pub content_encoding: ContentEncoding,
    #[serde(default)]
    pub metadata: serde_json::Value,
}

fn default_content_type() -> String {
    "text/plain".into()
}

#[derive(Debug, thiserror::Error)]
pub enum EnvelopeError {
    #[error("invalid base64 content: {0}")]
    Base64(#[from] base64::DecodeError),
}

impl Envelope {
    /// Convenience constructor for plain text.
    pub fn text(id: impl Into<String>, content: impl Into<String>) -> Self {
        Envelope {
            schema: Some(crate::ENVELOPE_SCHEMA.into()),
            id: id.into(),
            source: Source::default(),
            collected_at: None,
            content_type: default_content_type(),
            content: content.into(),
            content_encoding: ContentEncoding::Utf8,
            metadata: serde_json::Value::Null,
        }
    }

    /// Decoded content (lossy UTF-8 for base64 payloads).
    pub fn decoded(&self) -> Result<String, EnvelopeError> {
        match self.content_encoding {
            ContentEncoding::Utf8 => Ok(self.content.clone()),
            ContentEncoding::Base64 => {
                let bytes = base64::engine::general_purpose::STANDARD.decode(self.content.trim())?;
                Ok(String::from_utf8_lossy(&bytes).into_owned())
            }
        }
    }

    /// Short channel name used to filter rules (`email`, `web`, ...).
    pub fn channel(&self) -> &str {
        let ct = self.content_type.as_str();
        if ct.starts_with("message/") {
            "email"
        } else if ct.contains("html") {
            "web"
        } else if ct.contains("pdf") {
            "pdf"
        } else {
            self.source.kind.as_str()
        }
    }
}

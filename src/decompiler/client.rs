//! HTTP client for the external GCLSD decompiler model.
//!
//! The model is expected to live in a separate process (typically a Python
//! FastAPI/uvicorn service). windy POSTs a `GclsdInput` JSON body and expects
//! a `GclsdOutput` JSON response. Results are cached per binary/VA/op_seq so
//! the UI and multiple MCP calls don't repeatedly hit the model for the same
//! unchanged function.

#![allow(dead_code)] // opt-in archive client retained for historical reproduction

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result};

use crate::ir::gclsd::{GclsdInput, GclsdOutput};

pub const DEFAULT_ENDPOINT: &str = "http://127.0.0.1:8000/decompile";
const DEFAULT_TIMEOUT_SECS: u64 = 120;

/// Cache key for decompiled output. A result is only valid while the project
/// snapshot (identified by SHA256) and its operation sequence number have not
/// changed; any rename/comment/undo invalidates prior results for that VA.
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct DecompilerCacheKey {
    pub image_sha256: String,
    pub va: u64,
    pub op_seq: u64,
}

/// Async HTTP client to the GCLSD model service.
#[derive(Clone)]
pub struct DecompilerClient {
    http: reqwest::Client,
    endpoint: String,
    cache: Arc<Mutex<HashMap<DecompilerCacheKey, GclsdOutput>>>,
}

impl DecompilerClient {
    /// Create a client pointing at the given HTTP endpoint.
    pub fn new(endpoint: impl Into<String>) -> Result<Self> {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(DEFAULT_TIMEOUT_SECS))
            .build()
            .context("build reqwest client")?;
        Ok(Self {
            http,
            endpoint: endpoint.into(),
            cache: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    /// Create a client from the environment (`WINDY_DECOMPILER_URL`) or the
    /// default localhost endpoint.
    pub fn from_env() -> Result<Self> {
        let endpoint =
            std::env::var("WINDY_DECOMPILER_URL").unwrap_or_else(|_| DEFAULT_ENDPOINT.to_string());
        Self::new(endpoint)
    }

    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    /// Request decompilation, returning a cached result if available.
    pub async fn decompile(
        &self,
        key: DecompilerCacheKey,
        input: &GclsdInput,
    ) -> Result<GclsdOutput> {
        if let Some(cached) = self.cache.lock().unwrap().get(&key) {
            return Ok(cached.clone());
        }

        let output: GclsdOutput = self
            .http
            .post(&self.endpoint)
            .json(input)
            .send()
            .await
            .context("send decompile request")?
            .error_for_status()
            .context("decompile request failed")?
            .json()
            .await
            .context("parse decompile response")?;

        self.cache.lock().unwrap().insert(key, output.clone());
        Ok(output)
    }

    #[cfg(test)]
    fn insert_cache(&self, key: DecompilerCacheKey, output: GclsdOutput) {
        self.cache.lock().unwrap().insert(key, output);
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use super::*;
    use axum::{Router, extract::Json, routing::post};
    use serde_json::json;

    async fn echo_server() -> SocketAddr {
        let app = Router::new().route(
            "/decompile",
            post(|Json(_input): Json<serde_json::Value>| async move {
                Json(json!({ "pseudocode": "// stub decompiler output" }))
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        addr
    }

    #[tokio::test]
    async fn http_round_trip() {
        let addr = echo_server().await;
        let client = DecompilerClient::new(format!("http://{}/decompile", addr)).unwrap();
        let input = GclsdInput {
            name: "test".to_string(),
            entry_va: 0x1000,
            image_base: 0x1000_0000,
            bitness: 64,
            calling_conv: None,
            params: vec![],
            return_type: None,
            instructions: vec![],
            blocks: vec![],
            xrefs_in: vec![],
            xrefs_out: vec![],
            refine: None,
        };
        let output = client
            .decompile(
                DecompilerCacheKey {
                    image_sha256: "abc".to_string(),
                    va: 0x1000,
                    op_seq: 1,
                },
                &input,
            )
            .await
            .unwrap();
        assert_eq!(output.pseudocode, "// stub decompiler output");
    }

    #[tokio::test]
    async fn cache_hits_skip_network() {
        let addr = echo_server().await;
        let client = DecompilerClient::new(format!("http://{}/decompile", addr)).unwrap();
        let key = DecompilerCacheKey {
            image_sha256: "abc".to_string(),
            va: 0x1000,
            op_seq: 1,
        };
        client.insert_cache(
            key.clone(),
            GclsdOutput {
                pseudocode: "cached".to_string(),
            },
        );
        let input = GclsdInput {
            name: "test".to_string(),
            entry_va: 0x1000,
            image_base: 0x1000_0000,
            bitness: 64,
            calling_conv: None,
            params: vec![],
            return_type: None,
            instructions: vec![],
            blocks: vec![],
            xrefs_in: vec![],
            xrefs_out: vec![],
            refine: None,
        };
        let output = client.decompile(key, &input).await.unwrap();
        assert_eq!(output.pseudocode, "cached");
    }
}

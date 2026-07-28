// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! HTTP transport for exact repository-v6 transfer between two replicas.
//!
//! The peer is any host that serves the daemon's repository-v6 transfer seam:
//!
//! - `GET  {base_url}/repos/{repository_id}/transfer/advertise`
//! - `POST {base_url}/repos/{repository_id}/transfer/status`
//! - `POST {base_url}/repos/{repository_id}/transfer/export`
//! - `POST {base_url}/repos/{repository_id}/transfer/receive`
//!
//! This layer is transport only. It carries exact envelopes, maps peer refusals
//! back to the transfer error they were raised as, and decides nothing about
//! what either replica holds. A peer that returns a body this crate cannot
//! parse is a protocol failure, never a silently empty result.

use std::time::Duration;

use kin_model::{RefName, RepositoryId};
use ureq::Agent;

use crate::http_transport::urlencoded;
use crate::repository_transfer::{
    RepositoryRefAdvertisement, RepositoryTransferError, RepositoryTransferExpectation,
    RepositoryTransferPack, RepositoryTransferReceipt, RepositoryTransferStatus, Result,
};
use crate::repository_transfer_negotiation::RepositoryTransferTransport;

/// Where a peer replica serves its transfer seam.
#[derive(Debug, Clone)]
pub struct RepositoryTransferEndpoint {
    pub base_url: String,
    pub auth_token: Option<String>,
    pub timeout_secs: u64,
}

impl RepositoryTransferEndpoint {
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into().trim_end_matches('/').to_string(),
            auth_token: None,
            timeout_secs: 120,
        }
    }

    pub fn with_auth(mut self, token: impl Into<String>) -> Self {
        self.auth_token = Some(token.into());
        self
    }

    pub fn with_timeout(mut self, secs: u64) -> Self {
        self.timeout_secs = secs;
        self
    }
}

/// A transfer peer reached over HTTP.
pub struct HttpRepositoryTransferTransport {
    endpoint: RepositoryTransferEndpoint,
    agent: Agent,
}

impl std::fmt::Debug for HttpRepositoryTransferTransport {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HttpRepositoryTransferTransport")
            .field("base_url", &self.endpoint.base_url)
            .field("authenticated", &self.endpoint.auth_token.is_some())
            .finish()
    }
}

impl HttpRepositoryTransferTransport {
    pub fn new(endpoint: RepositoryTransferEndpoint) -> Self {
        let agent: Agent = Agent::config_builder()
            .timeout_global(Some(Duration::from_secs(endpoint.timeout_secs)))
            .build()
            .into();
        Self { endpoint, agent }
    }

    pub fn base_url(&self) -> &str {
        &self.endpoint.base_url
    }

    fn url(&self, repository_id: &RepositoryId, leaf: &str) -> String {
        format!(
            "{}/repos/{}/transfer/{leaf}",
            self.endpoint.base_url,
            urlencoded(repository_id.as_str())
        )
    }

    fn get_json<R: serde::de::DeserializeOwned>(&self, url: &str, what: &str) -> Result<R> {
        let mut request = self.agent.get(url);
        if let Some(token) = &self.endpoint.auth_token {
            request = request.header("Authorization", &format!("Bearer {token}"));
        }
        let response = request.call().map_err(|error| peer_error(error, what))?;
        read_json(response, what)
    }

    fn post_json<T: serde::Serialize, R: serde::de::DeserializeOwned>(
        &self,
        url: &str,
        body: &T,
        what: &str,
    ) -> Result<R> {
        let mut request = self.agent.post(url);
        if let Some(token) = &self.endpoint.auth_token {
            request = request.header("Authorization", &format!("Bearer {token}"));
        }
        let response = request
            .send_json(body)
            .map_err(|error| peer_error(error, what))?;
        read_json(response, what)
    }
}

fn read_json<R: serde::de::DeserializeOwned>(
    response: ureq::http::Response<ureq::Body>,
    what: &str,
) -> Result<R> {
    let body = response.into_body().read_to_string().map_err(|error| {
        RepositoryTransferError::Storage(format!("failed to read remote {what} response: {error}"))
    })?;
    serde_json::from_str(&body).map_err(|error| {
        RepositoryTransferError::Invalid(format!(
            "remote {what} response is not a valid repository-v6 envelope: {error}"
        ))
    })
}

/// Map a peer failure onto the transfer error it actually represents.
///
/// The receiving daemon already encodes its refusal class in the status code:
/// 422 for an invalid envelope, 409 for a lease or fast-forward conflict, 424
/// for storage. Preserving that mapping is what lets a caller distinguish "this
/// pack is malformed" from "the remote moved under us" without parsing prose.
fn peer_error(error: ureq::Error, what: &str) -> RepositoryTransferError {
    match error {
        ureq::Error::StatusCode(code) => match code {
            409 => RepositoryTransferError::Conflict(format!(
                "remote refused {what} with a repository-v6 conflict (HTTP 409)"
            )),
            422 => RepositoryTransferError::Invalid(format!(
                "remote rejected {what} as an invalid repository-v6 envelope (HTTP 422)"
            )),
            424 => RepositoryTransferError::Storage(format!(
                "remote {what} failed on storage (HTTP 424)"
            )),
            404 => RepositoryTransferError::Invalid(format!(
                "remote does not serve {what} for this repository (HTTP 404)"
            )),
            other => RepositoryTransferError::Storage(format!(
                "remote {what} failed with HTTP {other}"
            )),
        },
        other => {
            RepositoryTransferError::Storage(format!("remote {what} transport failed: {other}"))
        }
    }
}

impl RepositoryTransferTransport for HttpRepositoryTransferTransport {
    fn advertise_refs(&self, repository_id: &RepositoryId) -> Result<RepositoryRefAdvertisement> {
        self.get_json(
            &self.url(repository_id, "advertise"),
            "ref advertisement",
        )
    }

    fn transfer_status(
        &self,
        repository_id: &RepositoryId,
        destination_ref: &RefName,
    ) -> Result<RepositoryTransferStatus> {
        self.post_json(
            &self.url(repository_id, "status"),
            &serde_json::json!({ "destination_ref": destination_ref }),
            "transfer status",
        )
    }

    fn export_pack(
        &self,
        repository_id: &RepositoryId,
        source_ref: &RefName,
        expectation: &RepositoryTransferExpectation,
    ) -> Result<RepositoryTransferPack> {
        self.post_json(
            &self.url(repository_id, "export"),
            &serde_json::json!({
                "source_ref": source_ref,
                "expectation": expectation,
            }),
            "transfer export",
        )
    }

    fn receive_pack(
        &self,
        repository_id: &RepositoryId,
        destination_ref: &RefName,
        pack: &RepositoryTransferPack,
    ) -> Result<RepositoryTransferReceipt> {
        self.post_json(
            &self.url(repository_id, "receive"),
            &serde_json::json!({
                "destination_ref": destination_ref,
                "pack": pack,
            }),
            "transfer receive",
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn transport(base_url: &str) -> HttpRepositoryTransferTransport {
        HttpRepositoryTransferTransport::new(RepositoryTransferEndpoint::new(base_url))
    }

    #[test]
    fn endpoint_urls_percent_encode_the_repository_identity() {
        // A repository id accepts any non-control text, so an id carrying a
        // slash must not silently address a different route.
        let transport = transport("http://127.0.0.1:4010/");
        let repository_id = RepositoryId::new("org/repo name").unwrap();
        assert_eq!(
            transport.url(&repository_id, "receive"),
            "http://127.0.0.1:4010/repos/org%2Frepo%20name/transfer/receive"
        );
    }

    #[test]
    fn trailing_base_url_slashes_do_not_double_up() {
        let transport = transport("http://127.0.0.1:4010///");
        let repository_id = RepositoryId::new("kin").unwrap();
        assert_eq!(
            transport.url(&repository_id, "status"),
            "http://127.0.0.1:4010/repos/kin/transfer/status"
        );
    }

    #[test]
    fn peer_status_codes_keep_their_refusal_class() {
        assert!(matches!(
            peer_error(ureq::Error::StatusCode(409), "transfer receive"),
            RepositoryTransferError::Conflict(_)
        ));
        assert!(matches!(
            peer_error(ureq::Error::StatusCode(422), "transfer receive"),
            RepositoryTransferError::Invalid(_)
        ));
        assert!(matches!(
            peer_error(ureq::Error::StatusCode(424), "transfer receive"),
            RepositoryTransferError::Storage(_)
        ));
        assert!(matches!(
            peer_error(ureq::Error::StatusCode(500), "transfer receive"),
            RepositoryTransferError::Storage(_)
        ));
    }

    #[test]
    fn a_connectivity_failure_is_never_reported_as_a_clean_refusal() {
        // A peer that cannot be reached has not refused anything. Reporting
        // this as Invalid or Conflict would let a caller conclude the remote
        // evaluated the transfer and said no.
        let error = peer_error(ureq::Error::HostNotFound, "ref advertisement");
        assert!(matches!(error, RepositoryTransferError::Storage(_)));
    }
}

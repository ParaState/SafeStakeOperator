use crate::node::config::{API_ADDRESS, STATUS_REPORT_URL};
use crate::node::utils::request_to_web_server;
use crate::node::utils::SignDigest;
use crate::validation::http_metrics::metrics;
use hscrypto::SecretKey;
use serde::Serialize;
use std::net::SocketAddr;
use std::time::Duration;
#[derive(Debug, Serialize)]
pub struct StatusReportRequest {
    #[serde(rename = "operatorId")]
    pub operator_id: u32,
    pub address: String,
    #[serde(rename = "validatorEnabled")]
    pub validator_enabled: usize,
    #[serde(rename = "validatorTotal")]
    pub validator_total: usize,
    #[serde(rename = "signedBlocks")]
    pub signed_blocks: usize,
    #[serde(rename = "signedAttestation")]
    pub signed_attestation: usize,
    pub version: usize,
    #[serde(rename = "connectedNodes")]
    pub connected_nodes: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sign_hex: Option<String>,
}

impl SignDigest for StatusReportRequest {}

pub struct StatusReport {}

impl StatusReport {
    pub fn spawn(address: SocketAddr, operator_id: u32, secret: SecretKey) {
        tokio::spawn(async move {
            let mut report_interval = tokio::time::interval(Duration::from_secs(60 * 5));
            loop {
                report_interval.tick().await;
                let mut report_body = StatusReportRequest {
                    operator_id,
                    address: address.to_string(),
                    validator_enabled: metrics::int_gauge(&metrics::ENABLED_VALIDATORS_COUNT)
                        as usize,
                    validator_total: metrics::int_gauge(&metrics::TOTAL_VALIDATORS_COUNT) as usize,
                    signed_blocks: metrics::int_counter_vec(
                        &metrics::SIGNED_BLOCKS_TOTAL,
                        &[metrics::SUCCESS],
                    ) as usize,
                    signed_attestation: metrics::int_counter_vec(
                        &metrics::SIGNED_ATTESTATIONS_TOTAL,
                        &[metrics::SUCCESS],
                    ) as usize,
                    version: dvf_version::VERSION as usize,
                    connected_nodes: metrics::int_counter(&metrics::DVT_VC_CONNECTED_NODES)
                        as usize,
                    sign_hex: None,
                };
                report_body.sign_hex = Some(report_body.sign_digest(&secret).unwrap());
                log::info!("[Dvf Status Report] Body: {:?}", &report_body);
                let url_str = API_ADDRESS.get().unwrap().to_owned() + STATUS_REPORT_URL;
                tokio::spawn(async move {
                    _ = request_to_web_server(report_body, &url_str).await;
                });
            }
        });
    }
}
